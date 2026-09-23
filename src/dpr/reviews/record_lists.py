"""Handlers that send whole lists of stored records.

A list is a queryset that starts at `Model.objects` (or at a related manager of a record, such
as `order.items.all()`) and is narrowed by no value of the call: only `all`, `order_by`,
`values`, slices and similar steps, or `filter`/`exclude` with literal and module-level
arguments. It counts when it reaches the response: returned, passed to a render, response or
serializer call, or put in a name or context that is. Class list views (`ListView`,
`ListAPIView`, list viewsets) with a `queryset` or `model` and no `get_queryset` count too.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from dpr.model import Route
from dpr.parsing import pyast
from dpr.reviews.lookups import model_for, statements, user_model
from dpr.reviews.lookups_route import handler_functions
from dpr.reviews.personal import personal_fields
from dpr.rules import Context

STEPS = frozenset(
    {"all", "order_by", "values", "values_list", "select_related", "prefetch_related", "only",
     "defer", "distinct", "reverse", "using", "annotate", "iterator", "filter", "exclude"}
)  # fmt: skip
NARROW = frozenset({"filter", "exclude"})
SINGLE = frozenset(
    {"count", "exists", "aggregate", "first", "last", "get", "earliest", "latest", "delete",
     "update", "none"}
)  # fmt: skip
RESPONSE = re.compile(
    r"(?:^|\.)(?:render|smart_respond|render_to_response|render_to_string|TemplateResponse"
    r"|JsonResponse|Response|HttpResponse|jsonify)$|Serializer$"
)
LIST_VIEW = re.compile(r"ListView|ListAPIView|ListCreateAPIView|ModelViewSet|ListModelMixin")
FOREIGN = re.compile(r"(?:^|\.)(?:ForeignKey|OneToOneField|ManyToManyField)$|OneToOne\w*Field$")


@dataclass(frozen=True)
class RecordList:
    line: int
    model: str
    related: bool = False  # the records of one parent record, not a whole table


def related_names(ctx: Context) -> dict[str, str]:
    """`related_name` of each Django relation field, to the model that declares it, when the
    name is used by one model only."""
    if "related_names" not in ctx.facts:
        seen: dict[str, set[str]] = {}
        for model in ctx.detection.models:
            tree = (
                pyast.parse_file(ctx.index, model.location.file)
                if model.source == "django"
                else None
            )
            cls = (
                next((c for c in pyast.class_defs(tree) if c.lineno == model.location.line), None)
                if tree
                else None
            )
            for call in (n for n in ast.walk(cls) if isinstance(n, ast.Call)) if cls else []:
                name = pyast.constant(pyast.kwarg(call, "related_name"), None)
                if isinstance(name, str) and FOREIGN.search(pyast.dotted(call.func) or ""):
                    seen.setdefault(name, set()).add(model.name)
        ctx.facts["related_names"] = {k: next(iter(v)) for k, v in seen.items() if len(v) == 1}
    return ctx.facts["related_names"]


def _local_names(fn: ast.AST) -> set[str]:
    args = fn.args
    names = {a.arg for a in [*args.posonlyargs, *args.args, *args.kwonlyargs]}
    names |= {a.arg for a in (args.vararg, args.kwarg) if a is not None}
    for node in ast.walk(fn):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            names.add(node.id)
    return names


def _fixed(call: ast.Call, local: set[str]) -> bool:
    """A filter whose arguments hold no value of the call: no parameter or local name."""
    parts = [*call.args, *(k.value for k in call.keywords)]
    return not any(pyast.names_in(p) & local for p in parts)


def list_model(node: ast.AST, local: set[str], related: dict[str, str]) -> RecordList | None:
    """The record list an expression builds, or None when it is not one."""
    line = getattr(node, "lineno", 0)
    steps = 0
    while True:
        if isinstance(node, ast.Subscript):
            node = node.value
            continue
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            break
        if node.func.attr not in STEPS or (node.func.attr in NARROW and not _fixed(node, local)):
            return None
        steps += 1
        node = node.func.value
    if steps == 0 or not isinstance(node, ast.Attribute):
        return None
    if node.attr == "objects":
        name = (pyast.dotted(node.value) or "").split(".")[-1]
        return RecordList(line, name) if name[:1].isupper() else None
    if isinstance(node.value, ast.Name) and node.value.id in local and node.attr in related:
        return RecordList(line, related[node.attr], related=True)
    return None


def _find(
    node: ast.AST, holders: dict[str, RecordList], local: set[str], related: dict[str, str]
) -> RecordList | None:
    """A record list the expression passes on: written in it, or held by a name it uses. A
    list reduced to a count or one record (`count()`, `first()`, `exists()`) is not."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in SINGLE:
            return None
        found = list_model(node, local, related)
        if found is not None:
            return found
    if isinstance(node, ast.Name) and node.id in holders:
        return holders[node.id]
    for child in ast.iter_child_nodes(node):
        found = _find(child, holders, local, related)
        if found is not None:
            return found
    return None


def function_lists(fn: ast.AST, related: dict[str, str]) -> list[RecordList]:
    """Record lists a function sends in its response."""
    local = _local_names(fn)
    holders: dict[str, RecordList] = {}
    found: list[RecordList] = []
    for stmt in statements(fn):
        value = stmt.value
        if value is None:
            continue
        item = _find(value, holders, local, related)
        if item is None:
            continue
        if isinstance(stmt, ast.Return):
            found.append(item)
            continue
        for call in (n for n in ast.walk(value) if isinstance(n, ast.Call)):
            if RESPONSE.search(pyast.dotted(call.func) or ""):
                parts = [*call.args, *(k.value for k in call.keywords)]
                sent = next((i for p in parts if (i := _find(p, holders, local, related))), None)
                if sent is not None:
                    found.append(sent)
                    break
        targets = []
        if isinstance(stmt, ast.Assign | ast.AnnAssign):
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
        elif isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute):
            targets = [value.func.value]  # context.update(items=records)
        for target in targets:
            root = pyast.name_root(target)
            if root:
                holders[root] = item
    return found


def class_lists(cls: ast.ClassDef, related: dict[str, str]) -> list[RecordList]:
    """A list view's own `queryset` or `model` when it never narrows it in `get_queryset`."""
    if not any(LIST_VIEW.search(b) for b in pyast.base_names(cls)):
        return []
    methods = {i.name for i in cls.body if isinstance(i, ast.FunctionDef | ast.AsyncFunctionDef)}
    if methods & {"get_queryset", "list", "get", "filter_queryset"}:
        return []
    values = pyast.assignments(cls.body)
    queryset, model = values.get("queryset"), values.get("model")
    found = list_model(queryset, set(), related) if queryset is not None else None
    if found is not None:
        return [found]
    model_name = (pyast.dotted(model) or "").split(".")[-1] if model is not None else ""
    return [RecordList(model.lineno, model_name)] if model_name[:1].isupper() else []


def route_lists(ctx: Context, route: Route) -> list[RecordList]:
    """Record lists a route's handler sends, class attributes first."""
    related = related_names(ctx)
    handler = route.handler
    found = class_lists(handler, related) if isinstance(handler, ast.ClassDef) else []
    for fn in handler_functions(handler) if isinstance(handler, ast.AST) else []:
        found += function_lists(fn, related)
    return found


def personal_model(ctx: Context, name: str) -> bool:
    """A user model, or a model the classifier finds personal fields on."""
    return user_model(name) or any(p.model.name == name for p in personal_fields(ctx))


def has_file_field(ctx: Context, name: str) -> bool:
    model = model_for(ctx, name)
    return model is not None and any(f.type.endswith("FileField") for f in model.fields)
