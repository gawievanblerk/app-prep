"""Values a Python handler reads from the request, and the names assigned from them.

A value counts when it comes from a path parameter, `request.GET`, `request.POST`,
`request.data`, `request.query_params`, a JSON body (`json.loads(request.body)`), a DRF
serializer's `validated_data`, or a Django Ninja body schema parameter. A stored
record loaded with one of them is not a request value, and neither is `request.user`.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from dpr.parsing import pyast

DATA_ATTRS = frozenset(
    {"GET", "POST", "FGET", "FPOST", "data", "query_params", "args", "form", "json", "values"}
)
ID_NAME = re.compile(
    r"(?i)(?:^|_)(?:id|pk|uuid|guid|number|num|no|ref|reference|slug|hash|hashid)s?$"
    r"|^(?:[a-z]id|ids?|pks?)$"
)
PERSONAL_KEY = re.compile(
    r"(?i)id_?number|identity_number|policy_?number|policy_application_number|e_?mail"
    r"|phone|cell|mobile|msisdn|passport|account_number"
)
RECORD = re.compile(
    r"\.objects\.|get_(?:object|list)_or_404\(|\.query\.|\b(?:session|db)\.get\(|\.user\b"
)
SCHEMA_TYPES = frozenset({"str", "int", "float", "bool", "dict", "list", "HttpRequest", "Request"})


def identifier(label: str) -> bool:
    """A name that picks one record: an id, key, number, reference or a personal identifier."""
    return bool(ID_NAME.search(label) or PERSONAL_KEY.search(label))


@dataclass
class Taint:
    """Request names (`request`, `req`, `self.request`), names holding one request value
    (name to label: the request key it came from, or its own name), and containers holding
    the whole request data (a parsed JSON body, `validated_data`, a body schema)."""

    requests: set[str]
    keys: dict[str, str] = field(default_factory=dict)
    containers: set[str] = field(default_factory=set)


def request_names(fn: ast.AST, django: bool) -> set[str]:
    """`request`, `self.request`, and the first parameter of a Django view whatever its name."""
    params = [a.arg for a in [*fn.args.posonlyargs, *fn.args.args]]
    method = bool(params) and params[0] in ("self", "cls")
    found = {"request", "self.request"}
    if django and params[method:]:
        found.add(params[int(method)])
    return found


def _data(node: ast.AST, taint: Taint) -> bool:
    """The whole request data: request.GET, request.data, json.loads(request.body),
    request.get_json(), X.validated_data, or a container name."""
    if isinstance(node, ast.Name):
        return node.id in taint.containers
    if isinstance(node, ast.Call):
        name = pyast.dotted(node.func) or ""
        if name.endswith(("json.loads", "loads")) and node.args:
            return bool(re.search(r"\.body\b", ast.unparse(node.args[0])))
        if name.rsplit(".", 1)[0] in taint.requests and name.endswith(".get_json"):
            return True
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("dict", "copy", "items"):
            return _data(node.func.value, taint)
        return False
    if isinstance(node, ast.Attribute):
        if node.attr == "validated_data":
            return True
        return node.attr in DATA_ATTRS and pyast.dotted(node.value) in taint.requests
    return False


def reads(node: ast.AST, taint: Taint) -> dict[str, str]:
    """Request values used in an expression: tainted names and values read from the request
    data, each with its label (a request key such as "id_number", or the name)."""
    found: dict[str, str] = {}
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in taint.keys:
            found[sub.id] = taint.keys[sub.id]
        elif isinstance(sub, ast.Subscript) and _data(sub.value, taint):
            label = pyast.constant(sub.slice, None)
            found[ast.unparse(sub)] = label if isinstance(label, str) else ast.unparse(sub)
        elif isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
            if sub.func.attr in ("get", "getlist") and _data(sub.func.value, taint) and sub.args:
                label = pyast.constant(sub.args[0], None)
                found[ast.unparse(sub)] = label if isinstance(label, str) else ast.unparse(sub)
        elif isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name):
            if sub.value.id in taint.containers and not isinstance(sub.ctx, ast.Store):
                found[ast.unparse(sub)] = sub.attr
    return found


def _targets(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Assign):
        nodes = node.targets
    elif isinstance(node, ast.AnnAssign | ast.For):
        nodes = [node.target]
    else:
        return []
    return [n.id for t in nodes for n in ast.walk(t) if isinstance(n, ast.Name)]


def _value(node: ast.AST) -> ast.AST | None:
    return node.iter if isinstance(node, ast.For) else getattr(node, "value", None)


def body_schemas(fn: ast.AST) -> set[str]:
    """Django Ninja parameters typed with a schema class: the request body."""
    found = set()
    for arg in [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]:
        name = (pyast.dotted(arg.annotation) or "").split(".")[-1]
        if name[:1].isupper() and name not in SCHEMA_TYPES:
            found.add(arg.arg)
    return found


def _branches(value: ast.AST) -> list[ast.AST]:
    """Both sides of `a if test else b` and every operand of `a or b`."""
    if isinstance(value, ast.IfExp):
        return [*_branches(value.body), *_branches(value.orelse)]
    if isinstance(value, ast.BoolOp):
        return [part for item in value.values for part in _branches(item)]
    return [value]


def trace(fn: ast.AST, seeds: dict[str, str], framework: str) -> Taint:
    """Follow request values through the handler's assignments, in line order. A name keeps
    a request value only while assignments feed it one; a record loaded with it does not."""
    django = framework in ("django", "drf", "ninja")
    schemas = body_schemas(fn) if framework == "ninja" else set()
    taint = Taint(request_names(fn, django), dict(seeds), schemas)
    nodes = sorted(
        (n for n in ast.walk(fn) if isinstance(n, ast.Assign | ast.AnnAssign | ast.For)),
        key=lambda n: (n.lineno, n.col_offset),
    )
    for node in nodes:
        value = _value(node)
        if value is None:
            continue
        names = _targets(node)
        if RECORD.search(ast.unparse(value)):
            for name in names:
                taint.keys.pop(name, None)
            continue
        if any(_data(part, taint) for part in _branches(value)):
            taint.containers.update(names)
            continue
        found = reads(value, taint)
        for name in names:
            if found:
                labels = list(found.values())
                taint.keys[name] = labels[0] if len(names) == 1 and len(labels) == 1 else name
            else:
                taint.keys.pop(name, None)
    return taint
