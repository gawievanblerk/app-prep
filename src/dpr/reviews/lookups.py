"""Record lookups keyed by a request identifier, and whether the caller scopes them."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from dpr.model import DataModel, Location, Route
from dpr.parsing import jsts, pyast
from dpr.parsing.schemas import find_model
from dpr.reviews.access import Access, path_params
from dpr.reviews.visibility import js_visible, js_written_after, py_visible, py_written_after
from dpr.rules import Context

PY_ORM = re.compile(
    r"\bselect\(|\.where\(|\.filter(?:_by)?\(|\.objects\.|get_object_or_404\(|get_list_or_404\("
    r"|\.get_or_404\(|\.query\.get\(|\b(?:session|db|self\.db|self\.session)\.get\("
)
PY_MODEL = re.compile(
    r"\bselect\(\s*(\w+)|(\w+)\.objects\.|get_(?:object|list)_or_404\(\s*(\w+)"
    r"|(?:session|db)\.get\(\s*(\w+)|(\w+)\.query\b"
)
PY_PK = re.compile(r"\.id\s*==|\bpk\s*=|\bid\s*=|\.get\(\s*\w+\s*,|get_or_404\(|query\.get\(")
LOG_CALLS = re.compile(r"(?:logger|logging|log|print|warnings)\b")
SKIP_CALLS = re.compile(
    r"HTTPException|Response|JSONResponse|str|int|len|dict|list|getattr|isinstance"
)
JS_ORM = re.compile(
    r"(?:\w+)\.(\w+)\.(findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow|update|delete"
    r"|upsert)$|^(\w+)\.(findById|findByIdAndUpdate|findByIdAndDelete|findOne)$"
)
JS_KEY = re.compile(
    r"\b(?:params|req\.params|req\.query|request\.params|context\.params)\.(\w+)"
    r"|searchParams\.get\(\s*['\"](\w+)['\"]"
)
OWNER_COLUMNS = {
    "user_id", "owner_id", "created_by", "author_id", "profile_id", "uploaded_by",
    "uploaded_by_id", "manager_id", "account_id", "customer_id", "client_id", "member_id",
    "org_id", "organization_id", "tenant_id", "workspace_id", "team_id", "company_id",
}  # fmt: skip
USER_MODELS = {"user", "users", "profile", "profiles", "account", "accounts", "customer", "member"}


@dataclass(frozen=True)
class Lookup:
    location: Location
    keys: tuple[str, ...]
    model: str | None
    by_primary_key: bool
    target: str | None
    via: Location | None = None
    visible: bool = False


def snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def model_for(ctx: Context, name: str | None) -> DataModel | None:
    return find_model(ctx.detection.models, name) if name else None


def owned(ctx: Context, name: str | None) -> bool | None:
    """True when the model has an owner or tenant column, None when the model is unknown."""
    if name and name.lower().rstrip("s") in {m.rstrip("s") for m in USER_MODELS}:
        return True
    model = model_for(ctx, name)
    if model is None:
        return None
    columns = {snake(f.name) for f in model.fields}
    if columns & OWNER_COLUMNS:
        return True
    stems = {c[: -len("_id")] for c in columns if c.endswith("_id")}
    for parent in ctx.detection.models:
        names = (snake(parent.name), parent.table.split(".")[-1].rstrip("s"))
        if parent is not model and any(n.endswith(stem) for n in names for stem in stems):
            if {snake(f.name) for f in parent.fields} & OWNER_COLUMNS:
                return True
    return False


def request_keys(route: Route) -> set[str]:
    keys = set(path_params(route))
    fn = route.handler
    if isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
        params = [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
        defaults = [None] * (len(fn.args.posonlyargs) + len(fn.args.args) - len(fn.args.defaults))
        defaults += [*fn.args.defaults, *fn.args.kw_defaults]
        for arg, default in zip(params, defaults, strict=True):
            source = pyast.dotted(default.func) if isinstance(default, ast.Call) else None
            if source in ("Form", "Body", "File"):
                continue
            if arg.arg == "id" or arg.arg.endswith("_id"):
                keys.add(arg.arg)
    return keys


def subject_text(text: str, subjects: tuple[str, ...]) -> bool:
    return any(re.search(rf"(?<![\w.]){re.escape(s)}\b", text) for s in subjects)


def _statements(fn: ast.AST) -> list[ast.stmt]:
    found = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign | ast.AnnAssign | ast.Expr | ast.Return | ast.AugAssign):
            found.append(node)
    return sorted(found, key=lambda n: n.lineno)


def _target(stmt: ast.stmt) -> str | None:
    if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name):
        return stmt.targets[0].id
    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
        return stmt.target.id
    return None


def _model_name(text: str, fn: ast.AST) -> str | None:
    match = PY_MODEL.search(text)
    name = next(g for g in match.groups() if g) if match else None
    if name and name[0].isupper():
        return name
    compared = re.search(r"\b([A-Z]\w*)\.\w+\s*==", text)
    if compared:
        return compared.group(1)
    root = re.match(r"(\w+)\.(?:where|filter)", text)
    if root:
        for stmt in _statements(fn):
            if _target(stmt) == root.group(1):
                found = PY_MODEL.search(ast.unparse(stmt.value))
                if found:
                    return next(g for g in found.groups() if g)
    return None


def helper_index(ctx: Context) -> dict[str, list[tuple[str, ast.AST]]]:
    key = ("helper-index", "")
    if key not in ctx.index.cache:
        found: dict[str, list[tuple[str, ast.AST]]] = {}
        for entry in ctx.index.py_files:
            tree = pyast.parse_file(ctx.index, entry.rel)
            for fn in pyast.functions(tree) if tree else []:
                found.setdefault(fn.name, []).append((entry.rel, fn))
        ctx.index.cache[key] = found
    return ctx.index.cache[key]


def _shared_prefix(a: str, b: str) -> int:
    count = 0
    for left, right in zip(a.split("/"), b.split("/"), strict=False):
        if left != right:
            break
        count += 1
    return count


def _is_method(fn: ast.AST) -> bool:
    args = [*fn.args.posonlyargs, *fn.args.args]
    return bool(args) and args[0].arg in ("self", "cls")


def _helper(ctx: Context, rel: str, call: ast.Call, caller: ast.AST) -> tuple[str, ast.AST] | None:
    """The one definition of the called name, preferring the closest file when names repeat."""
    name = (pyast.dotted(call.func) or "").split(".")[-1]
    method = isinstance(call.func, ast.Attribute)
    defs = [
        d
        for d in helper_index(ctx).get(name, [])
        if d[1] is not caller and _is_method(d[1]) == method
    ]
    if len(defs) <= 1:
        return defs[0] if defs else None
    ranked = sorted(defs, key=lambda d: -_shared_prefix(rel, d[0]))
    if _shared_prefix(rel, ranked[0][0]) > _shared_prefix(rel, ranked[1][0]):
        return ranked[0]
    return None


def _param_names(fn: ast.AST, call: ast.Call, keys: set[str]) -> set[str]:
    params = [a.arg for a in [*fn.args.posonlyargs, *fn.args.args] if a.arg not in ("self", "cls")]
    mapped = set()
    for position, arg in enumerate(call.args):
        if isinstance(arg, ast.Name) and arg.id in keys and position < len(params):
            mapped.add(params[position])
    for keyword in call.keywords:
        if isinstance(keyword.value, ast.Name) and keyword.value.id in keys and keyword.arg:
            mapped.add(keyword.arg)
    return mapped


SUBJECT_PARAMS = re.compile(r"(?i)user|owner|actor|caller|principal|account|member|tenant|org")


def py_lookups(
    ctx: Context, rel: str, fn: ast.AST, keys: set[str], subjects: tuple[str, ...], depth: int = 0
) -> list[Lookup]:
    found = []
    for stmt in _statements(fn):
        value = stmt if isinstance(stmt, ast.Expr) else getattr(stmt, "value", None)
        if value is None:
            continue
        text = ast.unparse(value)
        names = pyast.names_in(value)
        used = names & keys
        if not used or subject_text(text, subjects):
            continue
        if PY_ORM.search(text):
            model = _model_name(text, fn)
            found.append(
                Lookup(
                    Location(rel, stmt.lineno),
                    tuple(sorted(used)),
                    model,
                    bool(PY_PK.search(text)),
                    _target(stmt),
                    visible=py_visible(value, model)
                    and not py_written_after(fn, _target(stmt), stmt.lineno),
                )
            )
            continue
        if depth >= 2:
            continue
        for call in [n for n in ast.walk(value) if isinstance(n, ast.Call)]:
            name = pyast.dotted(call.func) or ""
            if LOG_CALLS.match(name) or SKIP_CALLS.fullmatch(name.split(".")[-1]):
                continue
            if not pyast.names_in(call) & keys:
                continue
            helper = _helper(ctx, rel, call, fn)
            if helper is None:
                continue
            helper_rel, helper_fn = helper
            params = {a.arg for a in [*helper_fn.args.args, *helper_fn.args.kwonlyargs]}
            if any(SUBJECT_PARAMS.search(p) for p in params):
                continue
            mapped = _param_names(helper_fn, call, keys)
            inner = py_lookups(ctx, helper_rel, helper_fn, mapped, (), depth + 1)
            for item in inner:
                via = item.via or item.location
                found.append(
                    Lookup(
                        Location(rel, stmt.lineno),
                        tuple(sorted(used)),
                        item.model,
                        item.by_primary_key,
                        _target(stmt),
                        via,
                        item.visible and not py_written_after(fn, _target(stmt), stmt.lineno),
                    )
                )
            if inner:
                break
    return found


def py_checked_after(fn: ast.AST, lookup: Lookup, subjects: tuple[str, ...]) -> str:
    """'owner' when a later comparison or call uses both the subject and the record, 'helper'
    when a later call receives only the subject, else ''."""
    targets = {lookup.target} if lookup.target else set()
    for stmt in _statements(fn):
        if stmt.lineno > lookup.location.line and _target(stmt):
            if pyast.names_in(stmt.value) & targets:
                targets.add(_target(stmt))
    pattern = (
        re.compile(r"\b(?:" + "|".join(re.escape(t) for t in targets) + r")\b") if targets else None
    )
    result = ""
    for node in ast.walk(fn):
        if getattr(node, "lineno", 0) <= lookup.location.line:
            continue
        if isinstance(node, ast.Compare):
            text = ast.unparse(node)
        elif isinstance(node, ast.Call) and not LOG_CALLS.match(pyast.dotted(node.func) or ""):
            text = " ".join(ast.unparse(a) for a in [*node.args, *node.keywords])
        else:
            continue
        if not subject_text(text, subjects):
            continue
        if pattern is None or pattern.search(text):
            return "owner"
        if isinstance(node, ast.Call):
            result = "helper"
    return result


ONE_TIME_KEYS = re.compile(r"(?i)token|code|otp|nonce|signature|secret")


def js_keys(handler) -> set[str]:
    text = jsts.node_text(handler)
    keys = {next(g for g in m.groups() if g) for m in JS_KEY.finditer(text)}
    for match in re.finditer(r"\{\s*([\w\s,:]+)\}\s*=\s*(?:await\s+)?(?:\w+\.)?params\b", text):
        keys.update(n.strip().split(":")[-1].strip() for n in match.group(1).split(","))
    return {k for k in keys if k and not ONE_TIME_KEYS.search(k)}


def js_lookups(route: Route, subjects: tuple[str, ...]) -> list[Lookup]:
    tree, handler = route.tree, route.handler
    keys = js_keys(handler)
    found = []
    for call in jsts.calls(tree, re.compile(r".*"), handler):
        match = JS_ORM.search(jsts.callee(call))
        if not match:
            continue
        text = jsts.node_text(call)
        used = {k for k in keys if re.search(rf"\b{re.escape(k)}\b", text)}
        if not used or subject_text(text, subjects):
            continue
        model = match.group(1) or match.group(3)
        target = None
        parent = call.parent
        while parent is not None and parent.type in (
            "await_expression",
            "parenthesized_expression",
        ):
            parent = parent.parent
        if parent is not None and parent.type == "variable_declarator":
            target = jsts.node_text(parent.child_by_field_name("name"))
        pk = bool(re.search(r"\bid\s*:|findById", text))
        found.append(
            Lookup(
                Location(route.file, jsts.line(tree, call)),
                tuple(sorted(used)),
                model,
                pk,
                target,
                visible=js_visible(call) and not js_written_after(handler, call, target),
            )
        )
    return found


def js_checked_after(route: Route, lookup: Lookup, subjects: tuple[str, ...]) -> str:
    for node in jsts.walk(route.handler, {"binary_expression"}):
        if jsts.line(route.tree, node) <= lookup.location.line:
            continue
        text = jsts.node_text(node)
        if subject_text(text, subjects) and (
            lookup.target is None or re.search(rf"\b{re.escape(lookup.target)}\b", text)
        ):
            return "owner"
    return ""


def route_lookups(ctx: Context, route: Route, access: Access) -> list[tuple[Lookup, str]]:
    """Unscoped lookups of a route with the later check kind: 'owner', 'helper' or ''."""
    subjects = access.subjects
    if isinstance(route.handler, ast.AST) and route.framework in ("fastapi", "flask", "django"):
        fn = route.handler
        if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
            return []
        derived = tuple(
            _target(s)
            for s in _statements(fn)
            if _target(s) and subject_text(ast.unparse(s.value), subjects)
        )
        subjects = (*subjects, *derived)
        keys = request_keys(route)
        checked = [
            (item, py_checked_after(fn, item, subjects))
            for item in py_lookups(ctx, route.file, fn, keys, subjects)
        ]
        verified = {k for item, check in checked if check == "owner" for k in item.keys}
        return [(item, check) for item, check in checked if not set(item.keys) <= verified]
    if route.tree is not None and route.handler is not None and hasattr(route.handler, "type"):
        if route.handler.type in jsts.FUNCTION_TYPES:
            subjects = (*subjects, *(("req.user",) if route.framework == "express" else ()))
            return [
                (item, js_checked_after(route, item, subjects))
                for item in js_lookups(route, subjects)
            ]
    return []
