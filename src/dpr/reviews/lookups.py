"""Record lookups keyed by a request identifier, and whether the caller scopes them."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from dpr.model import DataModel, Location, Route
from dpr.parsing import pyast
from dpr.parsing.schemas import find_model
from dpr.reviews.access import path_params
from dpr.reviews.request_values import Taint, identifier, reads
from dpr.reviews.visibility import py_visible, py_written_after
from dpr.rules import Context

PY_ORM = re.compile(
    r"\bselect\(|\.where\(|\.filter(?:_by)?\(|\.objects\.|get_object_or_404\(|get_list_or_404\("
    r"|\.get_or_404\(|\.query\.get\(|\b(?:session|db|self\.db|self\.session)\.get\("
)
PY_MODEL = re.compile(
    r"\bselect\(\s*(\w+)|(\w+)\.objects\.|get_(?:object|list)_or_404\(\s*(?:\w+\.)*(\w+)"
    r"|(?:session|db)\.get\(\s*(\w+)|(\w+)\.query\b"
)
PY_PK = re.compile(r"\.id\s*==|\bpk\s*=|\bid\s*=|\.get\(\s*\w+\s*,|get_or_404\(|query\.get\(")
LOG_CALLS = re.compile(r"(?:logger|logging|log|print|warnings)\b")
SKIP_CALLS = re.compile(
    r"HTTPException|Response|JSONResponse|str|int|len|dict|list|getattr|isinstance"
)
OWNER_COLUMNS = {
    "user_id", "owner_id", "created_by", "author_id", "profile_id", "uploaded_by",
    "uploaded_by_id", "manager_id", "account_id", "customer_id", "client_id", "member_id",
    "org_id", "organization_id", "tenant_id", "workspace_id", "team_id", "company_id",
}  # fmt: skip
SCOPED = re.compile(
    r"\.(?:\w+_)?(?:by_user|for_user|visible_to|owned_by|accessible_by|accessible_to|for_owner"
    r"|of_user)\("
)
NOT_A_CHECK = re.compile(r"(?:Serializer|Form|render|smart_respond|Response|redirect)$")
VIEW_METHODS = frozenset(
    {"get", "post", "put", "patch", "delete", "list", "retrieve", "create", "update",
     "partial_update", "destroy"}
)  # fmt: skip
FOREIGN_KEYS = frozenset({"ForeignKey", "OneToOneField"})
# A call named like a check raises or answers whether the caller may act: `has_access`,
# `check_policy_access`, `user_owns_policy`, `policy.assert_owner`; `log_access` is not one.
CHECK_WORDS = frozenset(
    {"has", "can", "check", "verify", "assert", "ensure", "require", "validate", "allowed",
     "authorize", "authorise", "permitted", "owns"}
)  # fmt: skip
DATE_PARAM = re.compile(r"(?i)(?:^|_)(?:date|from|to|year|month|day|time)$")
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


def _columns(model: DataModel) -> set[str]:
    """Column names, with a Django foreign key `user` also read as its column `user_id`."""
    columns = {snake(f.name) for f in model.fields}
    return columns | {f"{snake(f.name)}_id" for f in model.fields if f.type in FOREIGN_KEYS}


def user_model(name: str) -> bool:
    lowered = name.lower().rstrip("s")
    return lowered in {m.rstrip("s") for m in USER_MODELS} or lowered.endswith("user")


def owned(ctx: Context, name: str | None) -> bool | None:
    """True when the model has an owner or tenant column, None when the model is unknown."""
    if name and user_model(name):
        return True
    model = model_for(ctx, name)
    if model is None:
        return None
    columns = _columns(model)
    if columns & OWNER_COLUMNS:
        return True
    stems = {c[: -len("_id")] for c in columns if c.endswith("_id")}
    for parent in ctx.detection.models:
        names = (snake(parent.name), parent.table.split(".")[-1].rstrip("s"))
        if parent is not model and any(n.endswith(stem) for n in names for stem in stems):
            if _columns(parent) & OWNER_COLUMNS:
                return True
    return False


def request_keys(route: Route, fn: ast.AST | None = None) -> set[str]:
    """Path parameters (not dates) and identifier-named handler parameters."""
    keys = {p for p in path_params(route) if not DATE_PARAM.search(p)}
    fn = fn or route.handler
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


def statements(fn: ast.AST) -> list[ast.stmt]:
    """Assignments, expressions and returns in line order, up to the function's first
    top-level return or raise: code after it never runs."""
    exit_ = next((s for s in fn.body if isinstance(s, ast.Return | ast.Raise)), None)
    last = exit_.end_lineno if exit_ is not None else float("inf")
    found = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign | ast.AnnAssign | ast.Expr | ast.Return | ast.AugAssign):
            if node.lineno <= last:
                found.append(node)
    return sorted(found, key=lambda n: n.lineno)


def statement_target(stmt: ast.stmt) -> str | None:
    if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name):
        return stmt.targets[0].id
    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value:
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
        for stmt in statements(fn):
            if statement_target(stmt) == root.group(1):
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


def resolve_helper(
    ctx: Context, rel: str, call: ast.Call, caller: ast.AST
) -> tuple[str, ast.AST] | None:
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


def _used(value: ast.AST, keys: set[str], taint: Taint | None) -> set[str]:
    """Request identifiers the expression uses: path keys and names derived from them, and
    request values (query string, form, JSON body) whose name or request key is an id."""
    if taint is None:
        return pyast.names_in(value) & keys
    found = set()
    for name, label in reads(value, taint).items():
        if label in keys or name in keys or identifier(label) or identifier(name):
            found.add(name if name.isidentifier() else label)
    return found


def py_lookups(
    ctx: Context,
    rel: str,
    fn: ast.AST,
    keys: set[str],
    subjects: tuple[str, ...],
    depth: int = 0,
    taint: Taint | None = None,
) -> list[Lookup]:
    found = []
    for stmt in statements(fn):
        value = stmt if isinstance(stmt, ast.Expr) else getattr(stmt, "value", None)
        if value is None:
            continue
        text = ast.unparse(value)
        used = _used(value, keys, taint)
        if not used or subject_text(text, subjects) or SCOPED.search(text):
            continue
        if PY_ORM.search(text):
            model = _model_name(text, fn)
            found.append(
                Lookup(
                    Location(rel, stmt.lineno),
                    tuple(sorted(used)),
                    model,
                    bool(PY_PK.search(text)),
                    statement_target(stmt),
                    visible=py_visible(value, model)
                    and not py_written_after(fn, statement_target(stmt), stmt.lineno),
                )
            )
            continue
        if depth >= 2:
            continue
        for call in [n for n in ast.walk(value) if isinstance(n, ast.Call)]:
            name = pyast.dotted(call.func) or ""
            if LOG_CALLS.match(name) or SKIP_CALLS.fullmatch(name.split(".")[-1]):
                continue
            if not pyast.names_in(call) & used:
                continue
            helper = resolve_helper(ctx, rel, call, fn)
            if helper is None:
                continue
            helper_rel, helper_fn = helper
            params = {a.arg for a in [*helper_fn.args.args, *helper_fn.args.kwonlyargs]}
            if any(SUBJECT_PARAMS.search(p) for p in params):
                continue
            mapped = _param_names(helper_fn, call, used)
            inner = py_lookups(ctx, helper_rel, helper_fn, mapped, (), depth + 1)
            for item in inner:
                via = item.via or item.location
                found.append(
                    Lookup(
                        Location(rel, stmt.lineno),
                        tuple(sorted(used)),
                        item.model,
                        item.by_primary_key,
                        statement_target(stmt),
                        via,
                        item.visible
                        and not py_written_after(fn, statement_target(stmt), stmt.lineno),
                    )
                )
            if inner:
                break
    return found


def _guards(fn: ast.AST) -> set[int]:
    """Nodes inside a guard: the test of an `if` whose branch returns or raises (a redirect, a
    404 or a 403 on mismatch), or of an `assert`."""
    found: set[int] = set()
    for node in ast.walk(fn):
        test = None
        if isinstance(node, ast.If):
            exits = [s for s in [*node.body, *node.orelse] if isinstance(s, ast.Return | ast.Raise)]
            test = node.test if exits else None
        elif isinstance(node, ast.Assert):
            test = node.test
        found |= {id(sub) for sub in ast.walk(test)} if test is not None else set()
    return found


def py_checked_after(fn: ast.AST, lookup: Lookup, subjects: tuple[str, ...]) -> str:
    """'owner' when a later guard (an `if` that returns or raises, an `assert`, or a call named
    like a check such as `has_access`) uses both the subject and the record, 'helper' when a
    later call receives the subject without such a guard, else ''."""
    guards = _guards(fn)
    targets = {lookup.target} if lookup.target else set()
    for stmt in statements(fn):
        if stmt.lineno > lookup.location.line and statement_target(stmt):
            if pyast.names_in(stmt.value) & targets:
                targets.add(statement_target(stmt))
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
            if NOT_A_CHECK.search(pyast.dotted(node.func) or ""):
                continue
            text = " ".join(ast.unparse(a) for a in [*node.args, *node.keywords])
        else:
            continue
        if not subject_text(text, subjects):
            continue
        record_text = re.sub("|".join(rf"(?<![\w.]){re.escape(s)}\b" for s in subjects), " ", text)
        called = (pyast.dotted(node.func) or "") if isinstance(node, ast.Call) else ""
        named = set(re.split(r"[._]", called.split(".")[-1].lower())) & CHECK_WORDS
        guard = id(node) in guards or bool(named)
        if guard and (pattern is None or pattern.search(record_text)):
            return "owner"
        if isinstance(node, ast.Call):
            result = "helper"
    return result
