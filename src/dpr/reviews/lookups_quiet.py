"""Lookups whose route sends nothing personal about the record.

A lookup is quiet when it only checks that a record exists or counts records (`.exists()`,
`.count()`), or when the handler writes nothing and every response it returns is a redirect, an
error status, or a body built only from literals, numbers, comparisons and fields whose names
the personal data classifier does not mark, with no serializer, form, template or record dump.
"""

from __future__ import annotations

import ast
import re

from dpr.parsing import pyast
from dpr.reviews.lookups import PY_ORM
from dpr.reviews.personal import classify

REDIRECTS = frozenset({"redirect", "HttpResponseRedirect", "HttpResponsePermanentRedirect"})
STATUS_RESPONSES = frozenset(
    {"HttpResponseNotFound", "HttpResponseForbidden", "HttpResponseBadRequest",
     "HttpResponseNotAllowed", "HttpResponseServerError", "HttpResponseGone"}
)  # fmt: skip
BODY_RESPONSES = frozenset({"HttpResponse", "JsonResponse", "Response", "JSONResponse", "jsonify"})
WRAPPERS = frozenset(
    {"dumps", "str", "int", "float", "round", "bool", "Decimal", "abs", "sum", "min", "max",
     "len", "format"}
)  # fmt: skip
COUNTS = frozenset({"exists", "count", "aggregate"})
DUMPS = re.compile(
    r"(?:^|_)(?:as_table|as_p|as_ul|serialize\w*|values|values_list|to_dict|as_dict|dict|data"
    r"|render\w*)$|model_to_dict|__dict__"
)
BUILDERS = re.compile(r"(?:Form|Serializer|model_to_dict|render_to_string|vars)\b")
# A call whose name starts with one of these verbs may change data or send it somewhere.
WRITE_VERBS = frozenset(
    {"save", "delete", "update", "create", "bulk", "set", "delay", "apply", "send", "remove",
     "clear", "add", "reset", "mark", "process", "approve", "decline", "reject", "cancel", "sync",
     "submit", "assign", "attach", "detach", "link", "unlink", "activate", "deactivate", "close",
     "reopen", "import", "run", "generate", "notify", "email", "sms", "queue", "schedule",
     "trigger", "start", "stop", "archive", "restore", "move", "merge", "upload", "write",
     "record", "refund", "pay", "allocate", "capture", "confirm", "accept", "register", "enable",
     "disable", "lock", "unlock", "block", "unblock", "change", "edit", "modify", "replace",
     "fix", "correct", "split", "post", "put", "patch", "call", "execute", "commit", "resend"}
)  # fmt: skip
FILLERS = frozenset({"update", "append", "extend", "insert", "setdefault"})


def _last(node: ast.AST) -> str:
    return (pyast.dotted(node) or "").split(".")[-1]


def _own_nodes(fn: ast.AST) -> list[ast.AST]:
    """Nodes of the function, not of functions or classes nested in it."""
    found, stack = [], list(ast.iter_child_nodes(fn))
    while stack:
        node = stack.pop()
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Lambda):
            continue
        found.append(node)
        stack.extend(ast.iter_child_nodes(node))
    return found


class _Values:
    """What each local name of a handler is built from."""

    def __init__(self, fn: ast.AST) -> None:
        self.parts: dict[str, list[ast.AST]] = {}
        for node in _own_nodes(fn):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    self._assign(target, node.value)
            elif isinstance(node, ast.AugAssign | ast.AnnAssign) and node.value is not None:
                self._assign(node.target, node.value)
            elif isinstance(node, ast.For | ast.comprehension):
                self._assign(node.target, node.iter)
            elif isinstance(node, ast.withitem) and node.optional_vars is not None:
                self._assign(node.optional_vars, node.context_expr)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                owner = node.func.value
                if isinstance(owner, ast.Name) and node.func.attr in FILLERS:
                    self.parts.setdefault(owner.id, []).extend(node.args)

    def _assign(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Name):
            self.parts.setdefault(target.id, []).append(value)
        elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
            key = pyast.constant(target.slice, None)
            entry = ast.Dict(keys=[ast.Constant(key)], values=[value])
            self.parts.setdefault(target.value.id, []).append(entry)
        elif isinstance(target, ast.Tuple | ast.List):
            for item in target.elts:
                self._assign(item, value)

    def built(self, name: str) -> str:
        return " ".join(ast.unparse(v) for v in self.parts.get(name, []))


def _personal(name: object) -> bool:
    return not isinstance(name, str) or classify(name) is not None


def _quiet(node: ast.AST | None, values: _Values, seen: frozenset[str] = frozenset()) -> bool:
    """A value that carries no personal data and no whole record."""
    if node is None or isinstance(node, ast.Constant | ast.Compare):
        return True
    if isinstance(node, ast.JoinedStr):
        return all(_quiet(v, values, seen) for v in node.values)
    if isinstance(node, ast.FormattedValue):
        return _quiet(node.value, values, seen)
    if isinstance(node, ast.BinOp):
        return _quiet(node.left, values, seen) and _quiet(node.right, values, seen)
    if isinstance(node, ast.BoolOp | ast.List | ast.Tuple | ast.Set):
        items = node.values if isinstance(node, ast.BoolOp) else node.elts
        return all(_quiet(v, values, seen) for v in items)
    if isinstance(node, ast.UnaryOp):
        return _quiet(node.operand, values, seen)
    if isinstance(node, ast.IfExp):
        return _quiet(node.body, values, seen) and _quiet(node.orelse, values, seen)
    if isinstance(node, ast.Dict):
        return all(_entry(k, v, values, seen) for k, v in zip(node.keys, node.values, strict=True))
    if isinstance(node, ast.Subscript):
        key = pyast.constant(node.slice, None)
        if not isinstance(key, str | int) or isinstance(key, str) and _personal(key):
            return False
        return _quiet(node.value, values, seen)
    if isinstance(node, ast.Attribute):
        return _field(node.attr, node.value, values)
    if isinstance(node, ast.Call):
        return _call(node, values, seen)
    if isinstance(node, ast.Name):
        if node.id in seen:
            return True
        parts = values.parts.get(node.id)
        if parts is None:  # a parameter or a global: judged by its name
            return not _personal(node.id)
        return all(_quiet(p, values, seen | {node.id}) for p in parts)
    return False


def _entry(key: ast.AST | None, value: ast.AST, values: _Values, seen: frozenset[str]) -> bool:
    """A literal value; a field read or a local name judged by what it reads
    (`division_display_name` holding `get_division_display()`); any other value also needs a
    key that is not personal."""
    if isinstance(value, ast.Constant):
        return key is not None
    read = (
        isinstance(value, ast.Attribute)
        or isinstance(value, ast.Name)
        and value.id in values.parts
        or isinstance(value, ast.Call)
        and isinstance(value.func, ast.Attribute)
        and _last(value.func) not in WRAPPERS
    )
    if not read and _personal(pyast.constant(key, None) if key is not None else None):
        return False
    return _quiet(value, values, seen)


def _field(attr: str, owner: ast.AST, values: _Values) -> bool:
    if classify(attr) is not None or DUMPS.search(attr):
        return False
    root = pyast.name_root(owner)
    return not (root and BUILDERS.search(values.built(root)))


def _call(node: ast.Call, values: _Values, seen: frozenset[str]) -> bool:
    name = _last(node.func)
    text = ast.unparse(node)
    if name in COUNTS:
        return True
    if PY_ORM.search(text) or BUILDERS.search(pyast.dotted(node.func) or ""):
        return False
    if name in WRAPPERS:
        return all(_quiet(a, values, seen) for a in node.args)
    if isinstance(node.func, ast.Attribute):
        display = re.fullmatch(r"get_(\w+)_display", name)
        field = display.group(1) if display else name
        arguments = [*node.args, *(k.value for k in node.keywords)]
        return _field(field, node.func.value, values) and all(
            _quiet(a, values, seen) for a in arguments
        )
    return False


def _target(node: ast.AST | None, values: _Values, depth: int = 0) -> bool:
    """A redirect target that says nothing about a record: a literal, `reverse(...)`, an id."""
    if node is None or isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.JoinedStr):
        return all(_target(v, values, depth) for v in node.values)
    if isinstance(node, ast.FormattedValue):
        return _target(node.value, values, depth)
    if isinstance(node, ast.BinOp):
        return _target(node.left, values, depth) and _target(node.right, values, depth)
    if isinstance(node, ast.Call):
        return _last(node.func) in ("reverse", "resolve_url", "reverse_lazy")
    if isinstance(node, ast.Attribute):
        return node.attr in ("id", "pk")
    if isinstance(node, ast.Name) and depth < 3:
        parts = values.parts.get(node.id)
        return parts is None or all(_target(p, values, depth + 1) for p in parts)
    return False


def _response(node: ast.AST | None, values: _Values, depth: int = 0) -> bool:
    if node is None:
        return True
    if isinstance(node, ast.Name) and depth < 3:
        parts = values.parts.get(node.id, [])
        return bool(parts) and all(_response(p, values, depth + 1) for p in parts)
    if not isinstance(node, ast.Call):
        return False
    name = _last(node.func)
    if name in REDIRECTS:
        return all(_target(a, values) for a in [*node.args, *(k.value for k in node.keywords)])
    if name in STATUS_RESPONSES or name in BODY_RESPONSES:
        return all(_quiet(a, values) for a in node.args)
    return False


def _writes(name: str) -> bool:
    first = name.lstrip("_").split("_", 1)[0].lower()
    return first in WRITE_VERBS or name.endswith("_or_create")


def quiet_handler(fn: ast.AST) -> bool:
    """The handler writes nothing and none of its responses carries personal data."""
    nodes = _own_nodes(fn)
    if any(isinstance(n, ast.Call) and _writes(_last(n.func)) for n in nodes):
        return False
    returns = [n for n in nodes if isinstance(n, ast.Return)]
    values = _Values(fn)
    return bool(returns) and all(_response(r.value, values) for r in returns)


def counted(fn: ast.AST, line: int) -> bool:
    """The lookup on this line only checks existence or counts: `.exists()`, `.count()`."""
    for node in _own_nodes(fn):
        if isinstance(node, ast.Assign | ast.Expr | ast.Return) and node.lineno == line:
            value = node.value
            while isinstance(value, ast.Call) and _last(value.func) in ("bool", "len", "int"):
                value = value.args[0] if value.args else None
            return isinstance(value, ast.Call) and _last(value.func) in COUNTS
    return False
