"""Review 6, place 3: request and response loggers that keep whole headers or bodies.

A function (typically a middleware) that passes whole request headers (`request.headers`,
`request.META`), a whole request body (`request.body`, `request.data`, `request.POST`,
`request.GET.dict()`) or a whole response body (`response.content`, `response.data`) to a log
call (headers only: bodies in log lines are left to `LEAK-LOGGED-PII`) or a database write,
directly or through local names, dicts and `dict.update`, with no redaction step in the
function.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Tag
from dpr.parsing import pyast
from dpr.redact import snippet
from dpr.reviews.app_code import app_py_files
from dpr.rules import Context, make_finding, rule

REQUEST = r"(?:request|req|self\.request)"
SOURCES = (
    ("headers", re.compile(rf"^{REQUEST}\.(?:headers|META)$")),
    ("request", re.compile(rf"^{REQUEST}\.(?:body|data|POST|GET)$")),
    ("response", re.compile(r"^(?:response|resp|res)\.(?:content|data)$")),
)
PASS = frozenset(
    {"dumps", "loads", "str", "repr", "dict", "list", "format", "decode", "encode", "copy",
     "deepcopy", "update", "setdefault", "append"}
)  # fmt: skip
WHOLE = frozenset({"decode", "encode", "dict", "copy", "strip", "read"})
PICKED = frozenset({"get", "getlist", "items", "keys", "__contains__"})
LOG_CALL = re.compile(
    r"(?:^|\.)(?:logger|logging|log|_logger|LOGGER)\.(?:debug|info|warning|warn|error|exception"
    r"|critical|log)$|^print$"
)
WRITE_CALL = re.compile(r"\.objects\.(?:create|bulk_create|get_or_create|update_or_create)$")
REDACT = re.compile(r"(?i)redact|mask|scrub|sanitiz|obfuscat|censor|strip_sensitive")


def _to_call(parents: dict[int, ast.AST], child: ast.AST) -> bool:
    """The value is handed to a call other than a copy or format step (`json.dumps`, `str`,
    `decode` and similar), possibly through `or`/`if` defaults: a form, serializer or helper
    takes what it needs, so the value is not stored whole."""
    parent = parents.get(id(child))
    while isinstance(parent, ast.Attribute) and parent.attr in WHOLE:
        call = parents.get(id(parent))  # request.GET.dict(): the value is the call
        if not isinstance(call, ast.Call) or call.func is not parent:
            break
        child, parent = call, parents.get(id(call))
    while isinstance(parent, ast.BoolOp | ast.IfExp):
        child, parent = parent, parents.get(id(parent))
    if not isinstance(parent, ast.Call) or child is parent.func:
        return False
    return (pyast.dotted(parent.func) or "").split(".")[-1] not in PASS


def _sources(node: ast.AST) -> dict[str, int]:
    """Whole headers or bodies the expression holds: an attribute not narrowed by a subscript
    or a `.get(...)`, with its line."""
    found: dict[str, int] = {}
    parents = {id(c): p for p in ast.walk(node) for c in ast.iter_child_nodes(p)}
    for child in ast.walk(node):
        if not isinstance(child, ast.Attribute):
            continue
        text = pyast.dotted(child) or ""
        kind = next((k for k, pattern in SOURCES if pattern.match(text)), None)
        parent = parents.get(id(child))
        if kind is None or isinstance(parent, ast.Subscript) and parent.value is child:
            continue
        if isinstance(parent, ast.Attribute) and parent.attr in PICKED or _to_call(parents, child):
            continue
        found.setdefault(kind, child.lineno)
    return found


def _whole_names(node: ast.AST) -> set[str]:
    """Names the expression uses whole: not narrowed by a subscript or an attribute (other than
    `decode()`, `dict()` and similar), and not handed to another call."""
    parents = {id(c): p for p in ast.walk(node) for c in ast.iter_child_nodes(p)}
    found = set()
    for child in ast.walk(node):
        if not isinstance(child, ast.Name):
            continue
        parent = parents.get(id(child))
        if isinstance(parent, ast.Subscript) and parent.value is child:
            continue
        if isinstance(parent, ast.Attribute) and parent.attr not in WHOLE:
            continue
        if _to_call(parents, child):
            continue
        found.add(child.id)
    return found


def _assignments(fn: ast.AST) -> list[tuple[ast.AST, list[str]]]:
    """Values and the names they flow into, in line order: assignments (a subscript target
    fills its container) and `name.update(...)` calls."""
    found = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign | ast.AugAssign | ast.AnnAssign) and node.value:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            found.append((node, [pyast.name_root(t) for t in targets if pyast.name_root(t)]))
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            root = pyast.name_root(node.func.value)
            if node.func.attr in ("update", "setdefault", "append") and root:
                found.append((node, [root]))
    return sorted(found, key=lambda item: (item[0].lineno, item[0].col_offset))


def _flows(fn: ast.AST) -> dict[str, dict[str, int]]:
    """Names holding whole headers or bodies, with the kinds and where each was read."""
    held: dict[str, dict[str, int]] = {}
    for node, targets in _assignments(fn):
        value = (
            node.value
            if not isinstance(node, ast.Call)
            else ast.Tuple([*node.args, *(k.value for k in node.keywords)])
        )
        kinds = _sources(value)
        for name in _whole_names(value):
            for kind, line in held.get(name, {}).items():
                kinds.setdefault(kind, line)
        for target in targets if kinds else []:
            for kind, line in kinds.items():
                held.setdefault(target, {}).setdefault(kind, line)
    return held


def stored(fn: ast.AST) -> tuple[dict[str, int], int] | None:
    """Kinds of whole headers or bodies a function logs or saves, and the sink's line."""
    if REDACT.search(ast.unparse(fn)):
        return None
    held = _flows(fn)
    kinds: dict[str, int] = {}
    sink = 0
    for call in sorted(
        (n for n in ast.walk(fn) if isinstance(n, ast.Call)), key=lambda n: n.lineno
    ):
        name = pyast.dotted(call.func) or ""
        table = bool(WRITE_CALL.search(name))
        if not (LOG_CALL.search(name) or table):
            continue
        for part in [*call.args, *(k.value for k in call.keywords)]:
            found = _sources(part)
            for held_name in _whole_names(part):
                for kind, line in held.get(held_name, {}).items():
                    found.setdefault(kind, line)
            if not table:  # bodies in log lines are left to LEAK-LOGGED-PII
                found = {k: v for k, v in found.items() if k == "headers"}
            for kind, line in found.items():
                kinds.setdefault(kind, line)
            sink = sink or (call.lineno if found else 0)
    return (kinds, sink) if kinds else None


def _what(kinds: dict[str, int]) -> str:
    """ "whole request headers and request and response bodies" and shorter forms."""
    bodies = [k for k in ("request", "response") if k in kinds]
    parts = ["request headers"] if "headers" in kinds else []
    if bodies:
        parts.append(" and ".join(bodies) + " bodies")
    return "whole " + " and ".join(parts)


@rule("LEAK-REQUEST-LOG", review="leaks", severity="medium", exploitability="low")
def request_log(ctx: Context) -> Iterator[Finding]:
    for rel, text, tree in app_py_files(ctx, ".headers", ".META", ".body", ".content", ".data"):
        classes = {
            id(fn): cls.name
            for cls in pyast.class_defs(tree)
            for fn in cls.body
            if isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef)
        }
        for fn in pyast.functions(tree):
            result = stored(fn)
            if result is None:
                continue
            kinds, sink = result
            first = min(kinds.values())
            where = f"{classes[id(fn)]}.{fn.name}" if id(fn) in classes else fn.name
            yield make_finding(
                "LEAK-REQUEST-LOG",
                tag=Tag.CONFIRMED,
                locations=[Location(rel, sink), Location(rel, first)],
                snippet=snippet(text, sink),
                severity=None if "headers" in kinds else "low",
                where=where,
                what=_what(kinds),
            )
