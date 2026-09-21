"""Small readers over the code of an auth flow: literals sent to the caller, early exits, calls."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.model import Location
from dpr.parsing import jsts, pyast
from dpr.reviews.auth_flows import Code

RESPONSE_CALL = re.compile(
    r"(?:^|\.)(?:HTTPException|JSONResponse|Response|jsonify|abort|make_response|ValueError"
    r"|ValidationError|PermissionError|json|send|status|NextResponse|redirect|render)$"
)
LOG_CALL = re.compile(r"(?:^|\.)(?:logger|logging|log|console|print)\b|^print$")
MISSING_TEST = re.compile(r"\bis None\b|^not \w+$|== None|^!\w+$|=== null|== null|^!\w+\.\w+$")
PASSWORD_VERIFY = re.compile(
    r"(?:^|\.)(?:verify_password|check_password|checkpw|compare|compareSync)$"
    r"|(?:pwd_context|password_context|context|hasher|argon2|bcrypt|crypt_context|ph)\.verify$"
)
DUMMY = re.compile(r"(?i)dummy|fake_hash|timing")


def _py_parents(root: ast.AST) -> dict[ast.AST, ast.AST]:
    return {child: node for node in ast.walk(root) for child in ast.iter_child_nodes(node)}


def _py_to_caller(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    current = parents.get(node)
    while current is not None:
        if isinstance(current, ast.Call):
            name = pyast.dotted(current.func) or ""
            if LOG_CALL.search(name):
                return False
            if RESPONSE_CALL.search(name):
                return True
        if isinstance(current, ast.Raise | ast.Return):
            return True
        if isinstance(current, ast.stmt):
            return False
        current = parents.get(current)
    return False


def _js_to_caller(node) -> bool:
    current = node.parent
    while current is not None:
        if current.type == "call_expression":
            name = jsts.callee(current)
            if LOG_CALL.search(name):
                return False
            if RESPONSE_CALL.search(name):
                return True
        if current.type in ("return_statement", "throw_statement", "new_expression"):
            return True
        if current.type.endswith("statement") or current.type in jsts.FUNCTION_TYPES:
            return False
        current = current.parent
    return False


def caller_literals(code: Code) -> Iterator[tuple[str, Location]]:
    """String literals that reach the HTTP response or an exception, not a log call."""
    if code.python:
        parents = _py_parents(code.node)
        for node in ast.walk(code.node):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                owner = parents.get(node)
                anchor = owner if isinstance(owner, ast.JoinedStr) else node
                if _py_to_caller(anchor, parents):
                    yield node.value, Location(code.rel, node.lineno)
        return
    for node in jsts.walk(code.node, {"string", "template_string"}):
        if _js_to_caller(node):
            yield jsts.node_text(node).strip("'\"`"), Location(code.rel, jsts.line(code.tree, node))


def status_codes(code: Code, values: tuple[int, ...]) -> Iterator[Location]:
    """Places where the flow sets one of these HTTP status codes."""
    names = {f"HTTP_{v}" for v in values}
    if code.python:
        for node in ast.walk(code.node):
            if isinstance(node, ast.Attribute) and any(node.attr.startswith(n) for n in names):
                yield Location(code.rel, node.lineno)
            if isinstance(node, ast.keyword) and node.arg in ("status_code", "status"):
                if pyast.constant(node.value, None) in values:
                    yield Location(code.rel, node.value.lineno)
        return
    for call in jsts.walk(code.node, {"call_expression"}):
        args = jsts.arguments(call)
        if (
            jsts.callee(call).endswith("status")
            and args
            and jsts.node_text(args[0]) in map(str, values)
        ):
            yield Location(code.rel, jsts.line(code.tree, call))
    for pair in jsts.walk(code.node, {"pair"}):
        key = jsts.node_text(pair.child_by_field_name("key"))
        value = jsts.node_text(pair.child_by_field_name("value"))
        if key == "status" and value in map(str, values):
            yield Location(code.rel, jsts.line(code.tree, pair))


def early_exit_before(code: Code, pattern: re.Pattern[str]) -> Location | None:
    """An exit taken when a looked-up record is missing, before a call matching the pattern."""
    if code.python:
        calls = [n for n in ast.walk(code.node) if isinstance(n, ast.Call)]
        targets = [c.lineno for c in calls if pattern.search(pyast.dotted(c.func) or "")]
        if not targets:
            return None
        for node in ast.walk(code.node):
            if not isinstance(node, ast.If) or node.lineno >= min(targets):
                continue
            exits = any(isinstance(s, ast.Return | ast.Raise) for s in node.body)
            inside = any(
                pattern.search(pyast.dotted(c.func) or "")
                for s in node.body
                for c in ast.walk(s)
                if isinstance(c, ast.Call)
            )
            if exits and not inside and MISSING_TEST.search(ast.unparse(node.test)):
                return Location(code.rel, node.lineno)
        return None
    calls = list(jsts.walk(code.node, {"call_expression"}))
    targets = [jsts.line(code.tree, c) for c in calls if pattern.search(jsts.callee(c))]
    if not targets:
        return None
    for node in jsts.walk(code.node, {"if_statement"}):
        line = jsts.line(code.tree, node)
        condition = jsts.node_text(node.child_by_field_name("condition")).strip("() ")
        body = jsts.node_text(node.child_by_field_name("consequence"))
        exits = "return" in body or "throw" in body
        if line < min(targets) and exits and MISSING_TEST.search(condition):
            if not pattern.search(body):
                return Location(code.rel, line)
    return None


def has_dummy_hash(code: Code) -> bool:
    return bool(DUMMY.search(code.text()))


def call_names(code: Code) -> list[tuple[str, int]]:
    if code.python:
        body = getattr(code.node, "body", [code.node])
        return [
            (pyast.dotted(n.func) or "", n.lineno)
            for stmt in body
            for n in ast.walk(stmt)
            if isinstance(n, ast.Call)
        ]
    return [
        (jsts.callee(c), jsts.line(code.tree, c)) for c in jsts.walk(code.node, {"call_expression"})
    ]
