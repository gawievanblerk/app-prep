"""Values in a built SQL string that are fixed in the source: literals and constants.

SQL formatted only from such values cannot carry caller input, so `OWASP-A03-RAW-SQL` skips it.
"""

from __future__ import annotations

import ast
import re

from dpr.parsing import jsts, pyast

# Module and class constants by naming convention, and calls that only reshape constants.
CONSTANT_NAME = re.compile(r"^_?[A-Z][A-Z0-9_]*$")
CONSTANT_CALLS = {"tuple", "list", "set", "frozenset", "sorted", "str", "int", "len"}


def py_constant(
    node: ast.AST, fn: ast.AST | None, module: dict[str, ast.expr], depth: int = 0
) -> bool:
    """A literal, an UPPER_CASE name or attribute, a name only ever assigned such values in
    the function (or at module level), or tuple(), list(), str() or ", ".join() of them."""
    if depth > 3:
        return False
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.Tuple | ast.List | ast.Set):
        return all(py_constant(e, fn, module, depth + 1) for e in node.elts)
    if isinstance(node, ast.Attribute):
        return bool(CONSTANT_NAME.match(node.attr))
    if isinstance(node, ast.Name):
        if CONSTANT_NAME.match(node.id):
            return True
        values = [
            stmt.value
            for stmt in (ast.walk(fn) if fn is not None else [])
            if isinstance(stmt, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == node.id for t in stmt.targets)
        ]
        bound = {
            n.id
            for n in (ast.walk(fn) if fn is not None else [])
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store) and n.id == node.id
        }
        params = {a.arg for a in ast.walk(fn) if isinstance(a, ast.arg)} if fn else set()
        if node.id in params or (bound and not values) or len(values) < len(bound):
            return False
        if not values and node.id in module:
            values = [module[node.id]]
        return bool(values) and all(py_constant(v, fn, module, depth + 1) for v in values)
    if isinstance(node, ast.Call):
        name = pyast.dotted(node.func) or ""
        parts = [*node.args, *(k.value for k in node.keywords)]
        if isinstance(node.func, ast.Attribute) and node.func.attr == "join":
            parts.append(node.func.value)
        elif name not in CONSTANT_CALLS:
            return False
        return all(py_constant(p, fn, module, depth + 1) for p in parts)
    return False


def js_constant(part) -> bool:
    """A template substitution or operand that is a literal, an UPPER_CASE name or member, or
    a local name declared with a literal."""
    node = jsts.unwrap(part.named_children[0] if part.type == "template_substitution" else part)
    if node is None:
        return False
    if node.type in ("string", "number"):
        return True
    if node.type == "member_expression":
        return bool(CONSTANT_NAME.match(jsts.node_text(node.child_by_field_name("property"))))
    if node.type == "identifier":
        if CONSTANT_NAME.match(jsts.node_text(node)):
            return True
        resolved = jsts.unwrap(jsts.resolve_identifier(node))
        return resolved is not None and resolved.type in ("string", "number")
    return False
