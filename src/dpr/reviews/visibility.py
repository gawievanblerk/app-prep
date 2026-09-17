"""Visibility predicates: a read lookup that only returns records marked public.

A lookup is skipped by the unscoped query rule only when a truthy visibility key (`published`,
`is_public`, `isPublic`, `visible`, `visibility`) is a top-level key of the lookup's own filter.
A key inside `include`, `select` or a joined model, a false value, and any write (update,
delete, upsert) never count.
"""

from __future__ import annotations

import ast
import re

from dpr.parsing import jsts, pyast

VISIBILITY_NAME = re.compile(r"(?i)^(?:is_?)?(?:published|public|visible)$|^visibility$")
HIDDEN_VALUE = re.compile(r"(?i)private|hidden|draft|internal|false|^0$|^$")
PUBLIC_VALUE = re.compile(r"(?i)public|published|visible|true")
PY_FILTERS = frozenset({"where", "filter", "filter_by", "get", "get_or_404", "first_or_404"})
PY_WRITES = frozenset({"update", "delete", "upsert", "bulk_update", "merge", "save", "insert"})
JS_READS = frozenset(
    {"findUnique", "findUniqueOrThrow", "findFirst", "findFirstOrThrow", "findMany", "findOne"}
)


def _py_truthy(node: ast.AST | None) -> bool:
    value = pyast.constant(node, pyast.MISSING)
    if value is True:
        return True
    if isinstance(value, str):
        return not HIDDEN_VALUE.search(value)
    if isinstance(node, ast.Attribute | ast.Name):
        text = ast.unparse(node)
        return bool(PUBLIC_VALUE.search(text)) and not HIDDEN_VALUE.search(text)
    return False


def _py_predicate(node: ast.AST, model: str | None) -> bool:
    """`Model.published == True`, `Model.is_public`, `Model.published.is_(True)`."""
    column, value = None, None
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        if isinstance(node.ops[0], ast.Eq | ast.Is):
            column, value = node.left, node.comparators[0]
    elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "is_" and node.args:
            column, value = node.func.value, node.args[0]
    elif isinstance(node, ast.Attribute):
        column, value = node, ast.Constant(True)
    if not isinstance(column, ast.Attribute) or not VISIBILITY_NAME.match(column.attr):
        return False
    owner = pyast.dotted(column.value)
    return (model is None or owner == model) and _py_truthy(value)


def py_visible(value: ast.AST, model: str | None) -> bool:
    calls = [n for n in ast.walk(value) if isinstance(n, ast.Call)]
    names = [(pyast.dotted(c.func) or "").split(".")[-1] for c in calls]
    if PY_WRITES & set(names):
        return False
    for call, name in zip(calls, names, strict=True):
        if name not in PY_FILTERS and not name.endswith(("get_object_or_404", "get_list_or_404")):
            continue
        args = [a for arg in call.args for a in _and_parts(arg)]
        if any(_py_predicate(arg, model) for arg in args):
            return True
        for keyword in call.keywords:
            if keyword.arg and VISIBILITY_NAME.match(keyword.arg) and _py_truthy(keyword.value):
                return True
    return False


def _and_parts(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, ast.Call) and (pyast.dotted(node.func) or "").endswith("and_"):
        return list(node.args)
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
        return list(node.values)
    return [node]


def _js_truthy(node) -> bool:
    node = jsts.unwrap(node)
    if node is None:
        return False
    if node.type == "true":
        return True
    if node.type == "string":
        return not HIDDEN_VALUE.search(jsts.string_value(node) or "")
    if node.type == "object":
        return _js_truthy(jsts.object_pairs(node).get("equals"))
    if node.type == "member_expression":
        text = jsts.node_text(node)
        return bool(PUBLIC_VALUE.search(text)) and not HIDDEN_VALUE.search(text)
    return False


def js_visible(call) -> bool:
    """Prisma `findFirst({ where: { published: true } })` or `findOne({ published: true })`."""
    method = jsts.callee(call).split(".")[-1]
    args = jsts.arguments(call)
    if method not in JS_READS or not args:
        return False
    pairs = jsts.object_pairs(args[0])
    where = jsts.object_pairs(pairs["where"]) if "where" in pairs else pairs
    return any(VISIBILITY_NAME.match(key) and _js_truthy(value) for key, value in where.items())
