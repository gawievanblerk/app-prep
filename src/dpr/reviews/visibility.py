"""Visibility predicates: a read lookup that only returns records marked public.

A lookup is skipped by the unscoped query rule only when all of these hold: a visibility key
(`published`, `is_public`, `isPublic`, `visible`, `visibility`) is a top-level key of the
lookup's own filter; its value is a literal that means public (`True`, `true`, `1`, `"public"`,
`"published"`); the call is a read (no update, delete or upsert); and the handler does not
write to the loaded record afterwards. A value from the request, any other literal, a key
inside `include`, `select` or a joined model, and a later write never count.
"""

from __future__ import annotations

import ast
import re

from dpr.parsing import jsts, pyast

VISIBILITY_NAME = re.compile(r"(?i)^(?:is_?)?(?:published|public|visible)$|^visibility$")
PUBLIC_WORDS = frozenset({"public", "published"})
PY_FILTERS = frozenset({"where", "filter", "filter_by", "get", "get_or_404", "first_or_404"})
PY_WRITES = frozenset({"update", "delete", "upsert", "bulk_update", "merge", "save", "insert"})
JS_READS = frozenset(
    {"findUnique", "findUniqueOrThrow", "findFirst", "findFirstOrThrow", "findMany", "findOne"}
)
LATER_WRITES = frozenset(
    {"update", "save", "commit", "delete", "destroy", "remove", "upsert", "merge", "add",
     "setattr", "assign", "updateOne", "findByIdAndUpdate", "findByIdAndDelete"}
)  # fmt: skip


def _py_public_literal(node: ast.AST | None) -> bool:
    value = pyast.constant(node, pyast.MISSING)
    if value is True or (type(value) is int and value == 1):
        return True
    return isinstance(value, str) and value.lower() in PUBLIC_WORDS


def _py_predicate(node: ast.AST, model: str | None) -> bool:
    """`Model.published == True`, `Model.published.is_(True)` or a bare `Model.is_public`."""
    column, public = None, False
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        if isinstance(node.ops[0], ast.Eq | ast.Is):
            column, public = node.left, _py_public_literal(node.comparators[0])
    elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "is_" and node.args:
            column, public = node.func.value, _py_public_literal(node.args[0])
    elif isinstance(node, ast.Attribute):
        column, public = node, True
    if not isinstance(column, ast.Attribute) or not VISIBILITY_NAME.match(column.attr):
        return False
    return public and (model is None or pyast.dotted(column.value) == model)


def _and_parts(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, ast.Call) and (pyast.dotted(node.func) or "").endswith("and_"):
        return list(node.args)
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
        return list(node.values)
    return [node]


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
            name_ok = keyword.arg and VISIBILITY_NAME.match(keyword.arg)
            if name_ok and _py_public_literal(keyword.value):
                return True
    return False


def py_written_after(fn: ast.AST, target: str | None, line: int) -> bool:
    """The handler assigns to an attribute of the loaded record, or calls a write that involves
    it (`record.save()`, `db.delete(record)`, `setattr(record, ...)`), after `line`."""
    if not target:
        return False
    for node in ast.walk(fn):
        if getattr(node, "lineno", 0) <= line:
            continue
        if isinstance(node, ast.Assign | ast.AugAssign | ast.AnnAssign):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for item in targets:
                if isinstance(item, ast.Attribute | ast.Subscript):
                    if pyast.name_root(item) == target:
                        return True
        if isinstance(node, ast.Call):
            name = (pyast.dotted(node.func) or "").split(".")[-1]
            if name in LATER_WRITES and target in pyast.names_in(node):
                return True
    return False


def _js_public_literal(node) -> bool:
    node = jsts.unwrap(node)
    if node is None:
        return False
    if node.type == "true":
        return True
    if node.type == "number":
        return jsts.node_text(node) == "1"
    if node.type == "string":
        return (jsts.string_value(node) or "").lower() in PUBLIC_WORDS
    if node.type == "object":
        return _js_public_literal(jsts.object_pairs(node).get("equals"))
    return False


def js_visible(call) -> bool:
    """Prisma `findFirst({ where: { published: true } })` or `findOne({ published: true })`."""
    method = jsts.callee(call).split(".")[-1]
    args = jsts.arguments(call)
    if method not in JS_READS or not args:
        return False
    pairs = jsts.object_pairs(args[0])
    where = jsts.object_pairs(pairs["where"]) if "where" in pairs else pairs
    return any(VISIBILITY_NAME.match(k) and _js_public_literal(v) for k, v in where.items())


def js_written_after(handler, call, target: str | None) -> bool:
    """The handler assigns to the loaded record or passes it to a write after the lookup call."""
    if not target or handler is None:
        return False
    word = re.compile(rf"(?<![\w.$]){re.escape(target)}\b")
    for node in jsts.walk(handler, {"assignment_expression", "augmented_assignment_expression"}):
        left = node.child_by_field_name("left")
        if node.start_byte > call.end_byte and left is not None:
            if left.type != "identifier" and jsts.member_root(left) == target:
                return True
    for node in jsts.walk(handler, {"call_expression"}):
        if node.start_byte <= call.end_byte:
            continue
        name = jsts.callee(node).split(".")[-1]
        if name in LATER_WRITES and word.search(jsts.node_text(node)):
            return True
    return False
