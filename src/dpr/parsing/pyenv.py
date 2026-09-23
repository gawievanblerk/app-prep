"""Python settings read from the environment: the reads, their defaults, and what a setting is
when the variable is unset. Nothing here returns a value to a report; callers compare it."""

from __future__ import annotations

import ast
import operator
import re
from dataclasses import dataclass

from dpr.parsing import pyast

MISSING = pyast.MISSING
# Every reader takes the default as the second argument or as default=.
ENV_READ = re.compile(r"(?:os\.)?(?:environ\.(?:get|setdefault)|getenv)")
# django-environ (env("X", default=...), env.bool(...)) and python-decouple (config("X", ...)).
ENV_HELPER = re.compile(r"(?:decouple\.)?config|env(?:\.(?:str|bool|int|get_value))?")
TRUE_WORDS = frozenset({"true", "1", "yes", "on", "y", "t"})
COMPARE = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
    ast.Is: operator.is_,
    ast.IsNot: operator.is_not,
}
STRING_METHODS = {"lower", "upper", "strip", "casefold"}


@dataclass(frozen=True)
class EnvRead:
    name: str
    default: ast.expr | None
    call: ast.Call


def env_read(node: ast.AST | None) -> EnvRead | None:
    """An environment read with a literal variable name, and its default expression if any."""
    if not isinstance(node, ast.Call) or not node.args:
        return None
    name = pyast.constant(node.args[0])
    if not isinstance(name, str):
        return None
    func = pyast.dotted(node.func) or ""
    if not ENV_READ.fullmatch(func) and not ENV_HELPER.fullmatch(func):
        return None
    default = node.args[1] if len(node.args) > 1 else pyast.kwarg(node, "default")
    return EnvRead(name, default, node)


def reads_env(node: ast.AST) -> bool:
    return any(env_read(sub) is not None for sub in ast.walk(node))


def _compare(node: ast.Compare) -> object:
    left = when_unset(node.left)
    for op, right_node in zip(node.ops, node.comparators, strict=True):
        right = when_unset(right_node)
        if left is MISSING or right is MISSING or type(op) not in COMPARE:
            return MISSING
        try:
            if not COMPARE[type(op)](left, right):
                return False
        except TypeError:
            return MISSING
        left = right
    return True


def _call(node: ast.Call) -> object:
    read = env_read(node)
    if read is not None:
        return None if read.default is None else when_unset(read.default)
    if isinstance(node.func, ast.Attribute) and node.func.attr in STRING_METHODS and not node.args:
        value = when_unset(node.func.value)
        return getattr(value, node.func.attr)() if isinstance(value, str) else MISSING
    if isinstance(node.func, ast.Name) and node.func.id in ("bool", "str") and len(node.args) == 1:
        value = when_unset(node.args[0])
        return MISSING if value is MISSING else {"bool": bool, "str": str}[node.func.id](value)
    return MISSING


def when_unset(node: ast.AST | None) -> object:
    """The value an expression has when every environment variable it reads is unset, or
    MISSING when it depends on anything else (a name, an unknown call)."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        items = [when_unset(e) for e in node.elts]
        return MISSING if any(i is MISSING for i in items) else items
    if isinstance(node, ast.Call):
        return _call(node)
    if isinstance(node, ast.Compare):
        return _compare(node)
    if isinstance(node, ast.IfExp):
        test = when_unset(node.test)
        if test is MISSING:
            return MISSING
        return when_unset(node.body if test else node.orelse)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        value = when_unset(node.operand)
        return MISSING if value is MISSING else not value
    if isinstance(node, ast.BoolOp):
        value: object = MISSING
        for item in node.values:
            value = when_unset(item)
            if value is MISSING:
                return MISSING
            if isinstance(node.op, ast.Or) == bool(value):
                return value
        return value
    return MISSING


def means_true(value: object) -> bool:
    """True, a non-zero number, or a string that reads as true ("True", "1", "yes", "on")."""
    if isinstance(value, bool | int):
        return bool(value)
    return isinstance(value, str) and value.strip().lower() in TRUE_WORDS


def module_assignments(tree: ast.Module) -> list[tuple[str, ast.expr, int]]:
    """Top-level `NAME = value` assignments, also inside top-level if/try blocks."""
    found: list[tuple[str, ast.expr, int]] = []
    pending: list[ast.stmt] = list(tree.body)
    while pending:
        stmt = pending.pop(0)
        if isinstance(stmt, ast.Assign):
            found += [
                (t.id, stmt.value, stmt.lineno) for t in stmt.targets if isinstance(t, ast.Name)
            ]
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value:
            found.append((stmt.target.id, stmt.value, stmt.lineno))
        elif isinstance(stmt, ast.If | ast.Try):
            pending += [*stmt.body, *stmt.orelse, *getattr(stmt, "finalbody", [])]
    return sorted(found, key=lambda item: item[2])
