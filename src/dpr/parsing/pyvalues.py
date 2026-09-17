"""Resolve simple Python values to string literals: constants, names and env fallbacks."""

from __future__ import annotations

import ast
from dataclasses import dataclass

from dpr.parsing import pyast

ENV_GET = ("os.environ.get", "os.getenv", "environ.get", "getenv")


@dataclass(frozen=True)
class Literal:
    value: str
    env_fallback: bool = False


def _assigned(body: list[ast.stmt], name: str, before: int) -> ast.expr | None:
    found = None
    for stmt in body:
        if stmt.lineno >= before:
            break
        for node in ast.walk(stmt):
            if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == name for t in node.targets
            ):
                found = node.value
            elif (
                isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
                and node.target.id == name
                and node.value is not None
            ):
                found = node.value
    return found


def _loop_items(tree: ast.Module, fn: ast.AST | None, name: str, line: int) -> list[ast.expr]:
    for node in ast.walk(fn or tree):
        if (
            isinstance(node, ast.For)
            and isinstance(node.target, ast.Name)
            and node.target.id == name
            and node.lineno <= line <= (node.end_lineno or node.lineno)
        ):
            source = node.iter
            if isinstance(source, ast.Name):
                source = pyast.assignments(tree.body).get(source.id)
            if isinstance(source, ast.List | ast.Tuple):
                return list(source.elts)
    return []


def resolve(tree: ast.Module, node: ast.AST | None, line: int, depth: int = 0) -> Literal | None:
    if node is None or depth > 4:
        return None
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "encode":
            return resolve(tree, node.func.value, line, depth + 1)
    if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value:
        return Literal(node.value)
    if isinstance(node, ast.Call) and pyast.dotted(node.func) in ENV_GET and len(node.args) > 1:
        inner = resolve(tree, node.args[1], line, depth + 1)
        return Literal(inner.value, True) if inner else None
    fn = pyast.function_at(tree, line)
    if isinstance(node, ast.Name):
        value = _assigned(fn.body, node.id, line) if fn is not None else None
        if value is None:
            value = pyast.assignments(tree.body).get(node.id)
        return resolve(tree, value, line, depth + 1)
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
        key = pyast.constant(node.slice, None)
        for item in _loop_items(tree, fn, node.value.id, line):
            if isinstance(item, ast.Dict) and isinstance(key, str):
                for k, v in zip(item.keys, item.values, strict=True):
                    if pyast.constant(k, None) == key:
                        found = resolve(tree, v, line, depth + 1)
                        if found:
                            return found
    return None
