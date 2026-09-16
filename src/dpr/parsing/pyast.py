"""Python ast parsing and small helpers."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.walk import RepoIndex

MISSING = object()
FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


def parse_file(index: RepoIndex, rel: str) -> ast.Module | None:
    key = ("py", rel)
    if key not in index.cache:
        try:
            index.cache[key] = ast.parse(index.text(rel), filename=rel)
        except (SyntaxError, ValueError):
            index.cache[key] = None
            index.skipped.append(f"{rel}: Python syntax could not be parsed")
    return index.cache[key]


def dotted(node: ast.AST | None) -> str | None:
    parts: list[str] = []
    while True:
        if isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        elif isinstance(node, ast.Name):
            parts.append(node.id)
            break
        elif isinstance(node, ast.Call):
            inner = dotted(node.func)
            if inner is None:
                return None
            parts.append(inner + "()")
            break
        else:
            return None
    return ".".join(reversed(parts))


def calls(tree: ast.AST, pattern: str | re.Pattern[str],
          within: ast.AST | None = None) -> Iterator[ast.Call]:
    regex = re.compile(pattern) if isinstance(pattern, str) else pattern
    found = []
    for node in ast.walk(within or tree):
        if isinstance(node, ast.Call):
            name = dotted(node.func)
            if name is not None and regex.fullmatch(name):
                found.append(node)
    found.sort(key=lambda n: (n.lineno, n.col_offset))
    yield from found


def kwarg(call: ast.Call, name: str) -> ast.expr | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def constant(node: ast.AST | None, default: object = MISSING) -> object:
    return node.value if isinstance(node, ast.Constant) else default


def functions(tree: ast.AST) -> list[FunctionNode]:
    found = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)]
    return sorted(found, key=lambda n: (n.lineno, n.col_offset))


def function_at(tree: ast.AST, lineno: int) -> FunctionNode | None:
    best = None
    for fn in functions(tree):
        end = fn.end_lineno or fn.lineno
        if fn.lineno <= lineno <= end and (best is None or fn.lineno >= best.lineno):
            best = fn
    return best


def class_defs(tree: ast.AST) -> list[ast.ClassDef]:
    found = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
    return sorted(found, key=lambda n: n.lineno)


def base_names(cls: ast.ClassDef) -> list[str]:
    return [dotted(base) or "" for base in cls.bases]


def assignments(body: list[ast.stmt]) -> dict[str, ast.expr]:
    found: dict[str, ast.expr] = {}
    for stmt in body:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    found[target.id] = stmt.value
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            if stmt.value is not None:
                found[stmt.target.id] = stmt.value
    return found


def name_root(node: ast.AST | None) -> str | None:
    while isinstance(node, ast.Attribute | ast.Subscript | ast.Call):
        node = node.func if isinstance(node, ast.Call) else node.value
    return node.id if isinstance(node, ast.Name) else None


def names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
