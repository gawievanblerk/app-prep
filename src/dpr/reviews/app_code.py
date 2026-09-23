"""The application's own Python code: not tests, vendored copies or migrations."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.parsing import pyast
from dpr.reviews.paths import is_test
from dpr.rules import Context
from dpr.vendored import is_vendored

MIGRATIONS = re.compile(r"(?:^|/)(?:alembic|migrations)/")


def app_file(ctx: Context, rel: str) -> bool:
    return not (is_test(rel) or is_vendored(ctx.index, rel) or MIGRATIONS.search(rel))


def app_py_files(ctx: Context, *needles: str) -> Iterator[tuple[str, str, ast.Module]]:
    """(path, text, tree) of each parsable application Python file holding any of the needles."""
    for entry in ctx.index.py_files:
        if not app_file(ctx, entry.rel):
            continue
        text = ctx.index.text(entry.rel)
        if needles and not any(n in text for n in needles):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        if tree is not None:
            yield entry.rel, text, tree


def own_nodes(fn: ast.AST) -> Iterator[ast.AST]:
    """Nodes of a function body, not descending into nested functions or classes."""
    stack = list(getattr(fn, "body", []))
    while stack:
        node = stack.pop()
        yield node
        stack.extend(
            child
            for child in ast.iter_child_nodes(node)
            if not isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
        )


def own_calls(fn: ast.AST, pattern: re.Pattern[str] | None = None) -> list[ast.Call]:
    """Calls made by the function itself, in line order, optionally by dotted name."""
    found = [
        n
        for n in own_nodes(fn)
        if isinstance(n, ast.Call)
        and (pattern is None or pattern.fullmatch(pyast.dotted(n.func) or ""))
    ]
    return sorted(found, key=lambda n: (n.lineno, n.col_offset))


def local_values(fn: ast.AST) -> dict[str, list[tuple[int, ast.expr]]]:
    """Every value assigned to each plain local name in a function, with its line."""
    found: dict[str, list[tuple[int, ast.expr]]] = {}
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    found.setdefault(target.id, []).append((node.lineno, node.value))
        elif isinstance(node, ast.AnnAssign | ast.AugAssign) and node.value is not None:
            if isinstance(node.target, ast.Name):
                found.setdefault(node.target.id, []).append((node.lineno, node.value))
    return found


def decorator_names(node: ast.AST) -> list[str]:
    """Dotted names of a function's or class's decorators, and of `method_decorator(x)`
    arguments."""
    names = []
    for dec in getattr(node, "decorator_list", []):
        target = dec.func if isinstance(dec, ast.Call) else dec
        name = pyast.dotted(target) or ""
        names.append(name)
        if isinstance(dec, ast.Call) and name.endswith("method_decorator"):
            names += [pyast.dotted(a) or "" for a in dec.args]
            for arg in dec.args:
                if isinstance(arg, ast.List | ast.Tuple):
                    names += [pyast.dotted(e) or "" for e in arg.elts]
    return names
