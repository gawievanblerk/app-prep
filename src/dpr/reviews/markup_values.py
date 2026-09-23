"""Python values that are safe inside HTML markup: constants, escaped values, numeric formats.

Shared by `OWASP-A03-XSS-SINK` (Markup and mark_safe) and `OWASP-A03-HTML-EMAIL`.
"""

from __future__ import annotations

import ast
import re

from dpr.parsing import pyast

ESCAPES = re.compile(r"(?:^|\.)(?:escape|quote|bleach\.clean|clean)$")
TRUSTED = re.compile(r"(?i)settings|config")


def safe_value(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) or (isinstance(node, ast.Name) and node.id.isupper()):
        return True
    if isinstance(node, ast.Call) and ESCAPES.search(pyast.dotted(node.func) or ""):
        return True
    return isinstance(node, ast.Attribute) and bool(TRUSTED.search(ast.unparse(node)))


def markup_safe(node: ast.AST, escaped: set[str]) -> bool:
    """Constants, escaped values, and strings built only from them, including joined loops."""
    if safe_value(node) or (isinstance(node, ast.Name) and node.id in escaped):
        return True
    if isinstance(node, ast.JoinedStr):
        values = [v for v in node.values if isinstance(v, ast.FormattedValue)]
        return all(_numeric_format(v) or markup_safe(v.value, escaped) for v in values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return markup_safe(node.left, escaped) and markup_safe(node.right, escaped)
    if isinstance(node, ast.List | ast.Tuple):
        return all(markup_safe(e, escaped) for e in node.elts)
    if isinstance(node, ast.ListComp | ast.GeneratorExp):
        names = set(escaped)
        for gen in node.generators:
            if markup_safe(gen.iter, names):
                names |= set(pyast.names_in(gen.target))
        return markup_safe(node.elt, names)
    if isinstance(node, ast.Call) and (pyast.dotted(node.func) or "").endswith("Markup"):
        return all(markup_safe(a, escaped) for a in node.args)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "join" and len(node.args) == 1:
            return markup_safe(node.args[0], escaped)
    return False


# A format spec that only accepts numbers, such as ,.0f or 05d: the field renders as digits.
NUMERIC_SPEC = re.compile(r"(?:.?[<>=^])?[+\- ]?z?#?0?\d*[,_]?(?:\.\d+)?[bcdeEfFgGnoxX%]")


def _numeric_format(value: ast.FormattedValue) -> bool:
    spec = value.format_spec
    if not isinstance(spec, ast.JoinedStr) or value.conversion != -1:
        return False
    if not all(isinstance(v, ast.Constant) for v in spec.values):
        return False
    return bool(NUMERIC_SPEC.fullmatch("".join(str(v.value) for v in spec.values)))


def markup_names(fn: ast.AST) -> set[str]:
    """Local names whose every assignment is escaped or constant markup."""
    values: dict[str, list[ast.AST]] = {}
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            if isinstance(node.targets[0], ast.Name):
                values.setdefault(node.targets[0].id, []).append(node.value)
    names: set[str] = set()
    for _ in range(2):
        names |= {n for n, vs in values.items() if all(markup_safe(v, names) for v in vs)}
    return names
