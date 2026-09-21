"""Review 7, abuse: request lists that fan out into many renders, sends or imports."""

from __future__ import annotations

import ast
import os
import re
from collections.abc import Iterator

from dpr.discovery.approots import root_of
from dpr.model import Finding, Location, Route, Tag
from dpr.parsing import pyast
from dpr.redact import snippet
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule

BULK_LIMIT = 25
LIST_TYPE = re.compile(r"^(?:typing\.)?(?:list|List|Sequence|set|Set|conlist)\b")
HEAVY_CALL = re.compile(
    r"^(?:generate|render|send|deliver|e?mail|notify|import|convert|export|upload|process)"
    r"|pdf|xlsx|docx"
)
CAP_KEYWORDS = ("max_length", "max_items")


def _cap(stmt: ast.AnnAssign) -> tuple[bool, int | None]:
    """(is a list field, its cap or None) for one annotated schema field."""
    annotation = ast.unparse(stmt.annotation)
    inner = annotation
    if annotation.startswith(("Annotated[", "typing.Annotated[")):
        inner = annotation.split("[", 1)[1]
    if not LIST_TYPE.match(inner):
        return False, None
    for node in ast.walk(stmt):
        if isinstance(node, ast.Call):
            for key in CAP_KEYWORDS:
                value = pyast.constant(pyast.kwarg(node, key), None)
                if isinstance(value, int):
                    return True, value
    return True, None


Fields = dict[str, tuple[int | None, Location]]


def list_fields(ctx: Context) -> dict[str, list[Fields]]:
    """Schema class name to each definition's list fields, with size cap and location."""
    key = ("bulk-list-fields", "")
    if key in ctx.index.cache:
        return ctx.index.cache[key]
    found: dict[str, list[Fields]] = {}
    for entry in ctx.index.py_files:
        if is_test(entry.rel) or "BaseModel" not in ctx.index.text(entry.rel):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for cls in pyast.class_defs(tree) if tree else []:
            fields: Fields = {}
            for stmt in cls.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    is_list, cap = _cap(stmt)
                    if is_list:
                        fields[stmt.target.id] = (cap, Location(entry.rel, stmt.lineno))
            if fields:
                found.setdefault(cls.name, []).append(fields)
    ctx.index.cache[key] = found
    return found


def nearest(ctx: Context, definitions: list[Fields], rel: str) -> Fields:
    """The definition in the same app root as the route file, closest by folder path.

    Evidence never crosses app roots: a schema defined in another app root is never paired
    with this route, even if its folder path happens to share a long string prefix.
    """
    home = root_of(ctx.detection.app_roots, rel)
    same_root = [
        fields
        for fields in definitions
        if root_of(ctx.detection.app_roots, next(iter(fields.values()))[1].file) == home
    ]
    if not same_root:
        return {}

    def shared(fields: Fields) -> int:
        other = next(iter(fields.values()))[1].file
        return len(os.path.commonpath([rel, other])) if "/" in rel and "/" in other else 0

    return max(same_root, key=shared)


def _module_ints(tree: ast.Module) -> dict[str, int]:
    return {
        name: value.value
        for name, value in pyast.assignments(tree.body).items()
        if isinstance(value, ast.Constant) and isinstance(value.value, int)
    }


def _slice_cap(value: ast.AST, ints: dict[str, int]) -> int | None:
    if isinstance(value, ast.Subscript) and isinstance(value.slice, ast.Slice):
        upper = value.slice.upper
        if isinstance(upper, ast.Constant) and isinstance(upper.value, int):
            return upper.value
        if isinstance(upper, ast.Name):
            return ints.get(upper.id)
    return None


def _heavy_calls(body: list[ast.stmt]) -> list[str]:
    names = []
    for stmt in body:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Call):
                name = pyast.dotted(node.func) or ""
                final = name.split(".")[-1]
                if final[:1].islower() and HEAVY_CALL.search(final.lower()):
                    names.append(name)
    return names


def fan_out(route: Route, param: str, field: str) -> tuple[int, list[str]] | None:
    """The loop line and heavy calls when the list, or a copy of it, drives a loop."""
    fn = route.handler
    ints = _module_ints(route.tree)
    tainted = {f"{param}.{field}"}
    for node in sorted(ast.walk(fn), key=lambda n: getattr(n, "lineno", 0)):
        text = ast.unparse(node.value) if isinstance(node, ast.Assign) else ""
        if text and any(re.search(rf"(?<![\w.]){re.escape(t)}\b", text) for t in tainted):
            cap = _slice_cap(node.value, ints)
            targets = {ast.unparse(t) for t in node.targets}
            tainted = (
                tainted - targets if cap is not None and cap <= BULK_LIMIT else tainted | targets
            )
        elif isinstance(node, ast.For | ast.AsyncFor) and ast.unparse(node.iter) in tainted:
            calls = _heavy_calls(node.body)
            if calls:
                return node.lineno, calls
    return None


@rule("ABUSE-BULK-UNBOUNDED", review="abuse", severity="low", exploitability="medium", owasp="A04")
def bulk_unbounded(ctx: Context) -> Iterator[Finding]:
    schemas = list_fields(ctx)
    for route in ctx.detection.routes:
        fn = route.handler
        if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef) or is_test(route.file):
            continue
        for arg in [*fn.args.args, *fn.args.kwonlyargs]:
            name = pyast.dotted(arg.annotation) if arg.annotation is not None else None
            defs = schemas.get(name or "", [])
            for field, (cap, where) in nearest(ctx, defs, route.file).items():
                if cap is not None and cap <= BULK_LIMIT:
                    continue
                loop = fan_out(route, arg.arg, field)
                if loop is None:
                    continue
                line, calls = loop
                yield make_finding(
                    "ABUSE-BULK-UNBOUNDED",
                    tag=Tag.CONFIRMED,
                    locations=[where, Location(route.file, line)],
                    snippet=snippet(ctx.index.text(where.file), where.line),
                    method=route.method,
                    path=route.path,
                    field=f"{name}.{field}",
                    cap=f"up to {cap} items" if cap is not None else "with no size cap",
                    calls=", ".join(dict.fromkeys(calls[:4])),
                    limit=BULK_LIMIT,
                )
