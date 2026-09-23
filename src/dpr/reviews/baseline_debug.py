"""Review 4, baseline: debug mode that reaches a debug page, and API docs gated on the flag."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.discovery.approots import same_root
from dpr.model import Finding, Location, Tag
from dpr.parsing import pyast
from dpr.redact import snippet
from dpr.reviews.access_frameworks import non_production_settings
from dpr.reviews.deploy_env import all_false
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule

APP_CALL = r"(?:\w+\.)?(?:FastAPI|Flask|Starlette|run)"
DOCS_KEYWORDS = ("docs_url", "redoc_url", "openapi_url")
SINK_TEXT = re.compile(r"\bdebug\b", re.IGNORECASE)


def _debug(ctx: Context, rel: str, line: int, what: str, severity: str | None = None) -> Finding:
    return make_finding(
        "BASE-DEBUG-ON",
        tag=Tag.INFERRED,
        locations=[Location(rel, line)],
        severity=severity,
        snippet=snippet(ctx.index.text(rel), line),
        what=what,
    )


def _same_root_files(ctx: Context, rel: str) -> list[str]:
    return [
        f.rel
        for f in ctx.index.py_files
        if same_root(ctx.detection.app_roots, f.rel, rel) and not is_test(f.rel)
    ]


def _uses(ctx: Context, rel: str) -> tuple[list[int], list[int]]:
    """Lines where the settings flag reaches a debug sink, and lines where it only gates docs."""
    sinks, docs = [], []
    for other in _same_root_files(ctx, rel):
        text = ctx.index.text(other)
        if "debug" not in text:
            continue
        tree = pyast.parse_file(ctx.index, other)
        for call in pyast.calls(tree, APP_CALL) if tree else []:
            value = pyast.kwarg(call, "debug")
            if value is not None and not isinstance(value, ast.Constant):
                sinks.append(call.lineno)
            for keyword in DOCS_KEYWORDS:
                gate = pyast.kwarg(call, keyword)
                if gate is not None and SINK_TEXT.search(ast.unparse(gate)):
                    docs.append(call.lineno)
        for node in ast.walk(tree) if tree else []:
            if isinstance(node, ast.Assign) and any(
                ast.unparse(t).endswith((".debug", "['DEBUG']", '["DEBUG"]')) for t in node.targets
            ):
                if not isinstance(node.value, ast.Constant):
                    sinks.append(node.lineno)
    return sinks, docs


def _production_guard(cls: ast.ClassDef) -> bool:
    """A validator in the settings class that raises when debug is on."""
    for node in ast.walk(cls):
        if isinstance(node, ast.If) and SINK_TEXT.search(ast.unparse(node.test)):
            if any(isinstance(sub, ast.Raise) for stmt in node.body for sub in ast.walk(stmt)):
                return True
    return False


def _settings_debug(ctx: Context, rel: str, tree: ast.Module) -> Iterator[Finding]:
    for cls in pyast.class_defs(tree):
        if not any(b.endswith("Settings") for b in pyast.base_names(cls)):
            continue
        for stmt in cls.body:
            if not (
                isinstance(stmt, ast.AnnAssign)
                and isinstance(stmt.target, ast.Name)
                and stmt.target.id.lower() == "debug"
                and pyast.constant(stmt.value) is True
            ):
                continue
            if _production_guard(cls) or all_false(ctx, "DEBUG", rel):
                continue
            sinks, docs = _uses(ctx, rel)
            if sinks:
                what = (
                    "The settings class turns debug on unless the environment sets it, and the "
                    "flag is passed to the app, so errors can render a debug page."
                )
                yield _debug(ctx, rel, stmt.lineno, what)
            elif docs:
                what = (
                    "The settings class turns debug on unless the environment sets it. The flag "
                    "only decides whether the interactive API docs are served, so an unset "
                    "variable publishes the docs, not a debug page."
                )
                yield _debug(ctx, rel, stmt.lineno, what, severity="low")


def _switched_off(node: ast.AST | None) -> bool:
    """A docs keyword that is None outright or only in some configurations."""
    if node is None:
        return False
    return isinstance(node, ast.IfExp) or (isinstance(node, ast.Constant) and node.value is None)


def _always_served(node: ast.AST | None) -> bool:
    """openapi_url left at its default, or a fixed string with no condition."""
    if node is None:
        return True
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)
    return isinstance(node, ast.JoinedStr | ast.BinOp) and not any(
        isinstance(sub, ast.IfExp) for sub in ast.walk(node)
    )


@rule(
    "BASE-OPENAPI-ALWAYS-ON", review="baseline", severity="low", exploitability="low", owasp="A05"
)
def openapi_always_on(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if "FastAPI(" not in text or is_test(entry.rel):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for call in pyast.calls(tree, r"(?:\w+\.)?FastAPI") if tree else []:
            docs = [pyast.kwarg(call, k) for k in ("docs_url", "redoc_url")]
            schema = pyast.kwarg(call, "openapi_url")
            if not any(_switched_off(d) for d in docs) or not _always_served(schema):
                continue
            line = schema.lineno if schema is not None else call.lineno
            yield make_finding(
                "BASE-OPENAPI-ALWAYS-ON",
                tag=Tag.CONFIRMED,
                locations=[Location(entry.rel, line)],
                snippet=snippet(text, line),
                where="openapi_url is a fixed path"
                if schema is not None
                else "openapi_url is left at its default",
            )


@rule("BASE-DEBUG-ON", review="baseline", severity="high", exploitability="medium", owasp="A05")
def debug_on(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if "debug" not in text.lower() or is_test(entry.rel):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        if tree is None:
            continue
        if "INSTALLED_APPS" in text and not non_production_settings(ctx, entry.rel):
            for stmt in tree.body:
                if (
                    isinstance(stmt, ast.Assign)
                    and isinstance(stmt.targets[0], ast.Name)
                    and stmt.targets[0].id == "DEBUG"
                    and pyast.constant(stmt.value) is True
                ):
                    what = "Django settings set DEBUG = True."
                    yield _debug(ctx, entry.rel, stmt.lineno, what)
        for call in pyast.calls(tree, APP_CALL):
            if pyast.constant(pyast.kwarg(call, "debug")) is True:
                what = "The app is created or run with debug=True."
                yield _debug(ctx, entry.rel, call.lineno, what)
        yield from _settings_debug(ctx, entry.rel, tree)
