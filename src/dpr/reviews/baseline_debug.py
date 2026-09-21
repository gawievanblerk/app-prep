"""Review 4, baseline: debug mode that reaches a debug page, and API docs gated on the flag."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.discovery.approots import root_of
from dpr.model import Finding, Location, Tag
from dpr.parsing import pyast
from dpr.redact import snippet
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
    home = root_of(ctx.detection.app_roots, rel)
    prefix = f"{home.path}/" if home is not None and home.path else ""
    return [f.rel for f in ctx.index.py_files if f.rel.startswith(prefix) and not is_test(f.rel)]


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


@rule("BASE-DEBUG-ON", review="baseline", severity="high", exploitability="medium", owasp="A05")
def debug_on(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if "debug" not in text.lower() or is_test(entry.rel):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        if tree is None:
            continue
        if "INSTALLED_APPS" in text:
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
