"""Review 4, baseline: settings that fail open. Pickle sessions, an environment flag that means
production when unset, and feature switches that default to on."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Tag
from dpr.parsing import pyast
from dpr.parsing.pyenv import MISSING, means_true, module_assignments, reads_env, when_unset
from dpr.redact import snippet
from dpr.reviews.leaks_settings import signing_key_fallbacks
from dpr.reviews.settings_files import production_file, settings_module
from dpr.rules import Context, make_finding, rule

PROD_FLAG = re.compile(r"(?:IS_|IN_|RUN_AS_)?(?:PROD|PRODUCTION|LIVE)(?:_MODE|_ENV|_ENVIRONMENT)?")
ENV_NAME = re.compile(
    r"(?:APP_|DJANGO_|FLASK_|DEPLOY_|DEPLOYMENT_|RUNTIME_)?(?:ENV|ENVIRONMENT|STAGE)"
)
PROD_WORDS = frozenset({"prod", "production", "live", "prd"})
SWITCH_DEFAULTS = ("WAFFLE_SWITCH_DEFAULT", "WAFFLE_FLAG_DEFAULT", "WAFFLE_SAMPLE_DEFAULT")


def _settings_trees(ctx: Context, needle: str) -> Iterator[tuple[str, ast.Module]]:
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if needle not in text or not settings_module(entry.rel, text):
            continue
        if not production_file(ctx, entry.rel):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        if tree is not None:
            yield entry.rel, tree


@rule(
    "BASE-PICKLE-SESSIONS", review="baseline", severity="high", exploitability="medium", owasp="A08"
)
def pickle_sessions(ctx: Context) -> Iterator[Finding]:
    for rel, tree in _settings_trees(ctx, "PickleSerializer"):
        for name, value, line in module_assignments(tree):
            serializer = pyast.constant(value)
            if name != "SESSION_SERIALIZER" or not isinstance(serializer, str):
                continue
            if not serializer.endswith("PickleSerializer"):
                continue
            keys = signing_key_fallbacks(ctx)
            key = (
                f" The signing key falls back to a value committed at {keys[0]}, so anyone with "
                "the repository can sign a session that runs code on the server."
                if keys
                else ""
            )
            yield make_finding(
                "BASE-PICKLE-SESSIONS",
                tag=Tag.CONFIRMED,
                locations=[Location(rel, line), *keys[:1]],
                snippet=snippet(ctx.index.text(rel), line),
                key=key,
            )


def _defaults_to_production(name: str, value: ast.expr) -> str | None:
    """What the flag becomes when the environment sets nothing, if that means production."""
    if not reads_env(value):
        return None
    unset = when_unset(value)
    if unset is MISSING:
        return None
    if PROD_FLAG.fullmatch(name) and means_true(unset):
        return f"{name} is true"
    if ENV_NAME.fullmatch(name) and isinstance(unset, str) and unset.lower() in PROD_WORDS:
        return f"{name} names production"
    return None


@rule(
    "BASE-ENV-DEFAULTS-PROD",
    review="baseline",
    severity="medium",
    exploitability="low",
    owasp="A05",
)
def env_defaults_prod(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if not re.search(r"PROD|LIVE|ENV|STAGE", text) or not production_file(ctx, entry.rel):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for name, value, line in module_assignments(tree) if tree else []:
            what = _defaults_to_production(name.upper(), value)
            if what is not None:
                yield make_finding(
                    "BASE-ENV-DEFAULTS-PROD",
                    tag=Tag.CONFIRMED,
                    locations=[Location(entry.rel, line)],
                    snippet=snippet(text, line),
                    name=name,
                    what=what,
                )


@rule(
    "BASE-FEATURE-DEFAULT-ON", review="baseline", severity="low", exploitability="low", owasp="A05"
)
def feature_default_on(ctx: Context) -> Iterator[Finding]:
    for rel, tree in _settings_trees(ctx, "WAFFLE_"):
        hits = [
            (name, line)
            for name, value, line in module_assignments(tree)
            if name in SWITCH_DEFAULTS and pyast.constant(value) is True
        ]
        if hits:
            yield make_finding(
                "BASE-FEATURE-DEFAULT-ON",
                tag=Tag.CONFIRMED,
                locations=[Location(rel, line) for _, line in hits],
                snippet=snippet(ctx.index.text(rel), hits[0][1]),
                names=", ".join(name for name, _ in hits),
            )
