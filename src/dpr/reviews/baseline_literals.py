"""Review 4, baseline: one finding per committed password, merged across every file that uses it."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import PurePosixPath

from dpr.model import Finding, Location, Tag
from dpr.parsing import pyast, pyvalues
from dpr.reviews.baseline_accounts import (
    START_FILES,
    _copies,
    _digest,
    _masked,
    literal_password_sites,
)
from dpr.reviews.deploy_env import deploy_files
from dpr.rules import Context, make_finding, rule

DEV_SCRIPT = re.compile(r"(?i)seed|demo|sample|fixture|fake|dummy|example|mock")
Site = tuple[str, int, pyvalues.Literal]


def _groups(sites: dict[str, list[tuple[int, pyvalues.Literal]]]) -> list[list[Site]]:
    """Hashing sites joined by the digest of their own literal, in first-seen order.

    A file that hashes several distinct literals contributes a site to each literal's own
    group; only sites that hash the same text are ever merged."""
    groups: dict[str, list[Site]] = {}
    for rel, items in sorted(sites.items()):
        for line, lit in items:
            groups.setdefault(_digest(lit.value), []).append((rel, line, lit))
    return list(groups.values())


def _referenced(ctx: Context, rel: str) -> bool:
    """A start command, deploy config or CI file names the file or its module."""
    path = PurePosixPath(rel)
    parts = path.with_suffix("").parts
    names = {path.name, *(".".join(parts[i:]) for i in range(len(parts) - 1))}
    commands = [f.rel for f in ctx.index.named(*START_FILES)] + deploy_files(ctx)
    for other in dict.fromkeys(commands):
        text = ctx.index.text(other)
        if any(re.search(rf"(?<![\w.]){re.escape(n)}\b", text) for n in names):
            return True
    return False


def _dev_only(ctx: Context, rel: str) -> bool:
    return bool(DEV_SCRIPT.search(PurePosixPath(rel).stem)) and not _referenced(ctx, rel)


def _module_level(ctx: Context, rel: str, lines: list[int]) -> bool:
    if not rel.endswith(".py"):
        return False
    tree = pyast.parse_file(ctx.index, rel)
    return tree is not None and any(pyast.function_at(tree, line) is None for line in lines)


def _finding(ctx: Context, rows: list[Site]) -> Finding:
    direct = [(rel, line) for rel, line, lit in rows if not lit.env_fallback]
    live = [(rel, line) for rel, line in direct if not _dev_only(ctx, rel)]
    files = list(dict.fromkeys(rel for rel, _, _ in rows))
    first = live[0][0] if live else (direct[0][0] if direct else files[0])
    hashing = sorted({(rel, line) for rel, line, _ in rows}, key=lambda s: (s[0] != first, s))
    copies = [
        loc
        for rel in files
        for loc in _copies(ctx, rel, [lit for r, _, lit in rows if r == rel])
        if loc.file not in files
    ]
    extra = ""
    if _module_level(ctx, first, [line for rel, line in hashing if rel == first]):
        extra += " The hash is computed once at module level and reused for every account."
    if len(files) > 1:
        extra += f" The same text is hashed in {len(files)} files."
    fallbacks = sorted({rel for rel, _, lit in rows if lit.env_fallback})
    if fallbacks and direct:
        extra += (
            f" In {', '.join(fallbacks)} it is the fallback when an environment variable is unset."
        )
    unique_copies = list(dict.fromkeys(copies))
    if unique_copies:
        extra += f" The same text also appears in {len(unique_copies)} other place(s)."
    if direct and not live:
        severity = "low"
        extra += " Only scripts that no start command, deploy config or CI job runs hash it."
    else:
        severity = "critical" if direct else "high"
    literals = [lit for _, _, lit in rows]
    locations = [Location(rel, line) for rel, line in hashing] + unique_copies
    return make_finding(
        "BASE-LITERAL-PASSWORD-HASH",
        tag=Tag.CONFIRMED if direct else Tag.INFERRED,
        locations=locations[:10],
        severity=severity,
        snippet=_masked(ctx.index.text(first), hashing[0][1], literals),
        proof_needed=None
        if direct
        else "Check that the environment variable is set in every deployed environment.",
        file=first,
        count=sum(rel == first for rel, _ in hashing),
        extra=extra,
    )


@rule(
    "BASE-LITERAL-PASSWORD-HASH",
    review="baseline",
    severity="critical",
    exploitability="high",
    owasp="A07",
)
def literal_password_hash(ctx: Context) -> Iterator[Finding]:
    for rows in _groups(literal_password_sites(ctx)):
        yield _finding(ctx, rows)
