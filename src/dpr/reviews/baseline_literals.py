"""Review 4, baseline: one finding per committed password, merged across every file that uses it."""

from __future__ import annotations

import ast
import hashlib
import json
import re
from collections.abc import Iterator
from pathlib import PurePosixPath

from dpr.model import Finding, Location, Tag
from dpr.parsing import pyast, pyvalues
from dpr.redact import redact, snippet
from dpr.reviews.baseline_accounts import START_FILES, literal_password_sites
from dpr.reviews.deploy_env import applies, deploy_files
from dpr.rules import Context, make_finding, rule
from dpr.walk import line_of

DEV_SCRIPT = re.compile(r"(?i)seed|demo|sample|fixture|fake|dummy|example|mock")
TOKEN = re.compile(r"[^\s\"'`,;()\[\]{}<>]+")
Site = tuple[str, int, pyvalues.Literal]


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _token_sites(ctx: Context) -> dict[str, list[tuple[int, int, Location]]]:
    """Digest to (file order, offset, location) for every token in the indexed files that has the
    length and digest of a committed literal. Each file is scanned once per run."""
    if "password_token_sites" not in ctx.facts:
        literals = [lit for items in literal_password_sites(ctx).values() for _, lit in items]
        lengths = {len(lit.value) for lit in literals}
        digests = {_digest(lit.value) for lit in literals}
        found: dict[str, list[tuple[int, int, Location]]] = {}
        for order, entry in enumerate(ctx.index.files if literals else []):
            text = ctx.index.text(entry.rel)
            for match in TOKEN.finditer(text):
                token = match.group(0)
                digest = _digest(token) if len(token) in lengths else None
                if digest in digests:
                    location = Location(entry.rel, line_of(text, match.start()))
                    found.setdefault(digest, []).append((order, match.start(), location))
        ctx.facts["password_token_sites"] = found
    return ctx.facts["password_token_sites"]


def _copies(ctx: Context, owner: str, literals: list[pyvalues.Literal]) -> list[Location]:
    """Places outside `owner` where the text of one of `literals` appears as a whole token."""
    sites = _token_sites(ctx)
    digests = {_digest(lit.value) for lit in literals}
    hits = sorted(site for digest in digests for site in sites.get(digest, []))
    return [location for _, _, location in hits if location.file != owner]


def _char_column(source_line: str, byte_column: int) -> int:
    return len(source_line.encode("utf-8")[:byte_column].decode("utf-8", errors="ignore"))


def _literal_spans(text: str, line: int, values: set[str]) -> list[tuple[int, int]]:
    """Character ranges on `line` covered by Python string literals whose value is one of
    `values`, however the literal is spelled (adjacent parts, escapes, triple quotes)."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    lines = text.split("\n")
    spans = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and node.value in values):
            continue
        end_line = node.end_lineno or node.lineno
        if not node.lineno <= line <= end_line or node.end_col_offset is None:
            continue
        source = lines[line - 1]
        start = _char_column(source, node.col_offset) if node.lineno == line else 0
        end = _char_column(source, node.end_col_offset) if end_line == line else len(source)
        spans.append((start, end))
    return spans


def _masked(text: str, line: int, literals: list[pyvalues.Literal]) -> str:
    """The snippet of `line` with every literal masked on the whole line before it is cut.

    Python literals are masked by their source range, so a value spelled differently in the
    source (adjacent parts, escaped quotes, a triple-quoted block) never survives; other files
    fall back to the value's text forms."""
    lines = text.split("\n")
    full = lines[line - 1].removesuffix("\r") if 0 < line <= len(lines) else ""
    values = {lit.value for lit in literals}
    for start, end in sorted(_literal_spans(text, line, values), reverse=True):
        full = full[:start] + "<redacted:password>" + full[end:]
    forms = {f for v in values for f in (v, repr(v)[1:-1], json.dumps(v)[1:-1])}
    forms |= {part for form in forms for part in form.split("\n") if len(part) >= 4}
    for form in sorted(forms, key=len, reverse=True):
        full = full.replace(form, "<redacted:password>")
    value = snippet(full, 1)
    if len(value) < len(redact(full)):
        for form in forms:
            for size in range(len(form) - 1, 0, -1):
                if value.endswith(form[:size]):
                    return value[: len(value) - size] + "<redacted:password>"
    return value


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
    starts = [f.rel for f in ctx.index.named(*START_FILES) if applies(ctx, f.rel, rel)]
    commands = starts + deploy_files(ctx, rel=rel)
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
