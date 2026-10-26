"""Review 6, leak hunt: personal values written into code, such as ID number lists in migrations
and staff mobile numbers in settings. Counts only; no value is kept or reported."""

from __future__ import annotations

from collections.abc import Iterator

from dpr.model import Finding, Location, Tag
from dpr.pii_values import code_counts
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule
from dpr.vendored import is_vendored

CODE_SUFFIXES = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")


@rule("LEAK-PII-LITERAL-IN-CODE", review="leaks", severity="high", exploitability="medium")
def pii_literal_in_code(ctx: Context) -> Iterator[Finding]:
    """One finding per code file with three or more distinct South African ID numbers that pass
    the date and checksum checks (CONFIRMED), or five or more quoted mobile numbers (INFERRED,
    medium). Test files are low."""
    for entry in ctx.index.files:
        if not entry.rel.endswith(CODE_SUFFIXES) or is_vendored(ctx.index, entry.rel):
            continue
        text = ctx.index.text(entry.rel)
        counts = code_counts(text)
        if not counts:
            continue
        severity = "low" if is_test(entry.rel) else None if counts.ids else "medium"
        yield make_finding(
            "LEAK-PII-LITERAL-IN-CODE",
            tag=Tag.CONFIRMED if counts.confirmed else Tag.INFERRED,
            locations=[Location(entry.rel, counts.first_line, counts.last_line)],
            severity=severity,
            file=entry.rel,
            what=counts.describe(),
        )
