"""Review 5, OWASP A06: third-party libraries copied into the repository, reported once each."""

from __future__ import annotations

from collections.abc import Iterator

from dpr.model import Finding, Location, Tag
from dpr.rules import Context, make_finding, rule
from dpr.vendored import vendored


@rule("OWASP-A06-VENDORED-LIB", review="owasp", severity="low", exploitability="low", owasp="A06")
def vendored_library(ctx: Context) -> Iterator[Finding]:
    for library in vendored(ctx.index).libraries:
        label = f"{library.name} {library.version}" if library.version else library.name
        where = f" in the folder {library.folder}" if library.folder else ""
        yield make_finding(
            "OWASP-A06-VENDORED-LIB",
            tag=Tag.CONFIRMED if library.known else Tag.INFERRED,
            locations=[Location(rel, 1) for rel in library.files[:10]],
            library=label,
            name=library.name,
            where=where,
            count=len(library.files),
            evidence=library.evidence,
            version_note=("" if library.version else " No version could be read from its files."),
        )
