"""Review 5, OWASP A06: third-party libraries copied into the repository, one finding per
library listing every copy."""

from __future__ import annotations

import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Tag
from dpr.rules import Context, make_finding, rule
from dpr.vendored import Library, vendored

MAX_LOCATIONS = 20


def _version_key(version: str) -> tuple:
    return tuple(int(p) if p.isdigit() else -1 for p in re.split(r"[.-]", version))


def _label(name: str, copies: list[Library]) -> str:
    versions = sorted({c.version for c in copies if c.version}, key=_version_key)
    if not versions:
        return name
    listed = (
        versions[0] if len(versions) == 1 else ", ".join(versions[:-1]) + f" and {versions[-1]}"
    )
    return f"{name} {listed}"


def _locations(copies: list[Library]) -> list[Location]:
    """The first file of every copy, then the rest of each copy's files."""
    firsts = [c.files[0] for c in copies]
    rest = [rel for c in copies for rel in c.files[1:]]
    return [Location(rel, 1) for rel in dict.fromkeys(firsts + rest)][:MAX_LOCATIONS]


@rule("OWASP-A06-VENDORED-LIB", review="owasp", severity="low", exploitability="low", owasp="A06")
def vendored_library(ctx: Context) -> Iterator[Finding]:
    groups: dict[str, list[Library]] = {}
    for library in vendored(ctx.index).libraries:
        groups.setdefault(library.name.lower(), []).append(library)
    for copies in groups.values():
        folders = [c.folder for c in copies if c.folder]
        where = f" in the folder{'s' if len(folders) > 1 else ''} {', '.join(folders)}"
        unread = sum(1 for c in copies if not c.version)
        note = ""
        if unread == len(copies):
            note = " No version could be read from its files."
        elif unread:
            note = f" No version could be read from {unread} of the copies."
        yield make_finding(
            "OWASP-A06-VENDORED-LIB",
            tag=Tag.CONFIRMED if any(c.known for c in copies) else Tag.INFERRED,
            locations=_locations(copies),
            library=_label(copies[0].name, copies),
            name=copies[0].name,
            where=where if folders else "",
            count=sum(len(c.files) for c in copies),
            copies="a copy" if len(copies) == 1 else f"{len(copies)} separate copies",
            evidence=", ".join(dict.fromkeys(c.evidence for c in copies)),
            version_note=note,
        )
