"""Review 5, OWASP A06: dependency versions with published advisories.

Exact pins (`dpr.parsing.pins`) and versions read from libraries copied into the repository
(`dpr.vendored`) are compared with the bundled table `data/advisories.yaml`. The table is small
and dated; it is not an advisory database, and no network is used.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

from dpr.data import load
from dpr.model import Finding, Location, Tag
from dpr.parsing.pins import pinned_versions
from dpr.redact import snippet
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule
from dpr.vendored import LIB_EXTS, Library, file_library, is_vendored, vendored

SEVERITIES = ("critical", "high", "medium", "low")
PRE_RELEASE = re.compile(r"(?i)(?:a|b|rc|alpha|beta|pre|dev|preview)\d*")
MAX_LOCATIONS = 20


def version_key(version: str) -> tuple[tuple[int, ...], int]:
    """A sortable key: the numeric release parts (padded), then 0 for a pre-release (`4.0.0-beta.2`,
    `2.0rc1`) so it sorts before its release, 1 otherwise (post releases sort as the release)."""
    match = re.match(r"v?(\d+(?:\.\d+)*)(.*)$", version.strip())
    if match is None:
        return (), 1
    numbers = tuple(int(part) for part in match.group(1).split("."))
    numbers += (0,) * (4 - len(numbers))
    rest = match.group(2).lstrip(".-+_")
    pre = bool(rest) and bool(PRE_RELEASE.match(rest)) and not rest.lower().startswith("post")
    return numbers, 0 if pre else 1


def affected(version: str, ranges: list[list[str | None]]) -> str | None:
    """The fixed version of the range that holds the version ("" when no release fixes it), or
    None when no range holds it. A range is [introduced, fixed): introduced <= v < fixed."""
    key = version_key(version)
    if not key[0]:
        return None
    for introduced, fixed in ranges:
        if key >= version_key(str(introduced)) and (fixed is None or key < version_key(fixed)):
            return fixed or ""
    return None


@dataclass(frozen=True)
class Match:
    package: str
    version: str
    locations: tuple[Location, ...]


def _version_site(index, library: Library) -> Location:
    """Where a copy states its version (a banner, a version constant, the build output of a
    library folder), else the copy's first file."""
    below = []
    if library.folder:
        prefix = library.folder + "/"
        below = sorted(
            e.rel for e in [*index.files, *index.build_files] if e.rel.startswith(prefix)
        )
    for rel in dict.fromkeys([*library.files, *below]):
        if rel.endswith(LIB_EXTS):
            text = index.text(rel)
            found = file_library(rel, text)
            if found and found[1] == library.version:
                at = text.find(library.version, 0, 65536)
                return Location(rel, text.count("\n", 0, at) + 1 if at >= 0 else 1)
    return Location(library.files[0], 1)


def _installed(ctx: Context) -> list[Match]:
    """Each package and version the repository pins or copies, with where it is declared."""
    table = load("advisories.yaml")
    ecosystems = {name: entry["ecosystem"] for name, entry in table["packages"].items()}
    sites: dict[tuple[str, str], list[Location]] = {}
    for pin in pinned_versions(ctx.index):
        if ecosystems.get(pin.name) == pin.ecosystem and not is_test(pin.location.file):
            sites.setdefault((pin.name, pin.version), []).append(pin.location)
    for library in vendored(ctx.index).libraries:
        package = table["names"].get(library.name.lower())
        if package and library.version:
            where = sites.setdefault((package, library.version), [])
            where.append(_version_site(ctx.index, library))
    return [Match(name, version, tuple(where)) for (name, version), where in sorted(sites.items())]


@rule(
    "OWASP-A06-KNOWN-ADVISORY",
    review="owasp",
    severity="high",
    exploitability="medium",
    owasp="A06",
)
def known_advisory(ctx: Context) -> Iterator[Finding]:
    table = load("advisories.yaml")
    for item in _installed(ctx):
        entry = table["packages"][item.package]
        hits = []
        for advisory in entry["advisories"]:
            fixed = affected(item.version, advisory["affected"])
            if fixed is not None:
                hits.append((advisory, fixed))
        if not hits:
            continue
        severity = min((a["severity"] for a, _ in hits), key=SEVERITIES.index)
        listed = "; ".join(
            f"{a['id']} ({a['severity']}, "
            f"{'fixed in ' + fixed if fixed else 'no fixed release'}): {a['summary']}"
            for a, fixed in hits
        )
        fixes = [fixed for _, fixed in hits if fixed]
        target = max(fixes, key=version_key) if fixes else ""
        upgrade = (
            f"Upgrade {entry['label']} to {target} or later"
            if target
            else f"No release of {entry['label']} fixes every advisory listed"
        )
        if target and len(fixes) < len(hits):
            upgrade += ", and replace or remove it where an advisory has no fixed release"
        locations = sorted(dict.fromkeys(item.locations), key=lambda loc: (loc.file, loc.line))
        first = locations[0]
        yield make_finding(
            "OWASP-A06-KNOWN-ADVISORY",
            tag=Tag.CONFIRMED,
            locations=locations[:MAX_LOCATIONS],
            snippet=None
            if is_vendored(ctx.index, first.file)
            else snippet(ctx.index.text(first.file), first.line),
            severity=severity,
            component=entry["label"],
            version=item.version,
            count=f"{len(hits)} published security advisor{'y' if len(hits) == 1 else 'ies'}",
            advisories=", ".join(a["id"] for a, _ in hits),
            listed=listed,
            upgrade=upgrade,
            table_date=table["as_of"],
        )
