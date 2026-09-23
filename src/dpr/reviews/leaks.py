"""Review 6, leak hunt: keys, public env names, build output and error tracker config."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import PurePosixPath

import dpr.reviews.leaks_creds  # noqa: F401  (registers rules)
import dpr.reviews.leaks_files  # noqa: F401  (registers rules)
import dpr.reviews.leaks_logs  # noqa: F401  (registers rules)
import dpr.reviews.leaks_settings  # noqa: F401  (registers rules)
from dpr.facts import fact
from dpr.model import Finding, Location, Part, ReviewSection, Tag
from dpr.parsing import jsts, pyast
from dpr.redact import find_keys, is_secret_name, public_prefix, snippet
from dpr.reviews import leaks_code  # noqa: F401  (registers the leaks_code rules)
from dpr.reviews.leaks_summary import summary_parts
from dpr.rules import Context, make_finding, rule
from dpr.vendored import is_vendored
from dpr.walk import line_of

ROTATE = (
    "Rotate the key now. It already reached a browser or history; "
    "removing it from the next build does not undo that."
)
NEXT_SOURCEMAPS = re.compile(r"productionBrowserSourceMaps\s*:\s*true")
LOAD_ORDER = {
    "vite": [".js", ".mjs", ".ts", ".cjs", ".mts", ".cts"],
    "next": [".js", ".mjs", ".ts", ".cjs", ".mts", ".cts"],
}
VITE_SOURCEMAPS = re.compile(r"\bsourcemap\s*:\s*(?:true|['\"](?:inline|hidden)['\"])")


@rule("LEAK-PUBLIC-SECRET", review="leaks", severity="critical", exploitability="high")
def public_secret(ctx: Context) -> Iterator[Finding]:
    for env in ctx.detection.env_vars:
        prefix = public_prefix(env.name)
        if prefix and is_secret_name(env.name):
            yield make_finding(
                "LEAK-PUBLIC-SECRET",
                tag=Tag.CONFIRMED,
                locations=env.locations,
                name=env.name,
                prefix=prefix,
                renamed=env.name[len(prefix) :],
            )


@rule("LEAK-HARDCODED-KEY", review="leaks", severity="critical", exploitability="high")
def hardcoded_key(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.files:
        text = ctx.index.text(entry.rel)
        for hit in find_keys(text):
            yield make_finding(
                "LEAK-HARDCODED-KEY",
                tag=Tag.CONFIRMED,
                locations=[Location(entry.rel, hit.line)],
                severity=None if hit.live else "high",
                snippet=snippet(text, hit.line),
                kind=hit.kind,
            )


@rule("LEAK-KEY-IN-BUILD", review="leaks", severity="critical", exploitability="high")
def key_in_build(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.build_files:
        text = entry.path.read_text(encoding="utf-8", errors="replace")
        for hit in find_keys(text):
            yield make_finding(
                "LEAK-KEY-IN-BUILD",
                tag=Tag.CONFIRMED,
                locations=[Location(entry.rel, hit.line)],
                severity=None if hit.live else "high",
                kind=hit.kind,
            )


@rule("LEAK-SOURCEMAP", review="leaks", severity="medium", exploitability="medium")
def sourcemaps(ctx: Context) -> Iterator[Finding]:
    maps = [
        f
        for f in ctx.index.build_files
        if f.name.endswith(".map") and not is_vendored(ctx.index, f.rel)
    ]
    if maps:
        yield make_finding(
            "LEAK-SOURCEMAP",
            tag=Tag.CONFIRMED,
            locations=[Location(f.rel, 1) for f in maps[:5]],
            what=f"{len(maps)} source map file(s) are in the build output.",
        )
    groups: dict[tuple[str, str], list[Location]] = {}
    for entry in ctx.index.named("next.config.*", "vite.config.*"):
        if entry.name.endswith((".d.ts", ".d.mts", ".d.cts")):
            continue
        tool = "next" if entry.name.startswith("next.") else "vite"
        if PurePosixPath(entry.rel).suffix not in LOAD_ORDER[tool]:
            continue
        text = ctx.index.text(entry.rel)
        pattern = NEXT_SOURCEMAPS if tool == "next" else VITE_SOURCEMAPS
        folder = str(PurePosixPath(entry.rel).parent)
        for match in pattern.finditer(text):
            groups.setdefault((folder, tool), []).append(
                Location(entry.rel, line_of(text, match.start()))
            )
    for (_folder, tool), found in sorted(groups.items()):
        order = LOAD_ORDER[tool]
        found.sort(key=lambda loc: (order.index(PurePosixPath(loc.file).suffix), loc.line))
        loaded = PurePosixPath(found[0].file).name
        twins = sorted({PurePosixPath(loc.file).name for loc in found[1:]} - {loaded})
        extra = (
            f" The same setting is in {', '.join(twins)}, which {tool} does not load when "
            f"{loaded} exists."
            if twins
            else ""
        )
        yield make_finding(
            "LEAK-SOURCEMAP",
            tag=Tag.CONFIRMED,
            locations=found,
            snippet=snippet(ctx.index.text(found[0].file), found[0].line),
            what=f"{loaded} turns on source maps for the production build.{extra}",
        )


def _sentry_detail(sends_pii: bool, scrubs: bool) -> str:
    if sends_pii:
        extra = "" if scrubs else " There is no beforeSend hook to scrub events."
        return "The error tracker is set to send default personal data." + extra
    return "The error tracker is initialised without a beforeSend hook, so events are not scrubbed."


@dataclass(frozen=True)
class SentryInit:
    location: Location
    line: int
    sends_pii: bool
    scrubs: bool


def _js_sentry(ctx: Context) -> Iterator[SentryInit]:
    for entry in ctx.index.js_files:
        if "sentry" not in ctx.index.text(entry.rel).lower():
            continue
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for call in jsts.calls(tree, r"(?:\w+\.)?init"):
                args = jsts.arguments(call)
                pairs = jsts.object_pairs(args[0]) if args else {}
                if "dsn" not in pairs:
                    continue
                pii = pairs.get("sendDefaultPii")
                sends_pii = pii is not None and jsts.node_text(pii) == "true"
                line = jsts.line(tree, pii if sends_pii else call)
                location = Location(entry.rel, jsts.line(tree, call))
                yield SentryInit(location, line, sends_pii, "beforeSend" in pairs)


def _py_sentry(ctx: Context) -> Iterator[SentryInit]:
    for entry in ctx.index.py_files:
        if "sentry_sdk" not in ctx.index.text(entry.rel):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for call in pyast.calls(tree, r"sentry_sdk\.init") if tree else []:
            pii = pyast.kwarg(call, "send_default_pii")
            sends_pii = pyast.constant(pii) is True
            line = pii.lineno if sends_pii else call.lineno
            scrubs = pyast.kwarg(call, "before_send") is not None
            yield SentryInit(Location(entry.rel, call.lineno), line, sends_pii, scrubs)


def sentry_inits(ctx: Context) -> list[SentryInit]:
    """Error tracker init calls. Shared with the inventory review."""
    return fact(ctx, "sentry_inits", lambda c: [*_js_sentry(c), *_py_sentry(c)])


@rule("LEAK-SENTRY-PII", review="leaks", severity="medium", exploitability="low")
def sentry_pii(ctx: Context) -> Iterator[Finding]:
    for init in sentry_inits(ctx):
        if not init.sends_pii and init.scrubs:
            continue
        text = ctx.index.text(init.location.file)
        yield make_finding(
            "LEAK-SENTRY-PII",
            tag=Tag.CONFIRMED,
            locations=[Location(init.location.file, init.line)],
            snippet=snippet(text, init.line),
            what=_sentry_detail(init.sends_pii, init.scrubs),
        )


def run(ctx: Context) -> ReviewSection:
    note = (
        "No secret value is printed in this report. Findings name the variable or key type "
        "and where it is. A key that reached a browser or git history must be rotated."
    )
    return ReviewSection(
        "leaks",
        [Part("text", "What this review never prints", body=note), Part("findings", "Leaks")],
    )


def finish(ctx: Context, section: ReviewSection, findings: list[Finding]) -> None:
    position = next(i for i, p in enumerate(section.parts) if p.kind == "findings")
    section.parts[position:position] = summary_parts(ctx, findings)
