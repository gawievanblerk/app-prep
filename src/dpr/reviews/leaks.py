"""Review 6, leak hunt: keys, public env names, build output and error tracker config."""

from __future__ import annotations

import re
from collections.abc import Iterator

import dpr.reviews.leaks_creds  # noqa: F401  (registers rules)
import dpr.reviews.leaks_logs  # noqa: F401  (registers rules)
from dpr.model import Finding, Location, Part, ReviewSection, Tag
from dpr.parsing import jsts, pyast
from dpr.redact import find_keys, is_secret_name, public_prefix, snippet
from dpr.reviews import leaks_code  # noqa: F401  (registers the leaks_code rules)
from dpr.rules import Context, make_finding, rule
from dpr.walk import line_of

ROTATE = (
    "Rotate the key now. It already reached a browser or history; "
    "removing it from the next build does not undo that."
)
NEXT_SOURCEMAPS = re.compile(r"productionBrowserSourceMaps\s*:\s*true")
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
    maps = [f for f in ctx.index.build_files if f.name.endswith(".map")]
    if maps:
        yield make_finding(
            "LEAK-SOURCEMAP",
            tag=Tag.CONFIRMED,
            locations=[Location(f.rel, 1) for f in maps[:5]],
            what=f"{len(maps)} source map file(s) are in the build output.",
        )
    for entry in ctx.index.named("next.config.*", "vite.config.*"):
        text = ctx.index.text(entry.rel)
        pattern = NEXT_SOURCEMAPS if entry.name.startswith("next.") else VITE_SOURCEMAPS
        for match in pattern.finditer(text):
            line = line_of(text, match.start())
            yield make_finding(
                "LEAK-SOURCEMAP",
                tag=Tag.CONFIRMED,
                locations=[Location(entry.rel, line)],
                snippet=snippet(text, line),
                what=f"{entry.name} turns on source maps for the production build.",
            )


def _sentry_detail(sends_pii: bool, scrubs: bool) -> str:
    if sends_pii:
        extra = "" if scrubs else " There is no beforeSend hook to scrub events."
        return "The error tracker is set to send default personal data." + extra
    return "The error tracker is initialised without a beforeSend hook, so events are not scrubbed."


def _js_sentry(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.js_files:
        text = ctx.index.text(entry.rel)
        if "sentry" not in text.lower():
            continue
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for call in jsts.calls(tree, r"(?:\w+\.)?init"):
                args = jsts.arguments(call)
                pairs = jsts.object_pairs(args[0]) if args else {}
                if "dsn" not in pairs:
                    continue
                init_line = jsts.line(tree, call)
                ctx.facts.setdefault("sentry", []).append(Location(entry.rel, init_line))
                pii = pairs.get("sendDefaultPii")
                sends_pii = pii is not None and jsts.node_text(pii) == "true"
                scrubs = "beforeSend" in pairs
                if not sends_pii and scrubs:
                    continue
                line = jsts.line(tree, pii if sends_pii else call)
                yield make_finding(
                    "LEAK-SENTRY-PII",
                    tag=Tag.CONFIRMED,
                    locations=[Location(entry.rel, line)],
                    snippet=snippet(text, line),
                    what=_sentry_detail(sends_pii, scrubs),
                )


def _py_sentry(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if "sentry_sdk" not in text:
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        if tree is None:
            continue
        for call in pyast.calls(tree, r"sentry_sdk\.init"):
            ctx.facts.setdefault("sentry", []).append(Location(entry.rel, call.lineno))
            pii = pyast.kwarg(call, "send_default_pii")
            sends_pii = pyast.constant(pii) is True
            scrubs = pyast.kwarg(call, "before_send") is not None
            if not sends_pii and scrubs:
                continue
            line = pii.lineno if sends_pii else call.lineno
            yield make_finding(
                "LEAK-SENTRY-PII",
                tag=Tag.CONFIRMED,
                locations=[Location(entry.rel, line)],
                snippet=snippet(text, line),
                what=_sentry_detail(sends_pii, scrubs),
            )


@rule("LEAK-SENTRY-PII", review="leaks", severity="medium", exploitability="low")
def sentry_pii(ctx: Context) -> Iterator[Finding]:
    yield from _js_sentry(ctx)
    yield from _py_sentry(ctx)


def run(ctx: Context) -> ReviewSection:
    note = (
        "No secret value is printed in this report. Findings name the variable or key type "
        "and where it is. A key that reached a browser or git history must be rotated."
    )
    return ReviewSection(
        "leaks",
        [Part("text", "What this review never prints", body=note), Part("findings", "Leaks")],
    )
