"""Review 4, baseline: security headers, CSP strength, version disclosure, HTTPS redirect."""

from __future__ import annotations

import re
from collections.abc import Iterator

from dpr.adapters.headers import HeaderRead, read_headers
from dpr.model import Finding, Location, Tag
from dpr.reviews.headers_static import HEADERS, csp_values, surfaces
from dpr.rules import Context, make_finding, rule

SEVERITY = {"HSTS": "high", "CSP": "medium"}
LOGIN_PATH = re.compile(r"(?i)/(?:log-?in|sign-?in)$")
VERSION = re.compile(r"\d")


def login_path(ctx: Context) -> str:
    if ctx.options.login_path:
        return ctx.options.login_path
    for route in ctx.detection.routes:
        if LOGIN_PATH.search(route.path) and route.method in ("GET", "ANY", "POST"):
            return route.path
    return "/login"


def live_reads(ctx: Context) -> list[HeaderRead] | None:
    """Read live headers once per run, only when a URL was given with owner confirmation."""
    if not ctx.options.url or not ctx.options.owns_host:
        return None
    if "live_headers" not in ctx.facts:
        reads = read_headers(ctx.options.url, login_path(ctx))
        for read in reads:
            if read.error:
                ctx.not_covered.append(f"Live header read of {read.url} failed: {read.error}")
        ctx.facts["live_headers"] = reads
    return ctx.facts["live_headers"]


def _read(ctx: Context, label: str) -> HeaderRead | None:
    for read in live_reads(ctx) or []:
        if read.label == label and read.status is not None:
            return read
    return None


def _missing(ctx: Context, key: str) -> Iterator[Finding]:
    header = HEADERS[key]
    root = _read(ctx, "https root")
    if root is not None:
        present = header in root.headers or (
            key == "FRAME" and "frame-ancestors" in root.headers.get(HEADERS["CSP"], "")
        )
        if not present:
            yield make_finding(
                f"BASE-HEADER-MISSING-{key}",
                tag=Tag.CONFIRMED,
                locations=[Location(root.url, 1)],
                severity=SEVERITY.get(key, "low"),
                header=header,
                where=f"the live response from {root.url}",
            )
        return
    lacking = [s for s in surfaces(ctx) if header not in s.headers]
    if lacking:
        where = "; ".join(f"{s.name} ({s.kind})" for s in lacking)
        yield make_finding(
            f"BASE-HEADER-MISSING-{key}",
            tag=Tag.UNVERIFIED,
            locations=[s.location for s in lacking][:10],
            severity=SEVERITY.get(key, "low"),
            header=header,
            where=where,
        )


def _header_rule(key: str):
    def check(ctx: Context) -> Iterator[Finding]:
        yield from _missing(ctx, key)

    return check


for _key in HEADERS:
    rule(
        f"BASE-HEADER-MISSING-{_key}",
        review="baseline",
        severity=SEVERITY.get(_key, "low"),
        exploitability="low",
        owasp="A05",
    )(_header_rule(_key))


def _directive(policy: str, name: str) -> str | None:
    for part in policy.split(";"):
        tokens = part.strip().split()
        if tokens and tokens[0].lower() == name:
            return " ".join(tokens[1:])
    return None


def weak_csp_reason(policy: str) -> str | None:
    script = _directive(policy, "script-src")
    default = _directive(policy, "default-src")
    effective = script if script is not None else default
    if effective is not None and "'unsafe-inline'" in effective:
        return "script-src allows 'unsafe-inline'"
    if default is not None and "*" in default.split():
        return "default-src allows any origin (*)"
    return None


@rule("BASE-CSP-WEAK", review="baseline", severity="medium", exploitability="medium", owasp="A05")
def csp_weak(ctx: Context) -> Iterator[Finding]:
    root = _read(ctx, "https root")
    if root is not None and HEADERS["CSP"] in root.headers:
        reason = weak_csp_reason(root.headers[HEADERS["CSP"]])
        if reason:
            yield make_finding(
                "BASE-CSP-WEAK", tag=Tag.CONFIRMED, locations=[Location(root.url, 1)], reason=reason
            )
    for policy, location in csp_values(ctx):
        reason = weak_csp_reason(policy)
        if reason:
            yield make_finding(
                "BASE-CSP-WEAK", tag=Tag.CONFIRMED, locations=[location], reason=reason
            )


@rule(
    "BASE-VERSION-DISCLOSURE",
    review="baseline",
    severity="low",
    exploitability="low",
    owasp="A05",
)
def version_disclosure(ctx: Context) -> Iterator[Finding]:
    root = _read(ctx, "https root")
    if root is not None:
        for name in ("server", "x-powered-by"):
            if VERSION.search(root.headers.get(name, "")):
                yield make_finding(
                    "BASE-VERSION-DISCLOSURE",
                    tag=Tag.CONFIRMED,
                    locations=[Location(root.url, 1)],
                    what=f"The live response sends a {name} header with a version number.",
                )
    for surface in surfaces(ctx):
        text = ctx.index.text(surface.location.file)
        if surface.kind == "Next.js app" and not re.search(r"poweredByHeader\s*:\s*false", text):
            what = (
                "next.config does not set poweredByHeader: false, so X-Powered-By: Next.js is sent."
            )
        elif surface.kind == "Express app" and not _express_hides(ctx, surface.root):
            what = "The Express app neither calls app.disable('x-powered-by') nor uses helmet."
        else:
            continue
        yield make_finding(
            "BASE-VERSION-DISCLOSURE",
            tag=Tag.INFERRED,
            locations=[surface.location],
            what=what,
        )


def _express_hides(ctx: Context, root: str) -> bool:
    for entry in ctx.index.js_files:
        if root and not entry.rel.startswith(root + "/"):
            continue
        text = ctx.index.text(entry.rel)
        if re.search(r"disable\(\s*['\"]x-powered-by['\"]", text) or "helmet(" in text:
            return True
    return False


@rule(
    "BASE-NO-HTTPS-REDIRECT",
    review="baseline",
    severity="high",
    exploitability="medium",
    owasp="A02",
)
def no_https_redirect(ctx: Context) -> Iterator[Finding]:
    http = _read(ctx, "http root")
    if http is None:
        return
    location = http.headers.get("location", "")
    if http.status not in (301, 302, 303, 307, 308) or not location.startswith("https://"):
        yield make_finding(
            "BASE-NO-HTTPS-REDIRECT",
            tag=Tag.CONFIRMED,
            locations=[Location(http.url, 1)],
            status=http.status,
        )


@rule("BASE-CACHE-AUTH", review="baseline", severity="low", exploitability="low", owasp="A05")
def cache_auth(ctx: Context) -> Iterator[Finding]:
    login = _read(ctx, "https login page")
    if login is not None and "no-store" not in login.headers.get("cache-control", "").lower():
        yield make_finding("BASE-CACHE-AUTH", tag=Tag.CONFIRMED, locations=[Location(login.url, 1)])
