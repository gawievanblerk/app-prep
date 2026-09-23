"""Review 4, security baseline: headers, cookies, transport, password storage."""

from __future__ import annotations

import dpr.reviews.baseline_accounts  # noqa: F401  (registers rules)
import dpr.reviews.baseline_config  # noqa: F401  (registers rules)
import dpr.reviews.baseline_debug  # noqa: F401  (registers rules)
import dpr.reviews.baseline_infra  # noqa: F401  (registers rules)
import dpr.reviews.baseline_literals  # noqa: F401  (registers rules)
import dpr.reviews.baseline_settings  # noqa: F401  (registers rules)
from dpr.model import Finding, Part, ReviewSection
from dpr.reviews.baseline_headers import live_reads
from dpr.reviews.baseline_passes import checks_that_pass
from dpr.reviews.headers_static import HEADERS, surfaces
from dpr.rules import Context

MANAGED_AUTH = {
    "supabase-auth": "Supabase Auth",
    "clerk": "Clerk",
    "auth0": "Auth0",
    "firebase-auth": "Firebase Authentication",
}
HOW_CHECKED_STATIC = (
    "No URL was given, so headers come from configuration and app code. Configured is not the "
    "same as served: a CDN, proxy or platform can add or strip headers. Header findings are "
    "UNVERIFIED until checked against the live site with --url and --i-own-this-host."
)
HOW_CHECKED_LIVE = (
    "Headers were read from the live site named with --url, which the owner confirmed they "
    "control: one HEAD request each to the https root, the https login page and the http root."
)
ENUMERATION = (
    "Account enumeration through sign-in, signup and reset responses belongs to review 3 cases 1, "
    "2 and 4 (AUTH-ENUM-SIGNUP-MESSAGE, AUTH-ENUM-RESET-MESSAGE, AUTH-ENUM-LOCKOUT-STATUS and "
    "AUTH-ENUM-TIMING). This review does not repeat it."
)


def _surface_rows(ctx: Context) -> tuple[tuple[str, ...], ...]:
    return tuple(
        (s.name, s.kind, *("yes" if h in s.headers else "no" for h in HEADERS.values()))
        for s in surfaces(ctx)
    )


def run(ctx: Context) -> ReviewSection:
    reads = live_reads(ctx)
    parts = [
        Part(
            "text",
            "How headers were checked",
            body=HOW_CHECKED_LIVE if reads else HOW_CHECKED_STATIC,
        )
    ]
    if reads:
        rows = tuple(
            (r.label, r.url, str(r.status) if r.status is not None else "failed", r.error or "read")
            for r in reads
        )
        parts.append(
            Part("table", "Live header read", ("Request", "URL", "Status", "Result"), rows)
        )
    if surfaces(ctx):
        columns = ("Surface", "Kind", *HEADERS.values())
        parts.append(Part("table", "Security headers by surface", columns, _surface_rows(ctx)))
    parts.append(Part("findings", "Fix list"))
    managed = [MANAGED_AUTH[p] for p in ctx.detection.auth_providers if p in MANAGED_AUTH]
    notes = ENUMERATION
    if managed:
        notes = (
            f"Password storage is delegated to {', '.join(managed)}. That check is delegated to "
            "the provider, not passed by this repository. " + ENUMERATION
        )
    parts.append(Part("text", "Password storage and account enumeration", body=notes))
    return ReviewSection("baseline", parts)


def finish(ctx: Context, section: ReviewSection, findings: list[Finding]) -> None:
    position = next(i for i, p in enumerate(section.parts) if p.kind == "findings") + 1
    section.parts.insert(
        position, Part("text", "Checks that pass", body=checks_that_pass(ctx, findings))
    )
