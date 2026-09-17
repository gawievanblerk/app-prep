"""Review 5, OWASP sweep: own rules weighted to broken access control."""

from __future__ import annotations

import ast
import re

import dpr.reviews.owasp_a01  # noqa: F401  (registers rules)
import dpr.reviews.owasp_assign  # noqa: F401  (registers rules)
import dpr.reviews.owasp_inject  # noqa: F401  (registers rules)
import dpr.reviews.owasp_integrity  # noqa: F401  (registers rules)
import dpr.reviews.owasp_misc  # noqa: F401  (registers rules)
import dpr.reviews.owasp_paths  # noqa: F401  (registers rules)
from dpr.model import Finding, Part, ReviewSection, Route
from dpr.parsing import jsts
from dpr.reviews.access import ADMIN, PUBLIC, access
from dpr.reviews.lookups import PY_ORM, route_lookups
from dpr.reviews.owasp_a01 import unscoped
from dpr.rules import Context

CATEGORIES = {
    "A01": "Broken access control",
    "A02": "Cryptographic failures",
    "A03": "Injection",
    "A04": "Insecure design",
    "A05": "Security misconfiguration",
    "A06": "Vulnerable and outdated components",
    "A07": "Identification and authentication failures",
    "A08": "Software and data integrity failures",
    "A09": "Security logging and monitoring failures",
    "A10": "Server-side request forgery",
}
NOTES = {
    "A04": "Missing rate limits and bot protection are reported in review 7.",
    "A05": "Debug mode and missing headers are reported in review 4 (BASE-DEBUG-ON, "
    "BASE-HEADER-MISSING-*); error text and CORS in review 7 (ABUSE-ERROR-LEAK, ABUSE-CORS-*).",
    "A06": "Not run: the dependency audit adapters arrive in a later version.",
    "A07": "Session and account failure paths belong to review 3, which arrives in a later "
    "version; committed passwords are reported in review 4.",
}
INTRO = (
    "Findings are ordered by exploitability and effort. Access control carries the most weight: "
    "the signature is a route that checks who you are but never whether the record is yours. "
    "The route table below shows how every detected route was classified."
)


def _ownership_checked(ctx: Context, route: Route) -> bool:
    level = access(ctx, route)
    if any(check == "owner" for _, check in route_lookups(ctx, route, level)):
        return True
    subjects = level.subjects
    if not subjects or route.handler is None:
        return False
    if isinstance(route.handler, ast.AST):
        statements = [ast.unparse(n) for n in ast.walk(route.handler) if isinstance(n, ast.Call)]
        orm = PY_ORM
    else:
        statements = [jsts.node_text(c) for c in jsts.walk(route.handler, {"call_expression"})]
        orm = re.compile(r"\.(?:findUnique|findFirst|findMany|update|delete|eq|where)\(")
    return any(orm.search(s) and any(subject in s for subject in subjects) for s in statements)


def classify(ctx: Context, route: Route) -> str:
    level = access(ctx, route).level
    if level in (PUBLIC, ADMIN):
        return level
    if any(r is route or r == route for r, _, _ in unscoped(ctx)):
        return "authenticated, no ownership check found"
    if _ownership_checked(ctx, route):
        return "authenticated and ownership-checked"
    return "authenticated"


def run(ctx: Context) -> ReviewSection:
    if ctx.options.with_audit:
        ctx.not_covered.append(
            "Dependency audit not run: the audit adapters arrive in a later version"
        )
    parts = [Part("text", "How to read this section", body=INTRO), Part("findings", "Findings")]
    return ReviewSection("owasp", parts)


def finish(ctx: Context, section: ReviewSection, findings: list[Finding]) -> None:
    rows = tuple(
        (r.method, r.path, f"{r.file}:{r.line}", classify(ctx, r), access(ctx, r).evidence)
        for r in ctx.detection.routes
    )
    columns = ("Method", "Path", "Where", "Access", "Evidence")
    section.parts.append(Part("table", "Route classification", columns, rows))
    counts = {key: sum(f.owasp == key for f in findings) for key in CATEGORIES}
    lines = []
    for key, title in CATEGORIES.items():
        if counts[key]:
            status = f"{counts[key]} finding(s) above"
        else:
            status = "no finding from this review's own rules"
        note = f" {NOTES[key]}" if key in NOTES else ""
        lines.append(f"- {key} {title}: {status}.{note}")
    section.parts.append(Part("text", "Categories reviewed", body="\n".join(lines)))
