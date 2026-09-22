"""Review 5, OWASP A09: exports, downloads and reports that leave no audit record."""

from __future__ import annotations

import re
from collections.abc import Iterator

from dpr.discovery.approots import root_of, same_root
from dpr.model import Finding, Location, Route, Tag
from dpr.reviews.access import PUBLIC, access
from dpr.reviews.auth_flows import route_code
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule

EXPORT_PATH = re.compile(r"(?i)export|download|csv|pdf|xlsx|bulk|statement|backup|dump")
EXPORT_RESPONSE = re.compile(
    r"FileResponse|send_file|text/csv|application/pdf|spreadsheetml|attachment; filename"
    r"|Content-Disposition|res\.download\(|res\.attachment\("
)
AUDIT_CALL = re.compile(
    r"(?i)audit|log_?activity|record_?access|access_?log|activity_?log|track_?export"
)
AUDIT_MODEL = re.compile(r"(?i)audit|activity|access_?log|event_?log")


def export_routes(ctx: Context) -> list[tuple[Route, str]]:
    found = []
    for route in ctx.detection.routes:
        if is_test(route.file) or route.handler is None or access(ctx, route).level == PUBLIC:
            continue
        code = route_code(ctx, route)
        text = "\n".join(c.text() for c in code)
        if EXPORT_RESPONSE.search(text) or (
            EXPORT_PATH.search(route.path) and route.method == "GET"
        ):
            found.append((route, text))
    return found


@rule("OWASP-A09-NO-READ-AUDIT", review="owasp", severity="low", exploitability="low", owasp="A09")
def no_read_audit(ctx: Context) -> Iterator[Finding]:
    by_root: dict[str, list[Route]] = {}
    for route, text in export_routes(ctx):
        if AUDIT_CALL.search(text):
            continue
        home = root_of(ctx.detection.app_roots, route.file)
        by_root.setdefault(home.path if home else "", []).append(route)
    for root, routes in sorted(by_root.items()):
        models = [
            m.name
            for m in ctx.detection.models
            if same_root(ctx.detection.app_roots, m.location.file, routes[0].file)
            and AUDIT_MODEL.search(m.name)
        ]
        what = (
            (
                f"The app has audit tables ({', '.join(models)}), but "
                "these routes write no audit record"
            )
            if models
            else "The app has no audit table, so no read or export is recorded"
        )
        yield make_finding(
            "OWASP-A09-NO-READ-AUDIT",
            tag=Tag.INFERRED,
            locations=[Location(r.file, r.line) for r in routes][:10],
            app=root or "this repository",
            what=what,
            routes=", ".join(f"{r.method} {r.path}" for r in routes[:6]),
            count=len(routes),
        )
