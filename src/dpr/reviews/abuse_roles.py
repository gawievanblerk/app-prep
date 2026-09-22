"""Review 7, abuse: paid routes every signed-in role can call although the app has role checks."""

from __future__ import annotations

import re
from collections.abc import Iterator

from dpr.discovery.approots import same_root
from dpr.model import Finding, Location, Route, Tag
from dpr.parsing import pyast
from dpr.redact import snippet
from dpr.reviews.access import AUTHENTICATED, PY_DEP, access
from dpr.reviews.owasp_a01 import attacker
from dpr.reviews.paid import costs, paid_routes
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule

ROLE_NAME = re.compile(r"(?i)admin|manager|staff|agent|editor|owner|superuser|moderator|role")
JS_ROLE_CHECK = re.compile(r"\b(?:requireRole|authorize|hasRole|checkRole|requireAdmin)\b")


def role_checks(ctx: Context, route: Route) -> list[str]:
    """Role-restricted dependencies or checks used anywhere in the route's app root."""
    roots = ctx.detection.app_roots
    names: list[str] = []
    for entry in ctx.index.py_files:
        if not same_root(roots, entry.rel, route.file) or is_test(entry.rel):
            continue
        if "Depends" not in ctx.index.text(entry.rel):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for call in pyast.calls(tree, PY_DEP) if tree else []:
            target = (pyast.dotted(call.args[0]) or "").split(".")[-1] if call.args else ""
            if ROLE_NAME.search(target):
                names.append(target)
    for entry in ctx.index.js_files:
        if same_root(roots, entry.rel, route.file) and not is_test(entry.rel):
            names += JS_ROLE_CHECK.findall(ctx.index.text(entry.rel))
    return list(dict.fromkeys(names))


@rule(
    "ABUSE-PAID-ANY-ROLE", review="abuse", severity="medium", exploitability="medium", owasp="A01"
)
def paid_any_role(ctx: Context) -> Iterator[Finding]:
    for paid in paid_routes(ctx):
        route = paid.route
        level = access(ctx, route)
        if level.level != AUTHENTICATED or is_test(route.file):
            continue
        if attacker(level.evidence) != "any signed-in user":
            continue
        checks = role_checks(ctx, route)
        if not checks:
            continue
        cost = costs().get(paid.sdk.category, {"note": "provider pricing"})
        yield make_finding(
            "ABUSE-PAID-ANY-ROLE",
            tag=Tag.INFERRED,
            locations=[Location(route.file, route.line)],
            snippet=snippet(ctx.index.text(route.file), route.line),
            method=route.method,
            path=route.path,
            sdk=paid.sdk.name,
            cost=cost["note"],
            evidence=level.evidence,
            checks=", ".join(checks[:5]),
        )
