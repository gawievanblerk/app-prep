"""Review 7, abuse: paid routes without auth, limits or a kill switch; public forms."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.discovery.approots import root_of
from dpr.model import Finding, Location, Route, Tag
from dpr.parsing import jsts
from dpr.parsing.mounts import limiter_mounts
from dpr.redact import snippet
from dpr.reviews.access import PUBLIC, access, unread_guard
from dpr.reviews.auth_axes import axes_for
from dpr.reviews.auth_flows import flows_of
from dpr.reviews.paid import PaidRoute, costs, paid_routes
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule

LIMITER_WORD = re.compile(r"(?i)rate_?limit|limiter|\.limit\(|throttle|slowdown")
KILL_SWITCH = re.compile(
    r"(?i)\w*_enabled\b|\benabled\b|\bdisable_?\w*|kill_?switch|feature_?flag|is_?feature_?enabled"
    r"|isEnabled\(|unleash|launchdarkly|growthbook|flagsmith"
)
CHALLENGE = re.compile(r"(?i)turnstile|hcaptcha|recaptcha|captcha|honeypot")


def _handler_text(route: Route) -> str:
    handler = route.handler
    if isinstance(handler, ast.AST):
        return "\n".join(ast.unparse(d) for d in getattr(handler, "decorator_list", [])) + (
            "\n" + ast.unparse(handler)
        )
    if handler is not None and hasattr(handler, "type"):
        return jsts.node_text(handler)
    return ""


def slowapi_wired(ctx: Context) -> bool:
    return any(
        "SlowAPIMiddleware" in ctx.index.text(f.rel) and "add_middleware" in ctx.index.text(f.rel)
        for f in ctx.index.py_files
    )


def is_limited(ctx: Context, route: Route) -> bool:
    text = _handler_text(route)
    if LIMITER_WORD.search(text):
        return True
    if route.framework in ("fastapi", "flask") and slowapi_wired(ctx):
        return True
    if route.framework == "express" and route.tree is not None:
        for call in jsts.calls(route.tree, r"(?:\w+\.)*use"):
            if (
                LIMITER_WORD.search(jsts.node_text(call))
                and jsts.line(route.tree, call) < route.line
            ):
                return True
        home = root_of(ctx.detection.app_roots, route.file)
        for rel, prefix in limiter_mounts(ctx.index):
            same_app = root_of(ctx.detection.app_roots, rel) == home
            if same_app and (route.path == prefix or route.path.startswith(prefix + "/")):
                return True
    if route.framework.startswith("next"):
        for entry in ctx.index.named("middleware.ts", "middleware.js"):
            if LIMITER_WORD.search(ctx.index.text(entry.rel)):
                return True
    return False


def _paid_detail(paid: PaidRoute) -> dict[str, object]:
    cost = costs().get(paid.sdk.category, {"note": "provider pricing"})
    via = f" through {paid.via}()" if paid.via else ""
    return {
        "method": paid.route.method,
        "path": paid.route.path,
        "sdk": paid.sdk.name,
        "via": via,
        "cost": cost["note"],
    }


@rule("ABUSE-PAID-UNAUTH", review="abuse", severity="critical", exploitability="high", owasp="A04")
def paid_unauth(ctx: Context) -> Iterator[Finding]:
    for paid in paid_routes(ctx):
        route = paid.route
        if route.is_public_form and paid.sdk.category in ("email", "sms"):
            continue
        level = access(ctx, route)
        if level.level == PUBLIC and not is_test(route.file):
            proofs = [unread_guard(level)]
            if not paid.exact:
                proofs.append(
                    f"The {paid.via}() helper was matched by name only; confirm the route calls "
                    f"the function that uses {paid.sdk.name}."
                )
            proof = " ".join(p for p in proofs if p) or None
            yield make_finding(
                "ABUSE-PAID-UNAUTH",
                tag=Tag.INFERRED if proof else Tag.CONFIRMED,
                locations=[Location(route.file, route.line)],
                snippet=snippet(ctx.index.text(route.file), route.line),
                proof_needed=proof,
                **_paid_detail(paid),
            )


@rule("ABUSE-PAID-UNLIMITED", review="abuse", severity="high", exploitability="high", owasp="A04")
def paid_unlimited(ctx: Context) -> Iterator[Finding]:
    for paid in paid_routes(ctx):
        route = paid.route
        if not is_limited(ctx, route) and not is_test(route.file):
            cost = costs().get(paid.sdk.category, {})
            yield make_finding(
                "ABUSE-PAID-UNLIMITED",
                tag=Tag.INFERRED,
                locations=[Location(route.file, route.line)],
                snippet=snippet(ctx.index.text(route.file), route.line),
                per_user=cost.get("per_user", 20),
                per_ip=cost.get("per_ip", 40),
                window=cost.get("window", "1 h"),
                **_paid_detail(paid),
            )


@rule("ABUSE-NO-KILL-SWITCH", review="abuse", severity="low", exploitability="low", owasp="A04")
def no_kill_switch(ctx: Context) -> Iterator[Finding]:
    for paid in paid_routes(ctx):
        route = paid.route
        if KILL_SWITCH.search(_handler_text(route)) or is_test(route.file):
            continue
        flag = re.sub(r"[^A-Z0-9]+", "_", route.path.upper()).strip("_") or "PAID_ROUTE"
        yield make_finding(
            "ABUSE-NO-KILL-SWITCH",
            tag=Tag.INFERRED,
            locations=[Location(route.file, route.line)],
            flag=f"{flag}_ENABLED",
            **_paid_detail(paid),
        )


@rule(
    "ABUSE-FORM-NO-CHALLENGE",
    review="abuse",
    severity="medium",
    exploitability="medium",
    owasp="A04",
)
def form_no_challenge(ctx: Context) -> Iterator[Finding]:
    by_file: dict[str, list[Route]] = {}
    for route in ctx.detection.routes:
        if not route.is_public_form or is_test(route.file):
            continue
        if access(ctx, route).level != PUBLIC or route.method in ("GET", "HEAD", "OPTIONS"):
            continue
        if CHALLENGE.search(_handler_text(route)):
            continue
        by_file.setdefault(route.file, []).append(route)
    for rel, routes in sorted(by_file.items()):
        if CHALLENGE.search(ctx.index.text(rel)):
            continue
        locked = {
            (f.route.file, f.route.line) for f in flows_of(ctx, "login") if axes_for(ctx, rel)
        }
        limited = all(is_limited(ctx, r) or (r.file, r.line) in locked for r in routes)
        yield make_finding(
            "ABUSE-FORM-NO-CHALLENGE",
            tag=Tag.INFERRED,
            locations=[Location(r.file, r.line) for r in routes],
            snippet=snippet(ctx.index.text(rel), routes[0].line),
            routes=", ".join(f"{r.method} {r.path}" for r in routes),
            summary="have rate limits but no bot challenge"
            if limited
            else "accept unlimited automated submissions",
        )
