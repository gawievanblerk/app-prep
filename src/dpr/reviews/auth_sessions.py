"""Review 3: sessions that outlive logout, refresh with no absolute limit, unthrottled sign-in."""

from __future__ import annotations

import re
from collections.abc import Iterator

from dpr.discovery.approots import root_of
from dpr.model import Finding, Location, Tag
from dpr.redact import snippet
from dpr.reviews.abuse_paid import is_limited
from dpr.reviews.auth_code import call_names
from dpr.reviews.auth_flows import Flow, flows_of, lifetimes, record_pass, user_models
from dpr.rules import Context, make_finding, rule
from dpr.walk import line_of

COOKIE_OPS = re.compile(
    r"delete_cookie|set_cookie|clearCookie|clear_cookie|cookies\(\)\.delete|cookies\.delete|\.cookie\("
)
REVOKE_CALL = re.compile(
    r"(?i)invalidat|revoke|deny_?list|black_?list|block_?list|destroy|flush|sign_?out"
    r"|(?:^|\.)logout$|(?:^|\.)(?:delete|remove|pop|clear)$"
)
REVOKE_WRITE = re.compile(r"(?i)invalidated_?at|token_?version|revoked_?at|\bjti\b")
RESPONSE_ONLY = re.compile(
    r"(?:^|\.)(?:json|status|send|JSONResponse|Response|jsonify|redirect|NextResponse|end)$"
)
REFRESH_ISSUED = re.compile(
    r"create_refresh_token|refresh_token\s*=|[\"']type[\"']\s*:\s*[\"']refresh|new_refresh"
    r"|refreshToken\s*=|signRefresh|create_tokens|issue_tokens|generate_tokens|RefreshToken\.for_user"
)
ABSOLUTE_CAP = re.compile(
    r"(?i)auth_?time|orig_?iat|original_?iat|session_?start|absolute|max_?session|login_?at"
    r"|authenticated_?at|session_?expires|rotat"
)
LOCKOUT = re.compile(
    r"(?i)failed_?(?:login_?)?attempts|failed_?logins|failedLogins|locked_?until|lock_?until"
    r"|lockout|login_?attempts|brute"
)
LOCKOUT_PACKAGES = {"django-axes", "express-brute", "rate-limiter-flexible", "flask-limiter"}


def _removed_cookie_text(flow: Flow) -> str:
    return COOKIE_OPS.sub(" ", "\n".join(code.text() for code in flow.code))


@rule("AUTH-LOGOUT-NO-REVOKE", review="auth", severity="low", exploitability="low", owasp="A07")
def logout_no_revoke(ctx: Context) -> Iterator[Finding]:
    for flow in flows_of(ctx, "logout"):
        names = [name for code in flow.code for name, _ in call_names(code)]
        revoke = any(REVOKE_CALL.search(n) and not COOKIE_OPS.search(n) for n in names)
        if revoke or REVOKE_WRITE.search(_removed_cookie_text(flow)):
            for case in (5, 10):
                record_pass(
                    ctx,
                    case,
                    Tag.INFERRED,
                    "Logout calls server-side revocation or session removal",
                    flow.location,
                )
            continue
        calls = [name for name, _ in call_names(flow.code[0])]
        only_cookies = len(flow.code) == 1 and all(
            COOKIE_OPS.search(name) or RESPONSE_ONLY.search(name) for name in calls
        )
        yield make_finding(
            "AUTH-LOGOUT-NO-REVOKE",
            tag=Tag.CONFIRMED if only_cookies else Tag.INFERRED,
            locations=[flow.location],
            snippet=snippet(ctx.index.text(flow.route.file), flow.route.line),
            proof_needed=None
            if only_cookies
            else "Call the API with a token issued before logout and check whether it is accepted.",
            route=f"{flow.route.method} {flow.route.path}",
        )


def _absolute_cap_from_config(ctx: Context, flow: Flow) -> Location | None:
    """An absolute-lifetime-shaped setting inside this flow's own app root only."""
    home = root_of(ctx.detection.app_roots, flow.route.file)
    root = home.path if home else None
    for name, _value, location in lifetimes(ctx, root):
        if ABSOLUTE_CAP.search(name):
            return location
    return None


@rule(
    "AUTH-REFRESH-NO-ABSOLUTE-CAP", review="auth", severity="low", exploitability="low", owasp="A07"
)
def refresh_no_cap(ctx: Context) -> Iterator[Finding]:
    for flow in flows_of(ctx, "refresh"):
        text = "\n".join(code.text() for code in flow.code)
        if not REFRESH_ISSUED.search(text):
            continue
        cap = ABSOLUTE_CAP.search(text) or _absolute_cap_from_config(ctx, flow)
        if cap:
            record_pass(
                ctx,
                5,
                Tag.INFERRED,
                "Refresh carries the original sign-in time or rotates tokens",
                flow.location,
            )
            continue
        yield make_finding(
            "AUTH-REFRESH-NO-ABSOLUTE-CAP",
            tag=Tag.INFERRED,
            locations=[flow.location, *(_issue_sites(flow))][:5],
            snippet=snippet(ctx.index.text(flow.route.file), flow.route.line),
            route=f"{flow.route.method} {flow.route.path}",
        )


def _issue_sites(flow: Flow) -> list[Location]:
    found = []
    for code in flow.code[1:]:
        text = code.text()
        match = REFRESH_ISSUED.search(text)
        if match:
            found.append(Location(code.rel, code.line + line_of(text, match.start()) - 1))
    return found


def _lockout_evidence(ctx: Context, flow: Flow) -> Location | None:
    for code in flow.code:
        match = LOCKOUT.search(code.text())
        if match:
            return Location(code.rel, code.line + line_of(code.text(), match.start()) - 1)
    for model in user_models(ctx):
        field = next((f for f in model.fields if LOCKOUT.search(f.name)), None)
        if field is not None:
            return field.location
    return None


@rule("AUTH-NO-LOCKOUT", review="auth", severity="medium", exploitability="high", owasp="A07")
def no_lockout(ctx: Context) -> Iterator[Finding]:
    if LOCKOUT_PACKAGES & ctx.detection.packages:
        return
    for flow in flows_of(ctx, "login"):
        if is_limited(ctx, flow.route):
            record_pass(ctx, 1, Tag.CONFIRMED, "Sign-in has a rate limit", flow.location)
            continue
        evidence = _lockout_evidence(ctx, flow)
        if evidence is not None:
            record_pass(
                ctx, 1, Tag.INFERRED, "Failed sign-ins are counted toward a lockout", evidence
            )
            continue
        yield make_finding(
            "AUTH-NO-LOCKOUT",
            tag=Tag.INFERRED,
            locations=[flow.location],
            snippet=snippet(ctx.index.text(flow.route.file), flow.route.line),
            route=f"{flow.route.method} {flow.route.path}",
        )
