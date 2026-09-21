"""Review 3: responses and timing that tell a caller whether an account exists."""

from __future__ import annotations

import re
from collections.abc import Iterator

from dpr.model import Finding, Tag
from dpr.redact import snippet
from dpr.reviews.auth_code import (
    PASSWORD_VERIFY,
    call_names,
    caller_literals,
    early_exit_before,
    has_dummy_hash,
    status_codes,
)
from dpr.reviews.auth_flows import Flow, flows_of, record_pass
from dpr.rules import Context, make_finding, rule

EXISTS = re.compile(
    r"(?i)already (?:registered|exists|in use|taken|signed up)"
    r"|(?:email|account|user(?:name)?) (?:is )?(?:already )?(?:taken|exists|in use)"
    r"|account with (?:this|that) email"
)
NOT_FOUND = re.compile(
    r"(?i)no (?:account|user)s? (?:found|exists?|with|for)|(?:not|isn't|is not) registered"
    r"|does(?:n't| not) exist|(?:email|account|user) (?:was )?not found"
    r"|unknown (?:email|account|user)"
)
LOCKED = re.compile(
    r"(?i)account (?:is )?(?:temporarily )?locked|locked (?:out|until)|too many (?:failed )?"
    r"(?:login |sign-?in )?attempts|try again (?:after|in)"
)
SEND = re.compile(r"(?:^|\.)(?:send\w*|deliver\w*|mail)$")
BACKGROUND = re.compile(
    r"add_task|BackgroundTasks|\.delay\(|apply_async|enqueue|queue|setImmediate|nextTick|waitUntil"
)


def _message_findings(
    ctx: Context, flow: Flow, rule_id: str, pattern: re.Pattern[str]
) -> Finding | None:
    hits = [
        loc for code in flow.code for text, loc in caller_literals(code) if pattern.search(text)
    ]
    if not hits:
        return None
    locations = sorted(set(hits), key=lambda loc: (loc.file, loc.line))
    first = locations[0]
    return make_finding(
        rule_id,
        tag=Tag.CONFIRMED,
        locations=[*locations, flow.location],
        snippet=snippet(ctx.index.text(first.file), first.line),
        route=f"{flow.route.method} {flow.route.path}",
    )


@rule(
    "AUTH-ENUM-SIGNUP-MESSAGE",
    review="auth",
    severity="medium",
    exploitability="medium",
    owasp="A07",
)
def signup_message(ctx: Context) -> Iterator[Finding]:
    for flow in flows_of(ctx, "register"):
        finding = _message_findings(ctx, flow, "AUTH-ENUM-SIGNUP-MESSAGE", EXISTS)
        if finding:
            yield finding
        else:
            record_pass(
                ctx,
                4,
                Tag.INFERRED,
                "No response in the signup flow says the address is already registered",
                flow.location,
            )


@rule(
    "AUTH-ENUM-RESET-MESSAGE",
    review="auth",
    severity="medium",
    exploitability="medium",
    owasp="A07",
)
def reset_message(ctx: Context) -> Iterator[Finding]:
    for flow in flows_of(ctx, "forgot"):
        finding = _message_findings(ctx, flow, "AUTH-ENUM-RESET-MESSAGE", NOT_FOUND)
        if finding:
            yield finding
        else:
            record_pass(
                ctx,
                2,
                Tag.INFERRED,
                "No response in the reset request flow says the address is unknown",
                flow.location,
            )


@rule(
    "AUTH-ENUM-LOCKOUT-STATUS",
    review="auth",
    severity="medium",
    exploitability="medium",
    owasp="A07",
)
def lockout_status(ctx: Context) -> Iterator[Finding]:
    for flow in flows_of(ctx, "login"):
        hits = [loc for code in flow.code for loc in status_codes(code, (423,))]
        hits += [
            loc for code in flow.code for text, loc in caller_literals(code) if LOCKED.search(text)
        ]
        if not hits:
            continue
        locations = sorted(set(hits), key=lambda loc: (loc.file, loc.line))
        yield make_finding(
            "AUTH-ENUM-LOCKOUT-STATUS",
            tag=Tag.CONFIRMED,
            locations=[*locations, flow.location],
            snippet=snippet(ctx.index.text(locations[0].file), locations[0].line),
            route=f"{flow.route.method} {flow.route.path}",
        )


def _timing(ctx: Context, flow: Flow) -> Finding | None:
    if flow.kind == "login":
        for code in flow.code:
            exit_at = early_exit_before(code, PASSWORD_VERIFY)
            if exit_at and not has_dummy_hash(code):
                what = (
                    "The sign-in code returns as soon as no account matches, before any password "
                    "hash is checked, so unknown addresses answer measurably faster."
                )
                return _timing_finding(ctx, flow, exit_at, what, "Sign-in")
        return None
    for code in flow.code:
        exit_at = early_exit_before(code, SEND)
        sends = [line for name, line in call_names(code) if SEND.search(name)]
        if exit_at and sends and not BACKGROUND.search(code.text()):
            what = (
                "The reset request returns early when no account matches, and only real accounts "
                "wait for the email to be sent inside the request, so response time reveals which "
                "addresses are registered."
            )
            return _timing_finding(ctx, flow, exit_at, what, "Reset request")
    return None


def _timing_finding(ctx: Context, flow: Flow, exit_at, what: str, name: str) -> Finding:
    return make_finding(
        "AUTH-ENUM-TIMING",
        tag=Tag.INFERRED,
        locations=[exit_at, flow.location],
        snippet=snippet(ctx.index.text(exit_at.file), exit_at.line),
        route=f"{flow.route.method} {flow.route.path}",
        flow=name,
        what=what,
    )


@rule("AUTH-ENUM-TIMING", review="auth", severity="low", exploitability="low", owasp="A07")
def enumeration_timing(ctx: Context) -> Iterator[Finding]:
    for flow in flows_of(ctx, "login", "forgot"):
        finding = _timing(ctx, flow)
        if finding:
            yield finding
