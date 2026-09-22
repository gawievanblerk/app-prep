"""Review 6, leak hunt: the places searched, including what was reviewed and found clean."""

from __future__ import annotations

from dpr.model import Finding, Part
from dpr.redact import is_secret_name, public_prefix
from dpr.reviews.leaks_creds import GATE_WORDS
from dpr.rules import Context


def _public_variables(ctx: Context) -> str:
    rows = []
    for env in ctx.detection.env_vars:
        prefix = public_prefix(env.name)
        if not prefix:
            continue
        if is_secret_name(env.name):
            verdict = "secret word in a browser variable (LEAK-PUBLIC-SECRET)"
        elif GATE_WORDS.search(env.name[len(prefix) :]):
            verdict = "access gate key shipped to browsers (LEAK-PUBLIC-GATE-KEY)"
        else:
            verdict = "publishable"
        where = env.locations[0] if env.locations else "no reference"
        rows.append(f"- `{env.name}`: {verdict} (`{where}`)")
    if not rows:
        return "No browser-exposed (public-prefixed) environment variables were found."
    return "\n".join(rows)


def _count(findings: list[Finding], rule_id: str, empty: str, some: str) -> str:
    matching = [f for f in findings if f.rule_id == rule_id]
    return some.format(n=len(matching)) if matching else empty


def summary_parts(ctx: Context, findings: list[Finding]) -> list[Part]:
    history = [
        _count(
            findings,
            "LEAK-ENV-TRACKED",
            "No real .env file is tracked by git.",
            "{n} tracked .env file(s), listed below.",
        ),
        _count(
            findings,
            "LEAK-ENV-IN-HISTORY",
            "No real .env file appears in git history.",
            "{n} .env file(s) in git history, listed below.",
        ),
        _count(
            findings,
            "LEAK-HARDCODED-KEY",
            "No key pattern matched in source files.",
            "{n} key pattern match(es) in source, listed below.",
        ),
        _count(
            findings,
            "LEAK-KEY-IN-BUILD",
            "No key pattern matched in build output.",
            "{n} key pattern match(es) in build output, listed below.",
        ),
    ]
    if not ctx.detection.git.is_repo:
        history[:2] = ["Not a git repository, so tracked files and history were not checked."]
    responses = _count(
        findings,
        "LEAK-BROAD-RESPONSE",
        "No route returns a whole ORM record or select * result.",
        "{n} route response(s) return whole records, listed below.",
    )
    logs = _count(
        findings,
        "LEAK-LOGGED-PII",
        "No log call writes a request, user, token or personal value.",
        "{n} file(s) log personal data, listed below.",
    )
    return [
        Part("text", "Place 1: public variables reviewed", body=_public_variables(ctx)),
        Part(
            "text",
            "Place 1: keys, env files and git history",
            body="\n".join(f"- {h}" for h in history),
        ),
        Part("text", "Place 2: over-broad responses", body=responses),
        Part("text", "Place 3: logs", body=logs),
    ]
