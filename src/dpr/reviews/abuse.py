"""Review 7, abuse and bill guard: paid routes, limits, forms, CORS and error text."""

from __future__ import annotations

import re

import dpr.reviews.abuse_cors  # noqa: F401  (registers rules)
import dpr.reviews.abuse_limits  # noqa: F401  (registers rules)
import dpr.reviews.abuse_paid  # noqa: F401  (registers rules)
from dpr.model import Finding, Part, ReviewSection
from dpr.reviews.abuse_paid import is_limited
from dpr.reviews.access import PUBLIC, access
from dpr.reviews.paid import costs, paid_routes
from dpr.rules import Context

INTRO = (
    "Limits below are starting defaults, not measured traffic. Start from the real peak per user, "
    "roughly double it, and limit per signed-in user before per IP."
)
SNIPPETS = {
    "fastapi": (
        "```python\nlimiter = Limiter(key_func=user_or_ip, storage_uri=settings.redis_url,\n"
        '                  default_limits=["600/10minutes"])\n'
        "app.state.limiter = limiter\napp.add_middleware(SlowAPIMiddleware)\n\n"
        '@router.post("/generate")\n@limiter.limit("20/hour")\n'
        "async def generate(request: Request, user: CurrentUser): ...\n```\n\n"
        "Run the server with --forwarded-allow-ips set to the platform proxy so the IP key is "
        "the caller, and refuse to start without the shared store outside development."
    ),
    "next": (
        "```ts\nconst ratelimit = new Ratelimit({ redis: Redis.fromEnv(), "
        'limiter: Ratelimit.slidingWindow(20, "1 h") })\n'
        "const { success } = await ratelimit.limit(session.user.id)\n"
        'if (!success) return new Response("Too many requests", { status: 429 })\n```'
    ),
    "express": (
        "```js\napp.set('trust proxy', 1)\napp.use('/api/generate', rateLimit({ windowMs: 60 * 60 "
        "* 1000, limit: 20,\n  keyGenerator: (req) => req.user?.id ?? req.ip,\n"
        "  store: new RedisStore({ sendCommand: (...args) => redis.sendCommand(args) }) }))\n```"
    ),
    "django": (
        "```python\n@ratelimit(key='user_or_ip', rate='20/h', block=True)\n"
        "def generate(request): ...\n```\n\nSet CACHES to a shared Redis cache so every worker "
        "counts together."
    ),
    "flask": (
        "```python\nlimiter = Limiter(get_remote_address, app=app, storage_uri=REDIS_URL)\n\n"
        '@app.post("/generate")\n@limiter.limit("20 per hour")\ndef generate(): ...\n```'
    ),
}
ALERTS = (
    "- Rate of spend, not total: alert when paid calls in the last hour exceed 3 times the "
    "trailing 7-day hourly average.\n"
    "- Provider-side hard caps: set a monthly limit in every paid provider's dashboard; a cap is "
    "the only thing that stops the bill.\n"
    "- Signup rate anomaly: bot registration usually starts minutes before the abuse.\n"
    "- Error spike on paid routes: failures that still cost money are the worst case."
)


def _flag(path: str) -> str:
    return (re.sub(r"[^A-Z0-9]+", "_", path.upper()).strip("_") or "PAID_ROUTE") + "_ENABLED"


def _cost_rows(ctx: Context) -> tuple[tuple[str, ...], ...]:
    rows = []
    for paid in paid_routes(ctx):
        route = paid.route
        cost = costs().get(paid.sdk.category, {"note": "provider pricing"})
        rows.append(
            (
                f"{route.method} {route.path}",
                paid.sdk.name,
                cost["note"],
                "no" if access(ctx, route).level == PUBLIC else "yes",
                "yes" if is_limited(ctx, route) else "none found",
            )
        )
    for route in ctx.detection.routes:
        if route.is_public_form and access(ctx, route).level == PUBLIC and route.method != "GET":
            kind = "login" if re.search(r"(?i)log-?in|sign-?in", route.path) else "form"
            limited = "yes" if is_limited(ctx, route) else "none found"
            rows.append(
                (
                    f"{route.method} {route.path}",
                    "public form",
                    costs()[kind]["note"],
                    "no",
                    limited,
                )
            )
    return tuple(rows)


def _limit_rows(rows: tuple[tuple[str, ...], ...], ctx: Context) -> tuple[tuple[str, ...], ...]:
    by_route = {f"{p.route.method} {p.route.path}": p.sdk.category for p in paid_routes(ctx)}
    limits = []
    for endpoint, _calls, note, _auth, _limited in rows:
        if endpoint in by_route:
            key = by_route[endpoint]
        else:
            key = "login" if re.search(r"(?i)log-?in|sign-?in", endpoint) else "form"
        cost = costs().get(key, costs()["form"])
        limits.append(
            (
                endpoint,
                note,
                str(cost["per_user"]),
                str(cost["per_ip"]),
                cost["window"],
                "starting default, not measured traffic",
            )
        )
    return tuple(limits)


def _snippet(ctx: Context) -> str:
    for framework in ("fastapi", "next", "express", "django", "flask"):
        if framework in ctx.detection.frameworks:
            return SNIPPETS[framework]
    return "No supported server framework was detected, so no implementation snippet is given."


def run(ctx: Context) -> ReviewSection:
    return ReviewSection(
        "abuse", [Part("text", "How to read the limits", body=INTRO), Part("findings", "Guards")]
    )


def finish(ctx: Context, section: ReviewSection, findings: list[Finding]) -> None:
    rows = _cost_rows(ctx)
    position = next(i for i, p in enumerate(section.parts) if p.kind == "findings")
    added = [
        Part(
            "table",
            "Cost surface",
            ("Route", "Calls", "Cost per call", "Auth required", "Current limit"),
            rows,
        ),
        Part(
            "table",
            "Limits per endpoint",
            ("Endpoint", "Cost", "Per user", "Per IP", "Window", "Reasoning"),
            _limit_rows(rows, ctx),
        ),
        Part("text", "Implementation for this stack", body=_snippet(ctx)),
    ]
    section.parts[position:position] = added
    leaks = [f for f in findings if f.rule_id == "ABUSE-ERROR-LEAK"]
    cors = [f for f in findings if f.rule_id.startswith("ABUSE-CORS-")]
    lines = [
        f"- `{f.locations[0]}`: return a generic message with a request id; log the exception."
        for f in leaks
    ]
    cors_text = (
        f"{len(cors)} CORS finding(s) above. Allow only exact production and preview origins."
        if cors
        else "No wildcard, reflected or loose CORS origin was found."
    )
    body = cors_text + "\n\nError messages to rewrite:\n\n" + ("\n".join(lines) or "None found.")
    section.parts.append(Part("text", "CORS and error messages", body=body))
    switches = [
        f"- `{_flag(p.route.path)}` for {p.route.method} {p.route.path}" for p in paid_routes(ctx)
    ]
    kill = "\n\nKill switches, read on every request:\n\n" + "\n".join(switches) if switches else ""
    section.parts.append(Part("text", "Alerts and kill switches", body=ALERTS + kill))
