"""Review 7, abuse and bill guard: paid routes, limits, forms, CORS and error text."""

from __future__ import annotations

import re

import dpr.reviews.abuse_bulk  # noqa: F401  (registers rules)
import dpr.reviews.abuse_cors  # noqa: F401  (registers rules)
import dpr.reviews.abuse_limits  # noqa: F401  (registers rules)
import dpr.reviews.abuse_paid  # noqa: F401  (registers rules)
import dpr.reviews.abuse_roles  # noqa: F401  (registers rules)
from dpr.model import Finding, Part, ReviewSection, Route
from dpr.reviews.abuse_paid import is_limited
from dpr.reviews.access import PUBLIC, access
from dpr.reviews.cost_trace import app_label, auth_label, cost_rows
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


def _form_kind(route) -> str:
    return "login" if re.search(r"(?i)log-?in|sign-?in", route.path) else "form"


def _surface(ctx: Context) -> list[tuple[str, Route, list[str], list[str]]]:
    """(app, route, calls, cost categories) for traced routes, paid routes and public forms."""
    rows: dict[tuple[str, str, str], tuple[str, Route, list[str], list[str]]] = {}
    for row in cost_rows(ctx):
        key = (row.app, row.route.method, row.route.path)
        rows[key] = (row.app, row.route, list(row.calls), list(row.categories))
    for paid in paid_routes(ctx):
        key = (app_label(ctx, paid.route.file), paid.route.method, paid.route.path)
        entry = rows.setdefault(key, (key[0], paid.route, [], []))
        if paid.sdk.name not in entry[2]:
            entry[2].append(paid.sdk.name)
            entry[3].append(paid.sdk.category)
    for route in ctx.detection.routes:
        if route.is_public_form and access(ctx, route).level == PUBLIC and route.method != "GET":
            key = (app_label(ctx, route.file), route.method, route.path)
            entry = rows.setdefault(key, (key[0], route, [], []))
            entry[2].append("public form")
            entry[3].append(_form_kind(route))
    return list(rows.values())


def _note(category: str) -> str:
    return costs().get(category, {"note": "provider pricing"})["note"]


def _cost_rows(ctx: Context) -> tuple[tuple[str, ...], tuple[tuple[str, ...], ...]]:
    surface = _surface(ctx)
    multi = len({app for app, _, _, _ in surface}) > 1
    header = ("Route", "Calls", "Cost per call", "Auth required", "Current limit")
    rows = []
    for app, route, calls, categories in surface:
        row = (
            f"{route.method} {route.path}",
            ", ".join(calls),
            "; ".join(dict.fromkeys(_note(c) for c in categories)),
            auth_label(ctx, route),
            "yes" if is_limited(ctx, route) else "none found",
        )
        rows.append((app, *row) if multi else row)
    return (("App", *header) if multi else header), tuple(rows)


def _minutes(window: str) -> float:
    amount, unit = window.split(" ", 1)
    scale = {"min": 1, "h": 60, "day": 1440}
    return float(amount) * scale.get(unit.rstrip("s"), 1)


def _strictest(categories: list[str]) -> tuple[str, int, int, str]:
    """Per-user and per-IP are the lowest across all categories; the note and window come from
    whichever category gave the strictest per-user value. On a tie the longer window wins: the
    same count over a longer window is the lower rate."""
    scored = [costs().get(c, costs()["form"]) for c in categories]
    per_user = min(cost["per_user"] for cost in scored)
    per_ip = min(cost["per_ip"] for cost in scored)
    strictest = max(
        (c for c in categories if costs().get(c, costs()["form"])["per_user"] == per_user),
        key=lambda c: _minutes(costs().get(c, costs()["form"])["window"]),
    )
    return strictest, per_user, per_ip, costs().get(strictest, costs()["form"])["window"]


def _limit_rows(ctx: Context) -> tuple[tuple[str, ...], ...]:
    limits = []
    for app, route, _calls, categories in _surface(ctx):
        category, per_user, per_ip, window = _strictest(categories)
        endpoint = f"{route.method} {route.path}"
        limits.append(
            (
                endpoint if app == "." else f"{app}: {endpoint}",
                _note(category),
                str(per_user),
                str(per_ip),
                window,
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
    header, rows = _cost_rows(ctx)
    position = next(i for i, p in enumerate(section.parts) if p.kind == "findings")
    added = [
        Part("table", "Cost surface", header, rows),
        Part(
            "table",
            "Limits per endpoint",
            ("Endpoint", "Cost", "Per user", "Per IP", "Window", "Reasoning"),
            _limit_rows(ctx),
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
