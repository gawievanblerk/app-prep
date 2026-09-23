"""Review 5, OWASP A01 and A04: signed-in views that accept cross-site requests.

`OWASP-A01-CSRF-EXEMPT`: a Django view that relies on the session cookie and turns off CSRF
protection with `@csrf_exempt`. `OWASP-A04-GET-SIDE-EFFECT`: a signed-in route that answers a
plain GET and starts a job, sends messages in a loop, deletes records or writes in bulk.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Route, Tag
from dpr.parsing import pyast
from dpr.parsing.pyenv import module_assignments
from dpr.redact import snippet
from dpr.reviews.access import PUBLIC, access
from dpr.reviews.app_code import app_file, decorator_names, own_nodes
from dpr.reviews.request_values import request_names
from dpr.reviews.settings_files import production_file, settings_module
from dpr.rules import Context, make_finding, rule

SESSION_GUARD = re.compile(r"login_required|user_passes_test|permission_required|staff_member")
TOKEN_AUTH = re.compile(
    r"(?i)HTTP_AUTHORIZATION|authorization|api_?key|signature|hmac|compare_digest|\btoken\b"
    r"|X-Hub|X-Signature|verify_request"
)
CHANGE = re.compile(
    r"\.(?:save|delete|create|update|bulk_create|bulk_update|update_or_create|get_or_create"
    r"|delay|apply_async|set_password)\("
    r"|\b(?:create|update|delete|add|remove|send|process|perform|approve|cancel|activate"
    r"|deactivate|submit|reverse|refund|pay)_\w*\("
)
MONEY = re.compile(
    r"(?i)payment|premium|refund|debit|payout|persal|invoice|commission|amount|payroll|qlink"
)
METHOD_CHECK = re.compile(r"\.method\b|\.is_valid\(|require_POST|require_http_methods")
GET_ONLY = re.compile(r"require_GET|require_safe")
JOB = re.compile(
    r"\.(?:delay|apply_async|submit)$|(?:^|\.)(?:Thread|Process|start_new_thread|run_in_background)$"
)
SEND = re.compile(r"(?i)(?:^|\.)(?:send\w*|\w*_sms\w*|\w*sms_\w*|\w*_email|EmailMessage)$")
BULK_QUERY = re.compile(r"\.objects\.(?:filter|all|exclude)\(|\.filter\(|\.all\(\)|\.exclude\(")
WRITE = re.compile(r"\.(?:save|delete|create|update|bulk_create|bulk_update)$")
ACTIONS = {
    "job": "starts a background job",
    "send": "sends messages in a loop",
    "delete": "deletes records",
    "bulk": "writes records in bulk",
}


def samesite_none(ctx: Context) -> Location | None:
    """Where a production settings module sets the session or CSRF cookie to SameSite=None."""
    key = ("samesite-none", "")
    if key not in ctx.index.cache:
        found = None
        for entry in ctx.index.py_files:
            text = ctx.index.text(entry.rel)
            if "SAMESITE" not in text or not settings_module(entry.rel, text):
                continue
            tree = (
                pyast.parse_file(ctx.index, entry.rel) if production_file(ctx, entry.rel) else None
            )
            for name, value, line in module_assignments(tree) if tree else []:
                if name in ("SESSION_COOKIE_SAMESITE", "CSRF_COOKIE_SAMESITE"):
                    if str(pyast.constant(value, "")).lower() == "none":
                        found = found or Location(entry.rel, line)
        ctx.index.cache[key] = found
    return ctx.index.cache[key]


def _exempt(node: ast.AST) -> int | None:
    """The line of `@csrf_exempt` on a view function or class (or its dispatch method)."""
    holders = [node]
    if isinstance(node, ast.ClassDef):
        holders += [i for i in node.body if isinstance(i, ast.FunctionDef | ast.AsyncFunctionDef)]
    for holder in holders:
        for dec, name in zip(holder.decorator_list, decorator_names(holder), strict=False):
            if "csrf_exempt" in ast.unparse(dec) or name.endswith("csrf_exempt"):
                return dec.lineno
    return None


def _routes_by_handler(ctx: Context) -> dict[tuple[str, int], Route]:
    return {
        (r.file, r.handler.lineno): r
        for r in ctx.detection.routes
        if isinstance(r.handler, ast.AST) and r.framework in ("django", "flask")
    }


def _exempt_views(ctx: Context) -> Iterator[tuple[str, ast.AST, int]]:
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if "csrf_exempt" not in text or not app_file(ctx, entry.rel):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for node in tree.body if tree else []:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                line = _exempt(node)
                if line is not None:
                    yield entry.rel, node, line


def _session_view(ctx: Context, rel: str, node: ast.AST, routes: dict) -> bool:
    """The view is reached with the session cookie: a sign-in guard and no token check."""
    if TOKEN_AUTH.search(ast.unparse(node)):
        return False
    route = routes.get((rel, node.lineno))
    if route is not None:
        return access(ctx, route).level != PUBLIC
    return any(SESSION_GUARD.search(name) for name in decorator_names(node))


@rule(
    "OWASP-A01-CSRF-EXEMPT", review="owasp", severity="medium", exploitability="medium", owasp="A01"
)
def csrf_exempt_views(ctx: Context) -> Iterator[Finding]:
    routes = _routes_by_handler(ctx)
    none = samesite_none(ctx)
    by_file: dict[str, list[tuple[ast.AST, int]]] = {}
    for rel, node, line in _exempt_views(ctx):
        if _session_view(ctx, rel, node, routes):
            by_file.setdefault(rel, []).append((node, line))
    for rel, views in by_file.items():
        changing = [(n, line) for n, line in views if CHANGE.search(ast.unparse(n))]
        money = [n.name for n, _ in changing if MONEY.search(ast.unparse(n))]
        severity = "low" if not changing else ("high" if none else "medium")
        names = ", ".join(n.name for n, _ in (changing or views))
        cookie = (
            f" Production sets the session or CSRF cookie to SameSite=None ({none}), so the "
            "browser sends the session with requests other sites start."
            if none
            else ""
        )
        change = (
            f" {len(changing)} of them change data ({names})"
            + (f"; {', '.join(money)} move money or payroll records" if money else "")
            + "."
            if changing
            else " None of them visibly changes data."
        )
        ordered = changing + [v for v in views if v not in changing]
        yield make_finding(
            "OWASP-A01-CSRF-EXEMPT",
            tag=Tag.CONFIRMED,
            locations=[Location(rel, line) for _, line in ordered]
            + ([none] if none and changing else []),
            snippet=snippet(ctx.index.text(rel), ordered[0][1]),
            severity=severity,
            exploitability="high" if none and changing else None,
            count=len(views),
            change=change,
            cookie=cookie,
        )


def _in_loop(fn: ast.AST) -> set[int]:
    """Ids of calls made inside a for or while loop of the function."""
    inside = set()
    for node in own_nodes(fn):
        if isinstance(node, ast.For | ast.While | ast.AsyncFor | ast.comprehension):
            inside |= {id(n) for n in ast.walk(node) if isinstance(n, ast.Call)}
    return inside


def _querysets(fn: ast.AST) -> set[str]:
    names = set()
    for node in own_nodes(fn):
        if isinstance(node, ast.Assign) and BULK_QUERY.search(ast.unparse(node.value)):
            names |= {t.id for t in node.targets if isinstance(t, ast.Name)}
    return names


def side_effects(fn: ast.AST) -> dict[str, int]:
    """Jobs, sends in a loop, deletes and bulk writes the function makes itself."""
    found: dict[str, int] = {}
    looped = _in_loop(fn)
    querysets = _querysets(fn)
    for call in sorted(
        (n for n in own_nodes(fn) if isinstance(n, ast.Call)), key=lambda n: n.lineno
    ):
        name = pyast.dotted(call.func) or ""
        receiver = ast.unparse(call.func.value) if isinstance(call.func, ast.Attribute) else ""
        if JOB.search(name):
            found.setdefault("job", call.lineno)
        elif SEND.search(name) and id(call) in looped:
            found.setdefault("send", call.lineno)
        elif name.endswith(".delete"):
            found.setdefault("delete", call.lineno)
        elif name.endswith((".bulk_create", ".bulk_update")) or (
            WRITE.search(name)
            and (id(call) in looped or BULK_QUERY.search(receiver) or receiver in querysets)
            and not name.endswith(".save")
        ):
            found.setdefault("bulk", call.lineno)
        elif name.endswith(".save") and id(call) in looped:
            found.setdefault("bulk", call.lineno)
    return found


def _reads_body(fn: ast.AST) -> bool:
    """The handler reads a form, files or a body, so it serves a POST flow."""
    names = "|".join(re.escape(n) for n in request_names(fn, True))
    return bool(re.search(rf"\b(?:{names})\.(?:POST|FILES|body)\b", ast.unparse(fn)))


def _method_free(fn: ast.AST) -> bool:
    return not METHOD_CHECK.search(ast.unparse(fn)) and not _reads_body(fn)


def _get_handlers(route: Route) -> list[ast.AST]:
    handler = route.handler
    if isinstance(handler, ast.FunctionDef | ast.AsyncFunctionDef):
        names = decorator_names(handler)
        if any(GET_ONLY.search(n) for n in names):
            return [handler]
        if route.framework == "flask" and route.method != "GET":
            return []
        return [handler] if _method_free(handler) else []
    if isinstance(handler, ast.ClassDef) and route.framework == "django":
        return [
            item
            for item in handler.body
            if isinstance(item, ast.FunctionDef) and item.name == "get" and _method_free(item)
        ]
    return []


@rule(
    "OWASP-A04-GET-SIDE-EFFECT",
    review="owasp",
    severity="medium",
    exploitability="medium",
    owasp="A04",
)
def get_side_effect(ctx: Context) -> Iterator[Finding]:
    seen = set()
    deletes: dict[str, list[tuple[Route, int]]] = {}
    for route in ctx.detection.routes:
        if route.framework not in ("django", "flask") or not app_file(ctx, route.file):
            continue
        handlers = _get_handlers(route) if isinstance(route.handler, ast.AST) else []
        effects = {k: v for fn in handlers for k, v in side_effects(fn).items()}
        if not effects or (route.file, route.line) in seen:
            continue
        if access(ctx, route).level == PUBLIC:
            continue  # public writes and jobs belong to OWASP-A01-PUBLIC-SENSITIVE
        seen.add((route.file, route.line))
        kinds = [k for k in ACTIONS if k in effects]
        if kinds == ["delete"]:
            deletes.setdefault(route.file, []).append((route, effects["delete"]))
            continue
        yield make_finding(
            "OWASP-A04-GET-SIDE-EFFECT",
            tag=Tag.CONFIRMED,
            locations=[Location(route.file, effects[kinds[0]]), Location(route.file, route.line)],
            snippet=snippet(ctx.index.text(route.file), effects[kinds[0]]),
            path=route.path,
            action=ACTIONS[kinds[0]],
            actions="; ".join(ACTIONS[k] for k in kinds),
        )
    for rel, items in deletes.items():
        paths = [route.path for route, _ in items]
        others = f" and {len(paths) - 1} other route(s)" if len(paths) > 1 else ""
        yield make_finding(
            "OWASP-A04-GET-SIDE-EFFECT",
            tag=Tag.CONFIRMED,
            locations=[Location(rel, line) for _, line in items],
            snippet=snippet(ctx.index.text(rel), items[0][1]),
            severity="low",
            detail=(
                f"These signed-in views delete a record on a plain GET with no method check "
                f"({', '.join(paths)}). Links, image tags, link previews and prefetching send "
                "GET requests, and CSRF protection does not cover GET."
            ),
            path=paths[0] + others,
            action="deletes records" if not others else "delete records",
            actions="deletes a record",
        )
