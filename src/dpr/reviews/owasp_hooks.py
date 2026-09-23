"""Review 5: provider callbacks with no caller check, and health or test routes that disclose
detail. Both apply to routes the classifier marks public."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Route, Tag
from dpr.parsing import pyast
from dpr.redact import snippet
from dpr.reviews.access import PUBLIC, access, unread_guard
from dpr.reviews.lookups_route import handler_functions
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule

CALLBACK_NAME = re.compile(
    r"(?i)webhook|callback|(?:^|[/_-])(?:hooks?|push|ipn|notify|notification|dlr)(?:$|[/_-])"
    r"|result|response|confirmation"
)
CHANGE_CALL = re.compile(
    r"\.(?:save|create|update|delete|bulk_create|bulk_update|get_or_create|update_or_create"
    r"|accept|decline|approve|reject|confirm|cancel|delay|apply_async)$"
    r"|\.(?:create|update|set|mark|process|record|save)_\w+$"
)
CALLER_CHECK = re.compile(
    r"(?i)hmac|signature|signed|compare_digest|verify|secret|token|api_?key|REMOTE_ADDR"
    r"|x[-_]forwarded|allowed_ips|allow_?list|white_?list|ip_address|authori[sz]ation"
    r"|HTTP_AUTH|shared_key|password"
)
DEBUG_NAME = re.compile(
    r"(?i)(?:^|[/_-])(?:readyz|healthz|livez|health|healthcheck|ping|debug|test|tests|version"
    r"|diagnostics?|serialization_error|env|info)(?:$|[/_-])"
)
DETAIL = re.compile(
    r"\b(?:str|repr)\(\s*(?:e|ex|exc|err|error|exception)\s*\)|traceback|format_exc"
    r"|\bsettings\.[A-Z]|os\.environ|os\.getenv|sys\.version|platform\.|__version__"
    r"|get_version\(|django\.VERSION"
)


def _public(ctx: Context) -> Iterator[tuple[Route, list[ast.AST]]]:
    seen = set()
    for route in ctx.detection.routes:
        if not isinstance(route.handler, ast.AST) or is_test(route.file):
            continue
        if access(ctx, route).level != PUBLIC or (route.file, route.path) in seen:
            continue
        seen.add((route.file, route.path))
        yield route, handler_functions(route.handler)


def _named(route: Route, pattern: re.Pattern) -> bool:
    return bool(pattern.search(route.path) or pattern.search(getattr(route.handler, "name", "")))


def _decorators(route: Route) -> str:
    return " ".join(ast.unparse(d) for d in getattr(route.handler, "decorator_list", []))


def reachable(fn: ast.AST) -> list[ast.stmt]:
    """The handler body up to its first top-level return or raise; later code never runs."""
    body = []
    for stmt in fn.body:
        body.append(stmt)
        if isinstance(stmt, ast.Return | ast.Raise):
            break
    return body


def unsigned_callbacks(ctx: Context) -> list[tuple[Route, ast.Call]]:
    """Public callback-named routes that write data with no caller check, with the write."""
    if "unsigned_callbacks" not in ctx.facts:
        found = []
        for route, fns in _public(ctx):
            if not _named(route, CALLBACK_NAME):
                continue
            body = [stmt for fn in fns for stmt in reachable(fn)]
            text = " ".join(ast.unparse(stmt) for stmt in body) + " " + _decorators(route)
            if CALLER_CHECK.search(text):
                continue
            change = next(
                (
                    call
                    for stmt in body
                    for call in ast.walk(stmt)
                    if isinstance(call, ast.Call)
                    and CHANGE_CALL.search(pyast.dotted(call.func) or "")
                ),
                None,
            )
            if change is not None:
                found.append((route, change))
        ctx.facts["unsigned_callbacks"] = found
    return ctx.facts["unsigned_callbacks"]


def callback_routes(ctx: Context) -> set[Route]:
    return {route for route, _change in unsigned_callbacks(ctx)}


@rule(
    "OWASP-A01-UNSIGNED-CALLBACK",
    review="owasp",
    severity="high",
    exploitability="medium",
    owasp="A01",
)
def unsigned_callback(ctx: Context) -> Iterator[Finding]:
    for route, change in unsigned_callbacks(ctx):
        proof = unread_guard(access(ctx, route)) or (
            "Confirm the web server or proxy does not already limit this path to the "
            "provider's addresses."
        )
        yield make_finding(
            "OWASP-A01-UNSIGNED-CALLBACK",
            tag=Tag.INFERRED,
            locations=[Location(route.file, route.line), Location(route.file, change.lineno)],
            snippet=snippet(ctx.index.text(route.file), change.lineno),
            proof_needed=proof,
            method=route.method,
            path=route.path,
        )


def _static(node: ast.Return) -> bool:
    """A return of a literal or a response built only from literals, such as "OK"."""
    value = node.value
    if value is None or isinstance(value, ast.Constant):
        return True
    parts = [*value.args, *(k.value for k in value.keywords)] if isinstance(value, ast.Call) else []
    return isinstance(value, ast.Call) and all(isinstance(p, ast.Constant) for p in parts)


@rule(
    "OWASP-A05-DEBUG-ENDPOINT",
    review="owasp",
    severity="low",
    exploitability="low",
    owasp="A05",
)
def debug_endpoint(ctx: Context) -> Iterator[Finding]:
    for route, fns in _public(ctx):
        if not _named(route, DEBUG_NAME):
            continue
        for fn in fns:
            returns = [n for n in ast.walk(fn) if isinstance(n, ast.Return)]
            detail = next(
                (n for n in ast.walk(fn) if hasattr(n, "lineno") and DETAIL.search(_line(n))),
                None,
            )
            if detail is None or all(_static(r) for r in returns):
                continue
            proof = unread_guard(access(ctx, route))
            yield make_finding(
                "OWASP-A05-DEBUG-ENDPOINT",
                tag=Tag.INFERRED if proof else Tag.CONFIRMED,
                locations=[Location(route.file, detail.lineno)],
                snippet=snippet(ctx.index.text(route.file), detail.lineno),
                proof_needed=proof,
                method=route.method,
                path=route.path,
            )
            break


def _line(node: ast.AST) -> str:
    return ast.unparse(node) if isinstance(node, ast.expr) else ""
