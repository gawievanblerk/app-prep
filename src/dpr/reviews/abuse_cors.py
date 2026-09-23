"""Review 7, abuse: CORS that trusts any origin, loose origin patterns, error text in responses."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Tag
from dpr.parsing import jsts, pyast
from dpr.parsing.routes_js import response_calls
from dpr.redact import snippet
from dpr.reviews.access import PUBLIC, access
from dpr.reviews.leaks_code import sent
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule
from dpr.walk import line_of

JS_CREDENTIALS = re.compile(r"credentials\s*:\s*true|Allow-Credentials['\"]?\s*[,:]\s*['\"]true")
PY_CREDENTIALS = re.compile(
    r"allow_credentials\s*=\s*True|CORS_ALLOW_CREDENTIALS\s*=\s*True|supports_credentials\s*=\s*True"
)
ACAO_WILDCARD = re.compile(r"""Access-Control-Allow-Origin['"]?\s*[,:]\s*['"]\*['"]""", re.I)
ACAO_REFLECT = re.compile(
    r"""Access-Control-Allow-Origin['"]?\s*[,:]\s*(?:req|request)\.(?:headers\.origin|headers\.get\(\s*['"]origin)""",
    re.I,
)
BROAD_EXCEPTIONS = {None, "Exception", "BaseException"}
RESPONSE_CALLS = re.compile(
    r"(?:\w+\.)*(?:HTTPException|JSONResponse|Response|PlainTextResponse|HTMLResponse|JsonResponse"
    r"|HttpResponse|jsonify|make_response|abort)"
)
TASK_DECORATOR = re.compile(r"(?:^|\.)(?:shared_task|task|periodic_task|actor)$")
JS_ERROR_TEXT = re.compile(r"\b(?:err|error|e|ex|exception)\.(?:message|stack)\b")


def _has_auth_routes(ctx: Context) -> bool:
    return any(access(ctx, r).level != PUBLIC for r in ctx.detection.routes)


def _cors(
    ctx: Context, rule_id: str, rel: str, line: int, severity: str | None, what: str
) -> Finding:
    return make_finding(
        rule_id,
        tag=Tag.CONFIRMED,
        locations=[Location(rel, line)],
        severity=severity,
        snippet=snippet(ctx.index.text(rel), line),
        what=what,
    )


def _js_cors(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.js_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel) or not re.search(r"cors|Access-Control-Allow-Origin", text, re.I):
            continue
        credentials = bool(JS_CREDENTIALS.search(text))
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for call in jsts.calls(tree, r"cors"):
                args = jsts.arguments(call)
                line = jsts.line(tree, call)
                origin = jsts.object_pairs(args[0]).get("origin") if args else None
                value = jsts.node_text(origin) if origin is not None else None
                if not args or value in ("'*'", '"*"'):
                    yield _cors(
                        ctx,
                        "ABUSE-CORS-WILDCARD",
                        entry.rel,
                        line,
                        None,
                        "cors() allows every origin.",
                    )
                elif value == "true":
                    severity = "critical" if credentials else "high"
                    what = "cors() reflects any request origin back as allowed."
                    yield _cors(ctx, "ABUSE-CORS-REFLECT", entry.rel, line, severity, what)
                elif origin is not None and origin.type in jsts.FUNCTION_TYPES:
                    body = jsts.node_text(origin)
                    if re.search(r"\(\s*null\s*,\s*true\s*\)", body) and not re.search(
                        r"includes\(|indexOf\(|\.test\(|===|allow", body
                    ):
                        severity = "critical" if credentials else "high"
                        what = (
                            "The origin callback approves every origin without an allowlist check."
                        )
                        yield _cors(ctx, "ABUSE-CORS-REFLECT", entry.rel, line, severity, what)
                elif origin is not None and origin.type == "regex":
                    pattern = jsts.node_text(origin.child_by_field_name("pattern"))
                    if not (pattern.startswith("^") and pattern.endswith("$")):
                        what = f"The origin pattern /{pattern}/ is not anchored with ^ and $."
                        yield _cors(ctx, "ABUSE-CORS-LOOSE-REGEX", entry.rel, line, None, what)
        for match in ACAO_WILDCARD.finditer(text):
            what = "Access-Control-Allow-Origin is set to *."
            yield _cors(
                ctx, "ABUSE-CORS-WILDCARD", entry.rel, line_of(text, match.start()), None, what
            )
        for match in ACAO_REFLECT.finditer(text):
            severity = "critical" if credentials else "high"
            what = "Access-Control-Allow-Origin is copied from the request Origin header."
            line = line_of(text, match.start())
            yield _cors(ctx, "ABUSE-CORS-REFLECT", entry.rel, line, severity, what)


def _py_cors(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel) or not re.search(r"CORS|allow_origin", text):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        if tree is None:
            continue
        credentials = bool(PY_CREDENTIALS.search(text))
        for stmt in tree.body:
            if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name):
                name = stmt.targets[0].id
                if (
                    name in ("CORS_ALLOW_ALL_ORIGINS", "CORS_ORIGIN_ALLOW_ALL")
                    and pyast.constant(stmt.value) is True
                ):
                    what = f"{name} = True allows every origin."
                    yield _cors(ctx, "ABUSE-CORS-WILDCARD", entry.rel, stmt.lineno, None, what)
                if name == "CORS_ALLOWED_ORIGIN_REGEXES" and isinstance(
                    stmt.value, ast.List | ast.Tuple
                ):
                    for item in stmt.value.elts:
                        yield from _regex(ctx, entry.rel, item)
        for call in pyast.calls(tree, r"(?:\w+\.)*(?:add_middleware|CORSMiddleware|CORS)"):
            origins = pyast.kwarg(call, "allow_origins") or pyast.kwarg(call, "origins")
            if origins is not None and "'*'" in ast.unparse(origins):
                what = "The CORS middleware allows every origin."
                yield _cors(ctx, "ABUSE-CORS-WILDCARD", entry.rel, origins.lineno, None, what)
            regex = pyast.kwarg(call, "allow_origin_regex")
            if regex is not None and pyast.constant(regex, "") in (".*", "^.*$", ".+"):
                severity = "critical" if credentials else "high"
                what = (
                    "allow_origin_regex matches every origin, so any site is reflected as allowed."
                )
                yield _cors(ctx, "ABUSE-CORS-REFLECT", entry.rel, regex.lineno, severity, what)
            elif regex is not None:
                yield from _regex(ctx, entry.rel, regex)


def _regex(ctx: Context, rel: str, node: ast.AST) -> Iterator[Finding]:
    pattern = pyast.constant(node, None)
    if isinstance(pattern, str) and not (pattern.startswith("^") and pattern.endswith("$")):
        what = f"The origin pattern {pattern} is not anchored with ^ and $."
        yield _cors(ctx, "ABUSE-CORS-LOOSE-REGEX", rel, node.lineno, None, what)


def _cors_findings(ctx: Context) -> list[Finding]:
    if "cors_findings" not in ctx.facts:
        ctx.facts["cors_findings"] = [*_js_cors(ctx), *_py_cors(ctx)]
    return ctx.facts["cors_findings"]


@rule("ABUSE-CORS-WILDCARD", review="abuse", severity="high", exploitability="medium", owasp="A05")
def cors_wildcard(ctx: Context) -> Iterator[Finding]:
    if _has_auth_routes(ctx):
        yield from (f for f in _cors_findings(ctx) if f.rule_id == "ABUSE-CORS-WILDCARD")


@rule("ABUSE-CORS-REFLECT", review="abuse", severity="high", exploitability="high", owasp="A05")
def cors_reflect(ctx: Context) -> Iterator[Finding]:
    yield from (f for f in _cors_findings(ctx) if f.rule_id == "ABUSE-CORS-REFLECT")


@rule(
    "ABUSE-CORS-LOOSE-REGEX",
    review="abuse",
    severity="medium",
    exploitability="medium",
    owasp="A05",
)
def cors_loose_regex(ctx: Context) -> Iterator[Finding]:
    yield from (f for f in _cors_findings(ctx) if f.rule_id == "ABUSE-CORS-LOOSE-REGEX")


def _error_names(handler: ast.ExceptHandler) -> set[str]:
    names = {handler.name} if handler.name else set()
    for node in ast.walk(handler):
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            if pyast.names_in(node.value) & names or "format_exc" in ast.unparse(node.value):
                names.add(node.targets[0].id)
    return names


def _leaks_in(fn: ast.AST) -> Iterator[tuple[int, bool]]:
    """Lines where a catch-all exception's text is returned (True) or put in a response call
    (False), one per except clause."""
    for handler in [n for n in ast.walk(fn) if isinstance(n, ast.ExceptHandler)]:
        kind = pyast.dotted(handler.type) if handler.type is not None else None
        if kind not in BROAD_EXCEPTIONS:
            continue
        names = _error_names(handler)
        for node in ast.walk(fn):
            if getattr(node, "lineno", 0) < handler.lineno:
                continue
            if isinstance(node, ast.Return) and node.value is not None:
                value = node.value
            elif isinstance(node, ast.Call) and RESPONSE_CALLS.fullmatch(
                pyast.dotted(node.func) or ""
            ):
                value = node
            else:
                continue
            text = ast.unparse(value)
            if pyast.names_in(value) & names or "format_exc()" in text:
                yield node.lineno, isinstance(node, ast.Return)
                break


def _task(fn: ast.AST) -> bool:
    return any(
        TASK_DECORATOR.search(pyast.dotted(d.func if isinstance(d, ast.Call) else d) or "")
        for d in fn.decorator_list
    )


def _returned_to_client(fn: ast.AST, handlers: list[ast.AST]) -> bool:
    """A handler in the same file calls `fn` and sends its result in the response."""
    for handler in handlers:
        for call in ast.walk(handler):
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name | ast.Attribute):
                name = call.func.id if isinstance(call.func, ast.Name) else call.func.attr
                if name == fn.name and sent(handler, call):
                    return True
    return False


def _py_error_leaks(tree: ast.Module, handlers: list[ast.AST]) -> Iterator[int]:
    """Error text that reaches an HTTP response: put in a response call, returned by a route
    handler, or returned by a helper whose result a handler sends. Celery task results and
    other internal return values are not responses."""
    for fn in pyast.functions(tree):
        if _task(fn):
            continue
        for line, returned in _leaks_in(fn):
            if not returned or fn in handlers or _returned_to_client(fn, handlers):
                yield line


@rule("ABUSE-ERROR-LEAK", review="abuse", severity="medium", exploitability="medium", owasp="A05")
def error_leak(ctx: Context) -> Iterator[Finding]:
    route_files = {r.file for r in ctx.detection.routes}
    for entry in ctx.index.py_files:
        if entry.rel not in route_files or is_test(entry.rel):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        handlers = [r.handler for r in ctx.detection.routes if r.file == entry.rel]
        for line in sorted(set(_py_error_leaks(tree, handlers))) if tree else []:
            yield make_finding(
                "ABUSE-ERROR-LEAK",
                tag=Tag.CONFIRMED,
                locations=[Location(entry.rel, line)],
                snippet=snippet(ctx.index.text(entry.rel), line),
            )
    for entry in ctx.index.js_files:
        if entry.rel not in route_files or is_test(entry.rel):
            continue
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for clause in jsts.walk(tree.root, {"catch_clause"}):
                body = clause.child_by_field_name("body")
                for call in response_calls(body):
                    if JS_ERROR_TEXT.search(jsts.node_text(call)):
                        line = jsts.line(tree, call)
                        yield make_finding(
                            "ABUSE-ERROR-LEAK",
                            tag=Tag.CONFIRMED,
                            locations=[Location(entry.rel, line)],
                            snippet=snippet(ctx.index.text(entry.rel), line),
                        )
                        break
