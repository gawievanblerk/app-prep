"""Review 7, abuse: limiters that do not hold across workers or proxies, and unbounded uploads."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Tag
from dpr.parsing import jsts, pyast
from dpr.redact import snippet
from dpr.reviews.baseline_accounts import START_FILES
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule
from dpr.walk import line_of

WORKERS = re.compile(
    r"(?:--workers|-w)[ =](\d+)|WEB_CONCURRENCY=(\d+)|^\s*workers\s*=\s*(\d+)"
    r"|replicas:\s*(\d+)|-i\s+(max|\d+)|instances:\s*(max|\d+)",
    re.MULTILINE,
)
PROXY_TRUST = re.compile(
    r"forwarded-allow-ips|FORWARDED_ALLOW_IPS|ProxyHeadersMiddleware|ProxyFix|trust proxy"
    r"|trustProxy|get_ipaddr|x-forwarded-for",
    re.IGNORECASE,
)
PY_LIMITER = re.compile(r"(?:\w+\.)*Limiter")
COUNTER_NAME = re.compile(r"(?i)rate|limit|attempt|hits|count|bucket")
UPLOAD_READ = re.compile(r"(?:\w+)\.read")


def multi_process(ctx: Context, near: str = "") -> Location | None:
    """Evidence that more than one process or instance serves requests, closest to `near`."""
    if ctx.detection.serverless:
        return Location(ctx.detection.hosting[0] if ctx.detection.hosting else ".", 1)
    names = (*START_FILES, "gunicorn.conf.py", "*.yaml", "*.yml", "ecosystem.config.js")
    found = []
    for entry in ctx.index.named(*names):
        text = ctx.index.text(entry.rel)
        for match in WORKERS.finditer(text):
            value = next(g for g in match.groups() if g)
            if value == "max" or int(value) > 1:
                found.append(Location(entry.rel, line_of(text, match.start())))
                break
    if not found:
        return None
    return max(found, key=lambda loc: len(_common(loc.file, near)))


def _common(a: str, b: str) -> list[str]:
    shared = []
    for left, right in zip(a.split("/"), b.split("/"), strict=False):
        if left != right:
            break
        shared.append(left)
    return shared


def _limiters(ctx: Context) -> Iterator[tuple[str, ast.Module, ast.Call]]:
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel) or "Limiter(" not in text:
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for call in pyast.calls(tree, PY_LIMITER) if tree else []:
            yield entry.rel, tree, call


def _memory_storage(tree: ast.Module, call: ast.Call) -> str | None:
    """'always' when the limiter can only use memory, 'fallback' when one branch picks memory."""
    storage = pyast.kwarg(call, "storage_uri")
    if storage is None:
        return "always"
    value = pyast.constant(storage, None)
    if isinstance(value, str):
        return "always" if value.startswith("memory://") else None
    if isinstance(storage, ast.Name):
        fn = pyast.function_at(tree, call.lineno)
        for node in ast.walk(fn or tree):
            if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == storage.id for t in node.targets
            ):
                literal = pyast.constant(node.value, None)
                if isinstance(literal, str) and literal.startswith("memory://"):
                    return "fallback"
    return None


def _inmemory(
    ctx: Context, rel: str, line: int, tag: Tag, what: str, evidence: Location
) -> Finding:
    return make_finding(
        "ABUSE-INMEMORY-LIMITER",
        tag=tag,
        locations=[Location(rel, line), evidence],
        snippet=snippet(ctx.index.text(rel), line),
        proof_needed="Check whether production sets the shared store (for example REDIS_URL).",
        what=what,
    )


@rule(
    "ABUSE-INMEMORY-LIMITER",
    review="abuse",
    severity="medium",
    exploitability="medium",
    owasp="A04",
)
def inmemory_limiter(ctx: Context) -> Iterator[Finding]:
    if multi_process(ctx) is None:
        return
    for rel, tree, call in _limiters(ctx):
        evidence = multi_process(ctx, rel)
        kind = _memory_storage(tree, call)
        if kind == "always":
            what = "The limiter keeps its counters in process memory."
            yield _inmemory(ctx, rel, call.lineno, Tag.CONFIRMED, what, evidence)
        elif kind == "fallback":
            what = "The limiter falls back to process memory when no shared store is configured."
            yield _inmemory(ctx, rel, call.lineno, Tag.INFERRED, what, evidence)
    for entry in ctx.index.js_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel) or not re.search(r"rateLimit|new Map\(", text):
            continue
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for call in jsts.calls(tree, r"rateLimit|slowDown"):
                args = jsts.arguments(call)
                if not args or "store" not in jsts.object_pairs(args[0]):
                    what = "express-rate-limit has no store option, so it counts in process memory."
                    line = jsts.line(tree, call)
                    evidence = multi_process(ctx, entry.rel)
                    yield _inmemory(ctx, entry.rel, line, Tag.CONFIRMED, what, evidence)
            for decl in jsts.walk(tree.root, {"variable_declarator"}):
                name = jsts.node_text(decl.child_by_field_name("name"))
                value = jsts.node_text(decl.child_by_field_name("value"))
                top_level = jsts.enclosing_function(decl) is None
                if top_level and value.startswith("new Map(") and COUNTER_NAME.search(name):
                    what = f"The module-level Map {name} counts requests in process memory."
                    line = jsts.line(tree, decl)
                    evidence = multi_process(ctx, entry.rel)
                    yield _inmemory(ctx, entry.rel, line, Tag.INFERRED, what, evidence)


@rule(
    "ABUSE-LIMITER-NOT-APPLIED",
    review="abuse",
    severity="medium",
    exploitability="medium",
    owasp="A04",
)
def limiter_not_applied(ctx: Context) -> Iterator[Finding]:
    wired = any(
        "SlowAPI" in ctx.index.text(f.rel) and "add_middleware" in ctx.index.text(f.rel)
        for f in ctx.index.py_files
    )
    if wired:
        return
    for rel, _tree, call in _limiters(ctx):
        defaults = pyast.kwarg(call, "default_limits")
        if defaults is not None and "slowapi" in ctx.index.text(rel):
            yield make_finding(
                "ABUSE-LIMITER-NOT-APPLIED",
                tag=Tag.CONFIRMED,
                locations=[Location(rel, defaults.lineno)],
                snippet=snippet(ctx.index.text(rel), defaults.lineno),
            )


@rule(
    "ABUSE-LIMITER-PROXY-IP",
    review="abuse",
    severity="medium",
    exploitability="medium",
    owasp="A04",
)
def limiter_proxy_ip(ctx: Context) -> Iterator[Finding]:
    if not ctx.detection.hosting:
        return
    if any(PROXY_TRUST.search(ctx.index.text(f.rel)) for f in ctx.index.files):
        return
    for rel, _tree, call in _limiters(ctx):
        key = pyast.kwarg(call, "key_func")
        if key is not None and (pyast.dotted(key) or "").endswith("get_remote_address"):
            yield make_finding(
                "ABUSE-LIMITER-PROXY-IP",
                tag=Tag.INFERRED,
                locations=[Location(rel, key.lineno)],
                snippet=snippet(ctx.index.text(rel), key.lineno),
                key="get_remote_address",
            )
    for entry in ctx.index.js_files:
        if is_test(entry.rel) or "rateLimit" not in ctx.index.text(entry.rel):
            continue
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for call in jsts.calls(tree, r"rateLimit"):
                args = jsts.arguments(call)
                if not args or "keyGenerator" not in jsts.object_pairs(args[0]):
                    line = jsts.line(tree, call)
                    yield make_finding(
                        "ABUSE-LIMITER-PROXY-IP",
                        tag=Tag.INFERRED,
                        locations=[Location(entry.rel, line)],
                        snippet=snippet(ctx.index.text(entry.rel), line),
                        key="req.ip",
                    )


@rule(
    "ABUSE-UPLOAD-UNBOUNDED",
    review="abuse",
    severity="low",
    exploitability="medium",
    owasp="A04",
)
def upload_unbounded(ctx: Context) -> Iterator[Finding]:
    for route in ctx.detection.routes:
        fn = route.handler
        if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef) or is_test(route.file):
            continue
        uploads = {
            a.arg
            for a in [*fn.args.args, *fn.args.kwonlyargs]
            if a.annotation is not None and "UploadFile" in ast.unparse(a.annotation)
        }
        for call in pyast.calls(route.tree, UPLOAD_READ, fn):
            target = call.func.value if isinstance(call.func, ast.Attribute) else None
            is_upload = isinstance(target, ast.Name) and target.id in uploads
            is_flask = target is not None and "request.files" in ast.unparse(target)
            if (is_upload or is_flask) and not call.args:
                later = ast.unparse(fn)[ast.unparse(fn).find(ast.unparse(call)) :]
                checked = bool(re.search(r"len\(\w+\)\s*>", later))
                what = (
                    "reads the whole upload into memory and only then checks its size"
                    if checked
                    else "reads the whole upload into memory with no size limit"
                )
                yield make_finding(
                    "ABUSE-UPLOAD-UNBOUNDED",
                    tag=Tag.CONFIRMED,
                    locations=[Location(route.file, call.lineno)],
                    snippet=snippet(ctx.index.text(route.file), call.lineno),
                    method=route.method,
                    path=route.path,
                    what=what,
                )
