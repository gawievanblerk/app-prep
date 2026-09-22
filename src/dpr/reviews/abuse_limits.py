"""Review 7, abuse: limiters that do not hold across workers or proxies, and unbounded uploads."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.discovery.approots import root_of
from dpr.model import Finding, Location, Tag
from dpr.parsing import imports, jsts, pyast
from dpr.redact import snippet
from dpr.reviews.abuse_workers import multi_process
from dpr.reviews.deploy_env import applies
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule

PROXY_TRUST = re.compile(
    r"forwarded-allow-ips|FORWARDED_ALLOW_IPS|ProxyHeadersMiddleware|ProxyFix|trust proxy"
    r"|trustProxy|get_ipaddr|x-forwarded-for",
    re.IGNORECASE,
)
PY_LIMITER = re.compile(r"(?:\w+\.)*Limiter")
COUNTER_NAME = re.compile(r"(?i)rate|limit|attempt|hits|count|bucket")
UPLOAD_READ = re.compile(r"(?:\w+)\.read")
EXPRESS_LIMITERS = ("express-rate-limit", "express-slow-down")
STORAGE_ASSIGN = re.compile(r"""RATELIMIT_STORAGE_UR[IL]['"]?[ \t]{0,8}\]?[ \t]{0,8}[:=](?!=)""")
STORAGE_SETTING = re.compile(
    r"""RATELIMIT_STORAGE_UR[IL]['"]?[ \t]{0,8}\]?[ \t]{0,8}[:=][ \t]{0,8}(['"])([^'"\n]*)\1"""
)
DOC_SUFFIXES = (".md", ".mdx", ".rst", ".adoc", ".txt")


def _limiters(ctx: Context) -> Iterator[tuple[str, ast.Module, ast.Call]]:
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel) or "Limiter(" not in text:
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for call in pyast.calls(tree, PY_LIMITER) if tree else []:
            yield entry.rel, tree, call


def _storage_settings(ctx: Context) -> list[tuple[str, str]]:
    """(file, kind) for each RATELIMIT_STORAGE_URI (Flask-Limiter) or RATELIMIT_STORAGE_URL
    (slowapi) setting in non-test code or config: 'memory', 'shared' or 'runtime'."""
    key = ("limiter-storage-settings", "")
    if key not in ctx.index.cache:
        found = []
        for entry in ctx.index.files:
            text = ctx.index.text(entry.rel)
            if is_test(entry.rel) or "RATELIMIT_STORAGE" not in text:
                continue
            for match in STORAGE_ASSIGN.finditer(text):
                literal = STORAGE_SETTING.match(text, match.start())
                if literal is None:
                    found.append((entry.rel, "runtime"))
                else:
                    memory = literal.group(2).startswith("memory://")
                    found.append((entry.rel, "memory" if memory else "shared"))
        ctx.index.cache[key] = found
    return ctx.index.cache[key]


def _configured_storage(ctx: Context, rel: str) -> str | None:
    """The storage setting that applies to `rel`'s app root (its own root or shared config):
    'memory' or 'shared' when every setting is that literal, 'mixed' when the settings disagree
    or one is read at runtime, None when nothing sets it."""
    kinds = {kind for file, kind in _storage_settings(ctx) if applies(ctx, file, rel)}
    single = len(kinds) == 1 and "runtime" not in kinds
    return kinds.pop() if single else ("mixed" if kinds else None)


def _proxy_trusted(ctx: Context, rel: str) -> bool:
    """Proxy trust is configured in code or config that applies to `rel`'s app root. Test files
    and documents only mention the header, so they never count."""
    key = ("proxy-trust-files", "")
    if key not in ctx.index.cache:
        ctx.index.cache[key] = [
            entry.rel
            for entry in ctx.index.files
            if not is_test(entry.rel)
            and not entry.rel.endswith(DOC_SUFFIXES)
            and PROXY_TRUST.search(ctx.index.text(entry.rel))
        ]
    return any(applies(ctx, trusted, rel) for trusted in ctx.index.cache[key])


def _memory_storage(tree: ast.Module, call: ast.Call, configured: str | None = None) -> str | None:
    """'always' when the limiter can only use memory, 'fallback' when one branch picks memory,
    'config' when no storage_uri is passed and app config or the environment can still set one."""
    storage = pyast.kwarg(call, "storage_uri")
    if storage is None:
        return {"memory": "always", "shared": None}.get(configured or "", "config")
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
    ctx: Context, rel: str, line: int, tag: Tag, what: str, evidence: Location, proof: str = ""
) -> Finding:
    return make_finding(
        "ABUSE-INMEMORY-LIMITER",
        tag=tag,
        locations=[Location(rel, line), evidence],
        snippet=snippet(ctx.index.text(rel), line),
        proof_needed=proof
        or "Check whether production sets the shared store (for example REDIS_URL).",
        what=what,
    )


def express_limiter_names(ctx: Context, rel: str) -> set[str]:
    """Local names bound to express-rate-limit or express-slow-down in this file."""
    return {
        local
        for local, (_file, _exported, spec) in imports.js_imports(ctx.index, rel).items()
        if spec in EXPRESS_LIMITERS
    }


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
        if evidence is None:
            continue
        kind = _memory_storage(tree, call, _configured_storage(ctx, rel))
        if kind == "always":
            what = "The limiter keeps its counters in process memory."
            yield _inmemory(ctx, rel, call.lineno, Tag.CONFIRMED, what, evidence)
        elif kind == "fallback":
            what = "The limiter falls back to process memory when no shared store is configured."
            yield _inmemory(ctx, rel, call.lineno, Tag.INFERRED, what, evidence)
        elif kind == "config":
            what = "The limiter passes no storage_uri, so it counts in process memory by default."
            proof = (
                "The storage can still come from app config or the environment "
                "(RATELIMIT_STORAGE_URI or RATELIMIT_STORAGE_URL); check what production sets."
            )
            yield _inmemory(ctx, rel, call.lineno, Tag.INFERRED, what, evidence, proof)
    for entry in ctx.index.js_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel) or not re.search(
            r"express-rate-limit|express-slow-down|new Map\(", text
        ):
            continue
        names = express_limiter_names(ctx, entry.rel)
        callee = re.compile("|".join(re.escape(n) for n in sorted(names))) if names else None
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for call in jsts.calls(tree, callee) if callee else []:
                args = jsts.arguments(call)
                evidence = multi_process(ctx, entry.rel)
                if evidence is not None and (not args or "store" not in jsts.object_pairs(args[0])):
                    what = "express-rate-limit has no store option, so it counts in process memory."
                    line = jsts.line(tree, call)
                    yield _inmemory(ctx, entry.rel, line, Tag.CONFIRMED, what, evidence)
            for decl in jsts.walk(tree.root, {"variable_declarator"}):
                name = jsts.node_text(decl.child_by_field_name("name"))
                value = jsts.node_text(decl.child_by_field_name("value"))
                top_level = jsts.enclosing_function(decl) is None
                evidence = multi_process(ctx, entry.rel)
                if top_level and value.startswith("new Map(") and COUNTER_NAME.search(name):
                    if evidence is not None:
                        what = f"The module-level Map {name} counts requests in process memory."
                        line = jsts.line(tree, decl)
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

    def skipped(rel: str) -> bool:
        home = root_of(ctx.detection.app_roots, rel)
        return (home is not None and home.deployed is False) or _proxy_trusted(ctx, rel)

    for rel, _tree, call in _limiters(ctx):
        if skipped(rel):
            continue
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
        if is_test(entry.rel) or "rate-limit" not in ctx.index.text(entry.rel):
            continue
        if skipped(entry.rel):
            continue
        names = {
            local
            for local, (_file, _exported, spec) in imports.js_imports(ctx.index, entry.rel).items()
            if spec == "express-rate-limit"
        }
        callee = re.compile("|".join(re.escape(n) for n in sorted(names))) if names else None
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for call in jsts.calls(tree, callee) if callee else []:
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
