"""Review 4, baseline: cookie flags, debug mode, weak password hashing, mixed content."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Tag
from dpr.parsing import jsts, pyast
from dpr.redact import snippet
from dpr.reviews.access_names import name_tokens
from dpr.rules import Context, make_finding, rule
from dpr.walk import line_of

SESSION_LIKE = re.compile(r"(?i)sid|session|token|auth|jwt")
JS_COOKIE_CALL = re.compile(r"\(?(?:await)?cookies\(\)\)?\.set|\w+\.cookies\.set|\w+\.cookie")
JS_HEADER_CALL = re.compile(r"\w+\.(?:setHeader|header|set|append)")
FLAGS = {
    "httponly": "BASE-COOKIE-HTTPONLY",
    "secure": "BASE-COOKIE-SECURE",
    "samesite": "BASE-COOKIE-SAMESITE",
}
DJANGO_COOKIE_SETTINGS = {
    "SESSION_COOKIE_HTTPONLY": ("httponly", "high"),
    "SESSION_COOKIE_SECURE": ("secure", "high"),
    "CSRF_COOKIE_SECURE": ("secure", "low"),
    "SESSION_COOKIE_SAMESITE": ("samesite", "high"),
    "CSRF_COOKIE_SAMESITE": ("samesite", "low"),
}
WEAK_HASHES = re.compile(r"hashlib\.(md5|sha1|sha224|sha256)")
PASSWORD_WORD = re.compile(r"(?i)password|passwd|pwd")
TOKEN_WORDS = frozenset({"token", "tokens", "reset", "otp", "code", "codes", "nonce", "apikey"})
RANDOM_SOURCE = re.compile(r"randomBytes|secrets\.token_\w+")
WEAK_HASHERS = re.compile(r"MD5|SHA1", re.IGNORECASE)
MIXED = re.compile(
    r"""\b(?:src|href)\s*=\s*["']http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|www\.w3\.org)"""
)
MARKUP = (".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte", ".j2", ".jinja", ".jinja2")


def _cookie_findings(
    ctx: Context, rel: str, line: int, name: str, flags: dict[str, object]
) -> Iterator[Finding]:
    """flags maps httponly, secure, samesite to True, False, a SameSite string, or None."""
    session = bool(SESSION_LIKE.search(name))
    text = ctx.index.text(rel)
    for flag, value in flags.items():
        if flag == "samesite":
            bad = value is None or str(value).lower() == "none"
            severity = "high" if session and value is not None else "low"
            now = "not set" if value is None else "None"
        else:
            bad = value is False
            severity = "high" if session else "low"
            now = "missing or false"
        if bad:
            yield make_finding(
                FLAGS[flag],
                tag=Tag.CONFIRMED,
                locations=[Location(rel, line)],
                severity=severity,
                snippet=snippet(text, line),
                name=name,
                now=now,
            )


def _js_value(node) -> object:
    node = jsts.unwrap(node)
    if node is None:
        return None
    if node.type in ("true", "false"):
        return node.type == "true"
    text = jsts.string_value(node)
    return text if text is not None else "<dynamic>"


def _js_options(obj) -> dict[str, object] | None:
    if obj is not None and jsts.has_spread(obj):
        return None
    pairs = {k.lower(): v for k, v in jsts.object_pairs(obj).items()} if obj is not None else {}
    flags = {}
    for flag in FLAGS:
        value = _js_value(pairs.get(flag)) if flag in pairs else None
        if flag != "samesite" and flag not in pairs:
            value = False
        if value == "<dynamic>":
            continue
        flags[flag] = value
    return flags


def _set_cookie_literal(text: str) -> tuple[str, dict[str, object]]:
    parts = [p.strip() for p in text.split(";")]
    attrs = {p.split("=", 1)[0].lower(): (p.split("=", 1) + [""])[1] for p in parts[1:] if p}
    flags = {"httponly": "httponly" in attrs, "secure": "secure" in attrs}
    flags["samesite"] = attrs.get("samesite")
    return parts[0].split("=", 1)[0], flags


def _js_cookies(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.js_files:
        text = ctx.index.text(entry.rel)
        if "cookie" not in text.lower():
            continue
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for call in jsts.calls(tree, JS_COOKIE_CALL):
                args = jsts.arguments(call)
                if not args:
                    continue
                if jsts.unwrap(args[0]).type == "object":
                    pairs = jsts.object_pairs(args[0])
                    name = jsts.string_value(pairs.get("name")) or "cookie"
                    options = args[0]
                else:
                    name = jsts.string_value(args[0]) or jsts.node_text(args[0])
                    options = args[2] if len(args) > 2 else None
                flags = _js_options(options)
                if flags is not None:
                    line = jsts.line(tree, call)
                    yield from _cookie_findings(ctx, entry.rel, line, name, flags)
            for call in jsts.calls(tree, JS_HEADER_CALL):
                args = jsts.arguments(call)
                if len(args) < 2 or (jsts.string_value(args[0]) or "").lower() != "set-cookie":
                    continue
                raw = jsts.node_text(jsts.unwrap(args[1])).strip("'\"`")
                if "=" in raw:
                    name, flags = _set_cookie_literal(raw)
                    line = jsts.line(tree, call)
                    yield from _cookie_findings(ctx, entry.rel, line, name, flags)


def _py_cookies(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if "set_cookie" not in text and "COOKIE_" not in text:
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        if tree is None:
            continue
        starlette = "starlette" in text or "fastapi" in text
        for call in pyast.calls(tree, r"(?:\w+\.)+set_cookie"):
            if any(k.arg is None for k in call.keywords):
                continue
            key = call.args[0] if call.args else pyast.kwarg(call, "key")
            name = pyast.constant(key, None) if key is not None else None
            name = name if isinstance(name, str) else (ast.unparse(key) if key else "cookie")
            flags: dict[str, object] = {}
            for flag in FLAGS:
                node = pyast.kwarg(call, flag)
                value = pyast.constant(node, "<dynamic>") if node is not None else None
                if node is None and flag != "samesite":
                    value = False
                if node is None and flag == "samesite" and starlette:
                    value = "lax"
                if value != "<dynamic>":
                    flags[flag] = value
            yield from _cookie_findings(ctx, entry.rel, call.lineno, name, flags)
        if "INSTALLED_APPS" not in text and "MIDDLEWARE" not in text:
            continue
        for stmt in tree.body:
            if not isinstance(stmt, ast.Assign) or not isinstance(stmt.targets[0], ast.Name):
                continue
            setting = DJANGO_COOKIE_SETTINGS.get(stmt.targets[0].id)
            value = pyast.constant(stmt.value, "<dynamic>")
            if setting is None or value == "<dynamic>":
                continue
            flag, severity = setting
            bad = value is False if flag != "samesite" else str(value).lower() == "none"
            if bad:
                yield make_finding(
                    FLAGS[flag],
                    tag=Tag.CONFIRMED,
                    locations=[Location(entry.rel, stmt.lineno)],
                    severity=severity,
                    snippet=snippet(text, stmt.lineno),
                    name=stmt.targets[0].id,
                    now=f"set to {value}",
                )


def _cookie_rule(flag: str):
    def check(ctx: Context) -> Iterator[Finding]:
        if "cookie_findings" not in ctx.facts:
            ctx.facts["cookie_findings"] = [*_js_cookies(ctx), *_py_cookies(ctx)]
        for finding in ctx.facts["cookie_findings"]:
            if finding.rule_id == FLAGS[flag]:
                yield finding

    return check


for _flag, _rule_id in FLAGS.items():
    rule(_rule_id, review="baseline", severity="high", exploitability="medium", owasp="A05")(
        _cookie_rule(_flag)
    )


def _debug(ctx: Context, rel: str, line: int, what: str) -> Finding:
    return make_finding(
        "BASE-DEBUG-ON",
        tag=Tag.INFERRED,
        locations=[Location(rel, line)],
        snippet=snippet(ctx.index.text(rel), line),
        what=what,
    )


@rule("BASE-DEBUG-ON", review="baseline", severity="high", exploitability="medium", owasp="A05")
def debug_on(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if "debug" not in text.lower():
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        if tree is None:
            continue
        django = "INSTALLED_APPS" in text
        for stmt in tree.body:
            if (
                django
                and isinstance(stmt, ast.Assign)
                and isinstance(stmt.targets[0], ast.Name)
                and stmt.targets[0].id == "DEBUG"
                and pyast.constant(stmt.value) is True
            ):
                yield _debug(ctx, entry.rel, stmt.lineno, "Django settings set DEBUG = True.")
        for call in pyast.calls(tree, r"(?:\w+\.)?(?:FastAPI|Flask|run)"):
            if pyast.constant(pyast.kwarg(call, "debug")) is True:
                yield _debug(
                    ctx, entry.rel, call.lineno, "The app is created or run with debug=True."
                )
        for cls in pyast.class_defs(tree):
            if not any(b.endswith("Settings") for b in pyast.base_names(cls)):
                continue
            for stmt in cls.body:
                if (
                    isinstance(stmt, ast.AnnAssign)
                    and isinstance(stmt.target, ast.Name)
                    and stmt.target.id.lower() == "debug"
                    and pyast.constant(stmt.value) is True
                ):
                    what = "The settings class turns debug on unless the environment sets it."
                    yield _debug(ctx, entry.rel, stmt.lineno, what)


def _password_context(call_text: str, fn: ast.AST | None) -> bool:
    name = getattr(fn, "name", "") or ""
    return bool(PASSWORD_WORD.search(call_text) or PASSWORD_WORD.search(name))


def _names_token(text: str) -> bool:
    """The text names a token, reset link, one-time code, nonce or API key."""
    words = name_tokens(text)
    pairs = zip(words, words[1:], strict=False)
    return bool(TOKEN_WORDS & set(words)) or any(a == "api" and b == "key" for a, b in pairs)


def _hashes_random_or_token(hashed: str, context: str, sources: list[str]) -> bool:
    """Skip a weak hash of a random token: the hashed value, its target or statement names a
    token, or the value comes from randomBytes or secrets.token_*. A password argument is kept."""
    if PASSWORD_WORD.search(hashed):
        return False
    return _names_token(hashed + " " + context) or any(RANDOM_SOURCE.search(s) for s in sources)


def _py_statement(fn: ast.AST, line: int) -> str:
    found = [
        n
        for n in ast.walk(fn)
        if isinstance(n, ast.Assign | ast.AnnAssign | ast.AugAssign | ast.Return | ast.Expr)
        and n.lineno <= line <= (n.end_lineno or n.lineno)
    ]
    return ast.unparse(max(found, key=lambda n: n.lineno)) if found else ""


def _py_sources(fn: ast.AST, hashed: ast.AST) -> list[str]:
    names = pyast.names_in(hashed)
    return [
        ast.unparse(node.value)
        for node in ast.walk(fn)
        if isinstance(node, ast.Assign)
        and names & set().union(*(pyast.names_in(t) for t in node.targets))
    ]


def _js_hashed(call) -> list:
    """The values passed to .update() along a createHash(...).update(...) chain."""
    values = []
    node = call
    while node.parent is not None and node.parent.type == "member_expression":
        member = node.parent
        outer = member.parent
        if outer is None or outer.type != "call_expression":
            break
        if jsts.node_text(member.child_by_field_name("property")) == "update":
            values += [jsts.unwrap(a) for a in jsts.arguments(outer)]
        node = outer
    return values


@rule(
    "BASE-WEAK-HASH", review="baseline", severity="critical", exploitability="medium", owasp="A02"
)
def weak_hash(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if "hashlib" not in text and "PASSWORD_HASHERS" not in text:
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        if tree is None:
            continue
        for call in pyast.calls(tree, WEAK_HASHES):
            algorithm = (pyast.dotted(call.func) or "").split(".")[-1]
            fn = pyast.function_at(tree, call.lineno)
            hashed = ast.unparse(call.args[0]) if call.args else ""
            scope = fn or tree
            statement = _py_statement(scope, call.lineno)
            sources = [hashed, *(_py_sources(scope, call.args[0]) if call.args else [])]
            if _hashes_random_or_token(hashed, statement, sources):
                continue
            if _password_context(ast.unparse(call), fn):
                yield make_finding(
                    "BASE-WEAK-HASH",
                    tag=Tag.INFERRED,
                    locations=[Location(entry.rel, call.lineno)],
                    snippet=snippet(text, call.lineno),
                    algorithm=algorithm,
                )
        hashers = pyast.assignments(tree.body).get("PASSWORD_HASHERS")
        if isinstance(hashers, ast.List | ast.Tuple) and hashers.elts:
            first = pyast.constant(hashers.elts[0], "")
            if isinstance(first, str) and WEAK_HASHERS.search(first.rsplit(".", 1)[-1]):
                yield make_finding(
                    "BASE-WEAK-HASH",
                    tag=Tag.CONFIRMED,
                    locations=[Location(entry.rel, hashers.elts[0].lineno)],
                    snippet=snippet(text, hashers.elts[0].lineno),
                    algorithm=first.rsplit(".", 1)[-1],
                )
    for entry in ctx.index.js_files:
        text = ctx.index.text(entry.rel)
        if "createHash" not in text:
            continue
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for call in jsts.calls(tree, r"(?:\w+\.)?createHash"):
                args = jsts.arguments(call)
                algorithm = (jsts.string_value(args[0]) or "") if args else ""
                if algorithm.lower() not in ("md5", "sha1", "sha256"):
                    continue
                statement = call
                while statement.parent is not None and statement.parent.type not in (
                    "statement_block",
                    "program",
                ):
                    statement = statement.parent
                fn = jsts.enclosing_function(call)
                fn_name = jsts.node_text(fn.child_by_field_name("name")) if fn else ""
                hashed = _js_hashed(call)
                sources = [jsts.node_text(v) for v in hashed if v is not None]
                for value in hashed:
                    if value is not None and value.type == "identifier":
                        resolved = jsts.resolve_identifier(value)
                        sources.append(jsts.node_text(resolved) if resolved is not None else "")
                text = " ".join(jsts.node_text(v) for v in hashed if v is not None)
                if _hashes_random_or_token(text, jsts.node_text(statement), sources):
                    continue
                if PASSWORD_WORD.search(jsts.node_text(statement) + " " + fn_name):
                    line = jsts.line(tree, call)
                    yield make_finding(
                        "BASE-WEAK-HASH",
                        tag=Tag.INFERRED,
                        locations=[Location(entry.rel, line)],
                        snippet=snippet(text, line),
                        algorithm=algorithm,
                    )


@rule("BASE-MIXED-CONTENT", review="baseline", severity="low", exploitability="low", owasp="A02")
def mixed_content(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.files:
        if not entry.rel.lower().endswith(MARKUP):
            continue
        text = ctx.index.text(entry.rel)
        lines = sorted({line_of(text, m.start()) for m in MIXED.finditer(text)})
        if lines:
            yield make_finding(
                "BASE-MIXED-CONTENT",
                tag=Tag.INFERRED,
                locations=[Location(entry.rel, n) for n in lines[:5]],
                snippet=snippet(text, lines[0]),
                count=len(lines),
            )
