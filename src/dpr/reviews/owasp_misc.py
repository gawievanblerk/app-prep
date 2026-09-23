"""Review 5, OWASP A02, A04 and A10: weak random tokens, secrets in URLs, client prices, SSRF."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Tag
from dpr.parsing import jsts, pyast
from dpr.redact import SECRET_PARAM_NAMES, snippet
from dpr.reviews.owasp_inject import REQUEST_VALUE
from dpr.reviews.owasp_paths import request_params
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule
from dpr.vendored import is_vendored
from dpr.walk import line_of

TOKEN_NAME = re.compile(r"(?i)token|secret|code|otp|reset|nonce|password|salt|api_?key")
PY_RANDOM = re.compile(r"random\.(?:random|choice|choices|randint|randrange|sample|getrandbits)")
SECRET_PARAM = re.compile(rf"[?&]({SECRET_PARAM_NAMES})=")
ONE_TIME_LINK = re.compile(r"(?i)reset|verif|confirm|invite|magic|activate|unsubscribe")
PRICE_FIELD = re.compile(
    r"(?:body|req\.body|request\.(?:json|data|POST|form)|payload|data|input|params)"
    r"""(?:\??\.|\[['"])(price|amount|total|unit_amount|discount|plan|is_?paid)\b""",
    re.IGNORECASE,
)
PAYMENT_CALL = re.compile(r"(?i)stripe|checkout|payment_?intent|paddle|lemon")
JS_FETCH = re.compile(r"fetch|axios(?:\.(?:get|post|put|patch|delete|request))?|got|ky|needle")
PY_FETCH = re.compile(
    r"(?:requests|httpx|client|session|aiohttp\.ClientSession\(\))\.(?:get|post|put|patch|delete"
    r"|request|head)|urllib\.request\.urlopen|urlopen"
)
ALLOWLIST = re.compile(r"(?i)allow_?list|allowed_?(?:hosts|domains|origins)|ALLOWED|whitelist")
FIXED_HOST = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^/{}\s@]+/")
TRUSTED_HOST_PY = re.compile(
    r"[A-Z][A-Z0-9_]*|settings\.\w+|config\.\w+|os\.environ\[.*\]|os\.environ\.get\(.*\)"
    r"|os\.getenv\(.*\)"
)
TRUSTED_HOST_JS = re.compile(r"process\.env\.\w+|[A-Z][A-Z0-9_]*")


def _flatten_add(node: ast.AST) -> list[ast.AST]:
    """Left-to-right operands of a chain of `+` concatenations."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return [*_flatten_add(node.left), *_flatten_add(node.right)]
    return [node]


def _next_starts_with_slash(part: ast.AST | None) -> bool:
    value = pyast.constant(part, None)
    return isinstance(value, str) and value.startswith("/")


def _fixed_host_py(node: ast.AST | None) -> bool:
    """True when a URL expression starts with a literal scheme and host, or a trusted

    name (an ALL_CAPS constant, settings/config attribute, or os.environ/os.getenv) is
    immediately followed by a literal path starting with a slash.
    """
    if isinstance(node, ast.JoinedStr) and node.values:
        first = node.values[0]
        if isinstance(pyast.constant(first, None), str):
            return bool(FIXED_HOST.match(first.value))
        if isinstance(first, ast.FormattedValue) and TRUSTED_HOST_PY.fullmatch(
            ast.unparse(first.value)
        ):
            return _next_starts_with_slash(node.values[1] if len(node.values) > 1 else None)
        return False
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        parts = _flatten_add(node)
        first = parts[0]
        if isinstance(pyast.constant(first, None), str):
            return bool(FIXED_HOST.match(first.value))
        if TRUSTED_HOST_PY.fullmatch(ast.unparse(first)):
            return _next_starts_with_slash(parts[1] if len(parts) > 1 else None)
        return False
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        left = pyast.constant(node.left, None)
        return isinstance(left, str) and bool(FIXED_HOST.match(left))
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and isinstance(pyast.constant(node.func.value, None), str)
    ):
        return bool(FIXED_HOST.match(node.func.value.value))
    return False


def _fixed_host_js(node) -> bool:
    """Same test as `_fixed_host_py`, for a JS/TS template string."""
    if node is None or node.type != "template_string":
        return False
    parts = [c for c in node.named_children if c.type != "comment"]
    if not parts:
        return False
    first = parts[0]
    if first.type == "string_fragment":
        return bool(FIXED_HOST.match(jsts.node_text(first)))
    if first.type == "template_substitution":
        inner = first.named_children[0] if first.named_children else None
        if inner is None or not TRUSTED_HOST_JS.fullmatch(jsts.node_text(inner)):
            return False
        return (
            len(parts) > 1
            and parts[1].type == "string_fragment"
            and jsts.node_text(parts[1]).startswith("/")
        )
    return False


def _weak(ctx: Context, rel: str, line: int, name: str, call: str) -> Finding:
    return make_finding(
        "OWASP-A02-WEAK-RANDOM-TOKEN",
        tag=Tag.INFERRED,
        locations=[Location(rel, line)],
        snippet=snippet(ctx.index.text(rel), line),
        name=name,
        call=call,
    )


@rule(
    "OWASP-A02-WEAK-RANDOM-TOKEN",
    review="owasp",
    severity="high",
    exploitability="medium",
    owasp="A02",
)
def weak_random_token(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.js_files:
        if is_test(entry.rel) or is_vendored(ctx.index, entry.rel):
            continue
        if "Math.random" not in ctx.index.text(entry.rel):
            continue
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for node in jsts.walk(tree.root, {"variable_declarator", "assignment_expression"}):
                field = "name" if node.type == "variable_declarator" else "left"
                name = jsts.node_text(node.child_by_field_name(field))
                value = jsts.node_text(
                    node.child_by_field_name("value" if field == "name" else "right")
                )
                if "Math.random" in value and TOKEN_NAME.search(name):
                    yield _weak(ctx, entry.rel, jsts.line(tree, node), name, "Math.random()")
    for entry in ctx.index.py_files:
        if is_test(entry.rel) or is_vendored(ctx.index, entry.rel):
            continue
        if "random" not in ctx.index.text(entry.rel):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for node in ast.walk(tree) if tree else []:
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
                name = node.targets[0].id
                calls = [
                    pyast.dotted(c.func) for c in ast.walk(node.value) if isinstance(c, ast.Call)
                ]
                weak = [c for c in calls if c and PY_RANDOM.fullmatch(c)]
                if weak and TOKEN_NAME.search(name):
                    yield _weak(ctx, entry.rel, node.lineno, name, weak[0])


@rule(
    "OWASP-A02-SECRET-IN-URL",
    review="owasp",
    severity="medium",
    exploitability="low",
    owasp="A02",
)
def secret_in_url(ctx: Context) -> Iterator[Finding]:
    for entry in [*ctx.index.js_files, *ctx.index.py_files]:
        if is_test(entry.rel) or is_vendored(ctx.index, entry.rel):
            continue
        text = ctx.index.text(entry.rel)
        for match in SECRET_PARAM.finditer(text):
            line = line_of(text, match.start())
            line_text = text.splitlines()[line - 1]
            if match.group(1) == "token" and ONE_TIME_LINK.search(line_text):
                continue
            if not re.search(r"\$\{|\{\w|%s|\+\s*\w|['\"]\s*\+", line_text):
                continue
            yield make_finding(
                "OWASP-A02-SECRET-IN-URL",
                tag=Tag.INFERRED,
                locations=[Location(entry.rel, line)],
                snippet=snippet(text, line),
                param=match.group(1),
            )


@rule("OWASP-A04-CLIENT-PRICE", review="owasp", severity="high", exploitability="high", owasp="A04")
def client_price(ctx: Context) -> Iterator[Finding]:
    for route in ctx.detection.routes:
        handler = route.handler
        if handler is None or is_test(route.file):
            continue
        if isinstance(handler, ast.AST):
            nodes = [
                (n.lineno, ast.unparse(n)) for n in ast.walk(handler) if isinstance(n, ast.Call)
            ]
            names = [(line, text.split("(", 1)[0]) for line, text in nodes]
        elif route.tree is not None and getattr(handler, "type", "") in jsts.FUNCTION_TYPES:
            calls = list(jsts.calls(route.tree, re.compile(r".*"), handler))
            nodes = [(jsts.line(route.tree, c), jsts.node_text(c)) for c in calls]
            names = [(jsts.line(route.tree, c), jsts.callee(c)) for c in calls]
        else:
            continue
        for (line, text), (_, name) in zip(nodes, names, strict=True):
            field = PRICE_FIELD.search(text)
            if field and PAYMENT_CALL.search(name):
                yield make_finding(
                    "OWASP-A04-CLIENT-PRICE",
                    tag=Tag.INFERRED,
                    locations=[Location(route.file, line)],
                    snippet=snippet(ctx.index.text(route.file), line),
                    field=field.group(1),
                )
                break


@rule("OWASP-A10-SSRF", review="owasp", severity="high", exploitability="high", owasp="A10")
def ssrf(ctx: Context) -> Iterator[Finding]:
    for route in ctx.detection.routes:
        handler = route.handler
        if handler is None or is_test(route.file):
            continue
        if isinstance(handler, ast.FunctionDef | ast.AsyncFunctionDef):
            scope = ast.unparse(handler)
            assigned_exprs = {
                n.targets[0].id: n.value
                for n in ast.walk(handler)
                if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
            }
            for call in pyast.calls(route.tree, PY_FETCH, handler):
                if not call.args:
                    continue
                arg = call.args[0]
                target_names = pyast.names_in(arg)
                resolved_exprs = [assigned_exprs[n] for n in target_names if n in assigned_exprs]
                if any(_fixed_host_py(c) for c in (arg, *resolved_exprs)):
                    continue
                assigned = [ast.unparse(e) for e in resolved_exprs]
                params = set(request_params(ctx, route)) - {"request"}
                from_request = REQUEST_VALUE.search(" ".join([ast.unparse(arg), *assigned]))
                if (from_request or target_names & params) and not ALLOWLIST.search(scope):
                    yield _ssrf(ctx, route.file, call.lineno)
        elif route.tree is not None and getattr(handler, "type", "") in jsts.FUNCTION_TYPES:
            scope = jsts.node_text(handler)
            for call in jsts.calls(route.tree, JS_FETCH, handler):
                args = jsts.arguments(call)
                first = jsts.unwrap(args[0]) if args else None
                target_node, text = first, jsts.node_text(first)
                if first is not None and first.type == "identifier":
                    resolved = jsts.resolve_identifier(first)
                    if resolved is not None:
                        target_node, text = resolved, jsts.node_text(resolved)
                if _fixed_host_js(target_node):
                    continue
                if REQUEST_VALUE.search(text) and not ALLOWLIST.search(scope):
                    yield _ssrf(ctx, route.file, jsts.line(route.tree, call))


def _ssrf(ctx: Context, rel: str, line: int) -> Finding:
    return make_finding(
        "OWASP-A10-SSRF",
        tag=Tag.INFERRED,
        locations=[Location(rel, line)],
        snippet=snippet(ctx.index.text(rel), line),
    )
