"""Review 5, OWASP A01: redirects to an address taken from the request.

A redirect whose target starts with a request value (`next`, `return_url`, a JSON field) or
with the Referer header sends the user wherever the link says, unless the value is checked
with `url_has_allowed_host_and_scheme`, `is_safe_url` or an allowlist first.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Tag
from dpr.parsing import jsts, pyast
from dpr.redact import snippet
from dpr.reviews.app_code import app_file, app_py_files, local_values, own_calls
from dpr.reviews.request_values import RECORD, Taint, reads, trace
from dpr.rules import Context, make_finding, rule

PY_REDIRECT = re.compile(
    r"(?:[\w.]+\.)?(?:HttpResponseRedirect|HttpResponsePermanentRedirect|redirect|RedirectResponse)"
)
SAFE = re.compile(
    r"url_has_allowed_host_and_scheme|is_safe_url|allowed_hosts|ALLOWED_REDIRECT|allow_?list"
    r"|whitelist|\.netloc\b|is_safe_redirect|safe_url|urlparse\([^)]*\)\.(?:scheme|hostname)",
    re.IGNORECASE,
)
REFERER = re.compile(
    r"HTTP_REFERER|\.headers(?:\.get\(|\[)\s*['\"]referer|\.referrer\b|req\.get\(\s*['\"]referer",
    re.IGNORECASE,
)
NAMED_URL = re.compile(r"(?:^|\.)(?:reverse|url_for|reverse_lazy)$")
JS_REQUEST = re.compile(
    r"\breq(?:uest)?\.(?:query|body|params)\b|searchParams\.get\(|\bquery\.(?:next|redirect|return)"
)
REFERER_LABEL = "the Referer header"


def _literal_start(value: object) -> bool:
    """A literal that fixes where the redirect goes: a path on this site or a full URL."""
    return isinstance(value, str) and bool(re.match(r"/(?!/)|[a-zA-Z][\w+.-]*://", value))


def _source(node: ast.AST | None, values: dict, taint: Taint, line: int, depth: int = 0) -> str:
    """The request value that decides where the redirect goes, or "" when a literal fixes it."""
    if node is None or depth > 4:
        return ""
    nxt = depth + 1
    if isinstance(node, ast.Name):
        earlier = [v for at, v in values.get(node.id, []) if at < line]
        if not earlier:
            return taint.keys.get(node.id, "")
        return next((s for v in earlier if (s := _source(v, values, taint, line, nxt))), "")
    if isinstance(node, ast.BoolOp):
        return next((s for v in node.values if (s := _source(v, values, taint, line, nxt))), "")
    if isinstance(node, ast.IfExp):
        return _source(node.body, values, taint, line, nxt) or _source(
            node.orelse, values, taint, line, nxt
        )
    if isinstance(node, ast.JoinedStr) and node.values:
        first = node.values[0]
        if isinstance(first, ast.FormattedValue):
            return _source(first.value, values, taint, line, nxt)
        return ""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _source(node.left, values, taint, line, nxt)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        left = pyast.constant(node.left, None)
        if isinstance(left, str) and left.startswith("%s"):
            right = node.right.elts[0] if isinstance(node.right, ast.Tuple) else node.right
            return _source(right, values, taint, line, nxt)
        return ""
    if isinstance(node, ast.Constant):
        return ""
    if isinstance(node, ast.Call):
        name = pyast.dotted(node.func) or ""
        if NAMED_URL.search(name) or RECORD.search(ast.unparse(node)):
            return ""
        template = pyast.constant(node.func.value, None) if name.endswith("format") else None
        if isinstance(node.func, ast.Attribute) and isinstance(template, str):
            if _literal_start(template) or not node.args:
                return ""
            return _source(node.args[0], values, taint, line, nxt)
    if REFERER.search(ast.unparse(node)):
        return REFERER_LABEL
    found = reads(node, taint)
    return next(iter(found.values()), "") if found else ""


def _target(call: ast.Call) -> ast.expr | None:
    if call.args:
        return call.args[0]
    return next((k.value for k in call.keywords if k.arg in ("to", "url", "redirect_to")), None)


def _py_sites(ctx: Context) -> Iterator[tuple[str, int, str]]:
    for rel, _text, tree in app_py_files(ctx, "edirect"):
        for fn in pyast.functions(tree):
            text = ast.unparse(fn)
            if not PY_REDIRECT.search(text) or SAFE.search(text):
                continue
            taint = trace(fn, {}, "django")
            values = local_values(fn)
            for call in own_calls(fn, PY_REDIRECT):
                source = _source(_target(call), values, taint, call.lineno)
                if source:
                    yield rel, call.lineno, source


def _js_sites(ctx: Context) -> Iterator[tuple[str, int, str]]:
    for entry in ctx.index.js_files:
        text = ctx.index.text(entry.rel)
        if ".redirect(" not in text or not app_file(ctx, entry.rel) or SAFE.search(text):
            continue
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for call in jsts.calls(tree, re.compile(r"(?:[\w.]+\.)?redirect")):
                args = jsts.arguments(call)
                first = jsts.unwrap(args[-1]) if args else None
                if first is not None and first.type == "identifier":
                    first = jsts.resolve_identifier(first) or first
                value = jsts.node_text(first)
                if re.match(r"\s*[`'\"]/", value):
                    continue
                if REFERER.search(value) or re.search(r"(?i)headers\.referer", value):
                    yield entry.rel, jsts.line(tree, call), REFERER_LABEL
                elif JS_REQUEST.search(value):
                    yield entry.rel, jsts.line(tree, call), "a request value"


@rule(
    "OWASP-A01-OPEN-REDIRECT",
    review="owasp",
    severity="medium",
    exploitability="medium",
    owasp="A01",
)
def open_redirect(ctx: Context) -> Iterator[Finding]:
    referers: dict[str, list[int]] = {}
    seen = set()
    for rel, line, source in [*_py_sites(ctx), *_js_sites(ctx)]:
        if (rel, line) in seen:
            continue
        seen.add((rel, line))
        if source == REFERER_LABEL:
            referers.setdefault(rel, []).append(line)
            continue
        label = source if source == "a request value" else f"the request value {source}"
        yield make_finding(
            "OWASP-A01-OPEN-REDIRECT",
            tag=Tag.CONFIRMED,
            locations=[Location(rel, line)],
            snippet=snippet(ctx.index.text(rel), line),
            source=label,
            count=1,
        )
    for rel, lines in referers.items():
        yield make_finding(
            "OWASP-A01-OPEN-REDIRECT",
            tag=Tag.INFERRED,
            locations=[Location(rel, line) for line in lines],
            snippet=snippet(ctx.index.text(rel), lines[0]),
            severity="low",
            exploitability="low",
            detail=(
                f"{len(lines)} redirect(s) in this file go to the Referer header, which the "
                "page that linked here chooses. A link from another site sends the user back "
                "to that site after the action, which reads as this site sending them there."
            ),
            proof_needed=(
                "Confirm the redirects are reachable from a link on another site; browsers "
                "often trim or drop the Referer, which limits the abuse."
            ),
            source=REFERER_LABEL,
            count=len(lines),
        )
