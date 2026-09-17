"""Security header surfaces read from configuration and app code, without a network call."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from dpr.model import Location
from dpr.parsing import jsts, pyast
from dpr.reviews.paths import is_test
from dpr.rules import Context
from dpr.walk import line_of

HEADERS = {
    "HSTS": "strict-transport-security",
    "CSP": "content-security-policy",
    "XCTO": "x-content-type-options",
    "FRAME": "x-frame-options",
    "REFERRER": "referrer-policy",
    "PERMISSIONS": "permissions-policy",
}
ALL = frozenset(HEADERS.values())
HELMET = ALL - {"permissions-policy"}
MANIFESTS = ("package.json", "pyproject.toml", "requirements.txt", "manage.py")
HEADER_LITERAL = re.compile(
    r"""["'`](strict-transport-security|content-security-policy|x-content-type-options"""
    r"""|x-frame-options|referrer-policy|permissions-policy)["'`]""",
    re.IGNORECASE,
)
STRING_LITERAL = re.compile(r""""(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\]|\\.)*`""")
PLATFORM_HSTS = {"vercel.json", "netlify.toml"}
# A string literal, kept verbatim so a header name or CSP value inside one is never lost. Tried
# first in every mask below, so a comment marker inside a real string (a URL's //, for example)
# is consumed as part of the string and never misread as the start of a comment.
_STRING_ALT = rf"(?P<string>{STRING_LITERAL.pattern})"
JS_SUFFIXES = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"})
HASH_SUFFIXES = frozenset({".py", ".toml", ".conf"})
HASH_NAMES = frozenset({"_headers"})
# // starts a JS/TS comment but is floor division in Python, and # starts a Python comment but a
# private class field or method in JS/TS, so each language gets only its own comment syntax.
JS_COMMENT_MASK = re.compile(rf"{_STRING_ALT}|//[^\n]*|/\*.*?\*/", re.DOTALL)
HASH_COMMENT_MASK = re.compile(rf"{_STRING_ALT}|\#[^\n]*")


@dataclass(frozen=True)
class Surface:
    name: str
    kind: str
    location: Location
    headers: frozenset[str]
    root: str


def _file_names(ctx: Context) -> frozenset[str]:
    """All indexed file paths, cached once per run so app_root() stays cheap per call."""
    if "header_file_names" not in ctx.facts:
        ctx.facts["header_file_names"] = frozenset(f.rel for f in ctx.index.files)
    return ctx.facts["header_file_names"]


def app_root(ctx: Context, rel: str) -> str:
    names = _file_names(ctx)
    folder = PurePosixPath(rel).parent
    while True:
        prefix = "" if str(folder) == "." else f"{folder}/"
        if any(f"{prefix}{m}" in names for m in MANIFESTS):
            return str(folder) if prefix else ""
        if str(folder) == ".":
            return ""
        folder = folder.parent


def _comment_mask_for(rel: str) -> re.Pattern[str] | None:
    """The comment syntax to mask for this file, chosen by name and suffix. None masks nothing."""
    path = PurePosixPath(rel)
    suffix = path.suffix.lower()
    if suffix in JS_SUFFIXES:
        return JS_COMMENT_MASK
    if suffix in HASH_SUFFIXES or path.name in HASH_NAMES:
        return HASH_COMMENT_MASK
    return None


def _mask_comments(text: str, rel: str) -> str:
    """Blank out this file's own comment syntax (keeping newlines and string literals intact)."""
    pattern = _comment_mask_for(rel)
    if pattern is None:
        return text

    def repl(match: re.Match[str]) -> str:
        if match.group("string") is not None:
            return match.group(0)
        return "".join(ch if ch == "\n" else " " for ch in match.group(0))

    return pattern.sub(repl, text)


def _code_headers(ctx: Context, root: str) -> frozenset[str]:
    found: set[str] = set()
    for entry in [*ctx.index.js_files, *ctx.index.py_files]:
        if is_test(entry.rel) or app_root(ctx, entry.rel) != root:
            continue
        text = _mask_comments(ctx.index.text(entry.rel), entry.rel)
        found.update(m.group(1).lower() for m in HEADER_LITERAL.finditer(text))
        if "frame-ancestors" in text:
            found.add("x-frame-options")
        if "helmet(" in text:
            found |= HELMET
        if re.search(r"\bTalisman\(|\bsecure\.Secure\(|SecureHeaders\(", text):
            found |= ALL
    return frozenset(found)


def _json_headers(text: str, name: str) -> frozenset[str]:
    try:
        data = json.loads(text)
    except ValueError:
        return frozenset()
    keys: list[str] = []
    if name == "staticwebapp.config.json":
        keys += list((data.get("globalHeaders") or {}).keys())
        for route in data.get("routes") or []:
            keys += list((route.get("headers") or {}).keys())
    else:
        groups = data.get("headers") or []
        if name == "firebase.json":
            groups = (data.get("hosting") or {}).get("headers") or []
        for group in groups:
            keys += [h.get("key", "") for h in group.get("headers") or []]
    return frozenset(k.lower() for k in keys)


def _static_surfaces(ctx: Context) -> list[Surface]:
    found = []
    for entry in ctx.index.named("staticwebapp.config.json", "vercel.json", "firebase.json"):
        text = ctx.index.text(entry.rel)
        headers = _json_headers(text, entry.name)
        if entry.name == "firebase.json" and '"hosting"' not in text:
            continue
        if entry.name in PLATFORM_HSTS:
            headers |= {"strict-transport-security"}
        marker = (
            text.find('"globalHeaders"') if '"globalHeaders"' in text else text.find('"headers"')
        )
        line = line_of(text, marker) if marker >= 0 else 1
        found.append(
            Surface(entry.rel, "static host config", Location(entry.rel, line), headers, "")
        )
    for entry in ctx.index.named("netlify.toml", "_headers", "nginx.conf", "*.nginx.conf"):
        text = ctx.index.text(entry.rel)
        names = re.findall(r"(?im)^\s*(?:add_header\s+)?([A-Za-z-]+)\s*[:=\s]", text)
        headers = frozenset(n.lower() for n in names if n.lower() in ALL)
        if entry.name in PLATFORM_HSTS:
            headers |= {"strict-transport-security"}
        if entry.name != "netlify.toml" and not headers and "add_header" not in text:
            continue
        found.append(Surface(entry.rel, "static host config", Location(entry.rel, 1), headers, ""))
    return found


def _django_headers(text: str) -> frozenset[str]:
    found: set[str] = set()
    if "SecurityMiddleware" in text:
        found |= {"x-content-type-options", "referrer-policy"}
        if re.search(r"SECURE_HSTS_SECONDS\s*=\s*[1-9]", text):
            found.add("strict-transport-security")
        if re.search(r"SECURE_CONTENT_TYPE_NOSNIFF\s*=\s*False", text):
            found.discard("x-content-type-options")
    if "XFrameOptionsMiddleware" in text:
        found.add("x-frame-options")
    if "CSPMiddleware" in text or "CONTENT_SECURITY_POLICY" in text:
        found.add("content-security-policy")
    if "PERMISSIONS_POLICY" in text:
        found.add("permissions-policy")
    return frozenset(found)


def _app_surfaces(ctx: Context) -> list[Surface]:
    found = []
    for entry in ctx.index.named("next.config.*"):
        root = app_root(ctx, entry.rel)
        text = ctx.index.text(entry.rel)
        headers = frozenset(m.group(1).lower() for m in HEADER_LITERAL.finditer(text))
        headers |= _code_headers(ctx, root)
        found.append(Surface(entry.rel, "Next.js app", Location(entry.rel, 1), headers, root))
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if "INSTALLED_APPS" in text and "MIDDLEWARE" in text:
            found.append(
                Surface(
                    entry.rel, "Django settings", Location(entry.rel, 1), _django_headers(text), ""
                )
            )
            continue
        if not re.search(r"\b(FastAPI|Flask|Starlette)\(", text):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for call in pyast.calls(tree, r"(?:\w+\.)?(?:FastAPI|Flask|Starlette)") if tree else []:
            root = app_root(ctx, entry.rel)
            kind = f"{pyast.dotted(call.func).split('.')[-1]} app"
            location = Location(entry.rel, call.lineno)
            found.append(Surface(entry.rel, kind, location, _code_headers(ctx, root), root))
            break
    for entry in ctx.index.js_files:
        text = ctx.index.text(entry.rel)
        if "express" not in text:
            continue
        for tree in jsts.parse_file(ctx.index, entry.rel):
            calls = list(jsts.calls(tree, r"express"))
            if calls:
                root = app_root(ctx, entry.rel)
                location = Location(entry.rel, jsts.line(tree, calls[0]))
                found.append(
                    Surface(entry.rel, "Express app", location, _code_headers(ctx, root), root)
                )
    return found


def surfaces(ctx: Context) -> list[Surface]:
    if "header_surfaces" not in ctx.facts:
        ctx.facts["header_surfaces"] = sorted(
            [*_static_surfaces(ctx), *_app_surfaces(ctx)], key=lambda s: s.name
        )
    return ctx.facts["header_surfaces"]


def csp_values(ctx: Context) -> list[tuple[str, Location]]:
    found = []
    roots = {s.root for s in surfaces(ctx)}
    candidates = [s.location.file for s in surfaces(ctx)]
    candidates += [
        f.rel
        for f in [*ctx.index.js_files, *ctx.index.py_files]
        if not is_test(f.rel) and app_root(ctx, f.rel) in roots
    ]
    for rel in dict.fromkeys(candidates):
        text = _mask_comments(ctx.index.text(rel), rel)
        for match in STRING_LITERAL.finditer(text):
            policy = match.group(0)[1:-1]
            if "default-src" in policy or "script-src" in policy:
                found.append((policy, Location(rel, line_of(text, match.start()))))
    return found
