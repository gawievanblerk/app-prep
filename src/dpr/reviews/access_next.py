"""Route access for Next.js: auth calls in handlers, auth wrappers and middleware matchers."""

from __future__ import annotations

import re

from dpr.model import Route
from dpr.parsing import jsts
from dpr.reviews.access_names import ADMIN, ADMIN_WORD, AUTHENTICATED, Access, auth_name, public
from dpr.rules import Context

JS_AUTH_CALL = re.compile(
    r"\b(auth|getServerSession|getSession|currentUser|getAuth|requireAuth|requireUser"
    r"|getCurrentUser|verifyToken|getToken|validateRequest|getKindeServerSession|getUser"
    r"|withAuth)\s*\("
)
JS_ADMIN_CHECK = re.compile(r"""isAdmin|role\s*[!=]==?\s*['"]admin['"]|['"]admin['"]\s*[!=]==?""")
NEXT_AUTH_TEXT = re.compile(r"auth|clerkMiddleware|withAuth|getToken|updateSession|session")


def _js_subjects(handler) -> tuple[str, ...]:
    names = []
    for decl in jsts.walk(handler, {"variable_declarator"}):
        value = jsts.node_text(decl.child_by_field_name("value"))
        if not JS_AUTH_CALL.search(value) and "auth.getUser" not in value:
            continue
        target = decl.child_by_field_name("name")
        if target is not None and target.type == "identifier":
            names.append(jsts.node_text(target))
        elif target is not None:
            for ident in jsts.walk(target, {"shorthand_property_identifier_pattern", "identifier"}):
                names.append(jsts.node_text(ident))
    return tuple(dict.fromkeys(names))


def _path_regex(pattern: str) -> re.Pattern[str] | None:
    """A Next.js matcher (path-to-regexp syntax with regex groups) as a Python regex."""
    out: list[str] = []
    i = 0
    while i < len(pattern):
        param = re.match(r":(\w+)([*+?])?", pattern[i:])
        if param:
            optional = param.group(2) in ("*", "?") and out and out[-1] == "/"
            if optional:
                out.pop()
            segment = "(?:/.*)?" if param.group(2) == "*" else "(?:/[^/]+)?"
            out.append(segment if optional else "[^/]+" + (".*" if param.group(2) else ""))
            i += param.end()
        elif pattern[i] == "(":
            depth, j = 0, i
            while j < len(pattern):
                if pattern[j] == "\\":
                    j += 2
                    continue
                depth += {"(": 1, ")": -1}.get(pattern[j], 0)
                j += 1
                if depth == 0:
                    break
            out.append(pattern[i:j])
            i = j
        else:
            out.append(".*" if pattern[i] == "*" else re.escape(pattern[i]))
            i += 1
    try:
        return re.compile("".join(out))
    except re.error:
        return None


def _matcher_covers(text: str, path: str) -> bool:
    patterns = re.findall(r"""['"](/[^'"]*)['"]""", text[text.find("matcher") :])
    if "matcher" not in text or not patterns:
        return True
    for pattern in patterns:
        prefix = re.split(r"[:(\[*]", pattern, maxsplit=1)[0].rstrip("/")
        regex = _path_regex(pattern) if path.startswith("/") else None
        if regex is not None and regex.fullmatch(path):
            return True
        if regex is None and (not prefix or path == prefix or path.startswith(prefix + "/")):
            return True
    return False


def _next_middleware(ctx: Context, path: str) -> tuple[bool, str] | None:
    """(reads as auth, file) for a middleware file whose matcher covers the path."""
    found = None
    for entry in ctx.index.named("middleware.ts", "middleware.js"):
        if entry.rel not in (
            "middleware.ts",
            "middleware.js",
            "src/middleware.ts",
            "src/middleware.js",
        ):
            continue
        text = ctx.index.text(entry.rel)
        if _matcher_covers(text, path):
            found = (bool(NEXT_AUTH_TEXT.search(text)), entry.rel)
            if found[0]:
                return found
    return found


def next_js(ctx: Context, route: Route) -> Access:
    handler = route.handler
    text = jsts.node_text(handler) if handler is not None else ""
    if JS_AUTH_CALL.search(text) or "auth.getUser" in text:
        level = ADMIN if JS_ADMIN_CHECK.search(text) else AUTHENTICATED
        return Access(level, _js_subjects(handler), "auth call in handler")
    names = [n for n in route.wrappers if auth_name(n) or ADMIN_WORD.search(n)]
    if names:
        level = ADMIN if any(ADMIN_WORD.search(name) for name in names) else AUTHENTICATED
        subjects = _js_subjects(handler) if handler is not None else ()
        return Access(level, subjects, "wrapper " + ", ".join(names[:3]))
    middleware = _next_middleware(ctx, route.path)
    if middleware is not None and middleware[0]:
        return Access(AUTHENTICATED, (), "middleware matcher")
    unread = f"the middleware in {middleware[1]}" if middleware is not None else ""
    return public("no auth call and no middleware matcher", unread)
