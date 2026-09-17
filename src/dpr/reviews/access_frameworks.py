"""Route access for Flask, Django and Next.js, and app-level Python guards the classifier
cannot read."""

from __future__ import annotations

import ast
import re

from dpr.model import Route
from dpr.parsing import jsts, pyast
from dpr.reviews.access_names import (
    ADMIN,
    ADMIN_WORD,
    AUTHENTICATED,
    MIXED,
    PUBLIC,
    Access,
    auth_middleware,
    auth_name,
    public,
)
from dpr.reviews.paths import is_test
from dpr.rules import Context

PY_HOOK = re.compile(r"(?:\w+\.)*(?:middleware|before_request|before_app_request)")
HOOK_AUTH = re.compile(
    r"(?i)authori[sz]|authenticat|\bauth\b|\bjwt\b|bearer|token|\blogin|\b401\b|api[_-]?key"
)
FLASK_DECORATORS = re.compile(
    r"(?:\w+\.)*(login_required|jwt_required|fresh_jwt_required|auth_required|token_required"
    r"|requires_auth|roles_required|roles_accepted|admin_required|permission_required)"
)
DJANGO_DECORATORS = re.compile(
    r"(?:\w+\.)*(login_required|permission_required|user_passes_test|staff_member_required"
    r"|superuser_required)"
)
DJANGO_MIXINS = re.compile(r"(LoginRequired|PermissionRequired|UserPassesTest)Mixin")
DRF_VIEW = re.compile(r"(?:APIView|ViewSet|GenericAPIView)$")
READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
VIEW_ACTIONS = {
    "get": "GET", "head": "HEAD", "options": "OPTIONS", "list": "GET", "retrieve": "GET",
    "post": "POST", "create": "POST", "put": "PUT", "update": "PUT", "patch": "PATCH",
    "partial_update": "PATCH", "delete": "DELETE", "destroy": "DELETE",
}  # fmt: skip
JS_AUTH_CALL = re.compile(
    r"\b(auth|getServerSession|getSession|currentUser|getAuth|requireAuth|requireUser"
    r"|getCurrentUser|verifyToken|getToken|validateRequest|getKindeServerSession|getUser"
    r"|withAuth)\s*\("
)
JS_ADMIN_CHECK = re.compile(r"""isAdmin|role\s*[!=]==?\s*['"]admin['"]|['"]admin['"]\s*[!=]==?""")
NEXT_AUTH_TEXT = re.compile(r"auth|clerkMiddleware|withAuth|getToken|updateSession|session")
DJANGO_SUBJECTS = ("request.user", "self.request.user")
FLASK_SUBJECTS = ("current_user", "g.user", "get_jwt_identity")


def py_unread(ctx: Context) -> str:
    """An app-level auth middleware class or request hook that may guard every route."""
    key = ("py-unread-auth", "")
    if key in ctx.index.cache:
        return ctx.index.cache[key]
    found = ""
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if found or is_test(entry.rel) or not re.search(r"(?i)middleware|before_request", text):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for call in pyast.calls(tree, r"(?:\w+\.)*(?:add_middleware|Middleware)") if tree else []:
            name = pyast.dotted(call.args[0]) if call.args else None
            if name and auth_middleware(name.split(".")[-1]):
                found = f"{name} in {entry.rel}"
                break
        for fn in pyast.functions(tree) if tree and not found else []:
            for dec in fn.decorator_list:
                name = pyast.dotted(dec.func if isinstance(dec, ast.Call) else dec) or ""
                if not found and PY_HOOK.fullmatch(name) and HOOK_AUTH.search(ast.unparse(fn)):
                    found = f"the {fn.name} request hook in {entry.rel}"
    ctx.index.cache[key] = found
    return found


def _decorator_names(node: ast.AST) -> list[tuple[str, ast.AST]]:
    found = []
    for dec in getattr(node, "decorator_list", []):
        target = dec.func if isinstance(dec, ast.Call) else dec
        found.append(((pyast.dotted(target) or ""), dec))
    return found


def flask(ctx: Context, route: Route) -> Access:
    for name, dec in _decorator_names(route.handler):
        match = FLASK_DECORATORS.fullmatch(name)
        if not match:
            continue
        text = ast.unparse(dec)
        admin = "admin" in text.lower()
        return Access(ADMIN if admin else AUTHENTICATED, FLASK_SUBJECTS, f"@{match.group(1)}")
    return public("no login decorator", py_unread(ctx))


def _settings_names(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Assign):
        return [t.id for t in node.targets if isinstance(t, ast.Name)]
    if isinstance(node, ast.AugAssign | ast.AnnAssign) and isinstance(node.target, ast.Name):
        return [node.target.id]
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return [pyast.dotted(node.func.value) or ""]
    return []


def _permission_names(node: ast.AST | None) -> list[str]:
    """Class names in a permission list: strings ("rest_framework.permissions.X") or names."""
    names = []
    for item in ast.walk(node) if node is not None else []:
        value = pyast.constant(item, None)
        if isinstance(value, str):
            names.append(value.split(".")[-1])
        elif isinstance(item, ast.Name | ast.Attribute) and not isinstance(item.ctx, ast.Store):
            names.append((pyast.dotted(item) or "").split(".")[-1])
    return [n for n in names if n]


def _permission_kind(names: list[str]) -> str | None:
    """'admin', 'authenticated', 'read-only' (sign-in for writes only) or None."""
    if "IsAdminUser" in names:
        return "admin"
    if "IsAuthenticated" in names:
        return "authenticated"
    if {"IsAuthenticatedOrReadOnly", "DjangoModelPermissionsOrAnonReadOnly"} & set(names):
        return "read-only"
    return None


def _drf_default(node: ast.AST) -> ast.AST | None:
    """The DEFAULT_PERMISSION_CLASSES value in a REST_FRAMEWORK dict literal, update() or
    subscript assignment."""
    if isinstance(node, ast.Assign | ast.AnnAssign) and "REST_FRAMEWORK" in _settings_names(node):
        dicts = [node.value]
    elif isinstance(node, ast.Call) and "REST_FRAMEWORK" in _settings_names(node):
        dicts = list(node.args)
    elif (
        isinstance(node, ast.Assign)
        and isinstance(node.targets[0], ast.Subscript)
        and pyast.dotted(node.targets[0].value) == "REST_FRAMEWORK"
        and pyast.constant(node.targets[0].slice, None) == "DEFAULT_PERMISSION_CLASSES"
    ):
        return node.value
    else:
        return None
    for value in dicts:
        if isinstance(value, ast.Dict):
            for key, item in zip(value.keys, value.values, strict=True):
                if pyast.constant(key, None) == "DEFAULT_PERMISSION_CLASSES":
                    return item
    return None


def django_settings(ctx: Context) -> tuple[bool, str | None, str]:
    """From every non-test settings module, read as a syntax tree so comments never count:
    LoginRequiredMiddleware listed, the DRF default permission kind, and a custom auth
    middleware the classifier cannot read."""
    key = ("django-settings-auth", "")
    if key in ctx.index.cache:
        return ctx.index.cache[key]
    login, drf, unread = False, None, ""
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if not re.search(r"INSTALLED_APPS|REST_FRAMEWORK|MIDDLEWARE", text) or is_test(entry.rel):
            continue
        holds = "INSTALLED_APPS" in text or "REST_FRAMEWORK" in text
        tree = pyast.parse_file(ctx.index, entry.rel)
        for node in ast.walk(tree) if tree else []:
            default = _drf_default(node) if holds else None
            if default is not None:
                drf = _permission_kind(_permission_names(default))
            if "MIDDLEWARE" not in _settings_names(node):
                continue
            for item in ast.walk(node):
                value = pyast.constant(item, None)
                if not isinstance(value, str):
                    continue
                if value.endswith("LoginRequiredMiddleware"):
                    login = True
                elif not value.startswith("django.") and auth_middleware(value.split(".")[-1]):
                    unread = unread or f"{value} in {entry.rel}"
    ctx.index.cache[key] = (login, drf, unread)
    return ctx.index.cache[key]


def _view_methods(node: ast.AST | None) -> set[str] | None:
    """HTTP methods a DRF view serves, or None when they cannot be read."""
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
        for name, dec in _decorator_names(node):
            if name.endswith("api_view"):
                args = dec.args if isinstance(dec, ast.Call) else []
                values = [pyast.constant(e, None) for a in args[:1] for e in ast.walk(a)]
                return {v.upper() for v in values if isinstance(v, str)} or {"GET"}
        return None
    if not isinstance(node, ast.ClassDef):
        return None
    defined = {
        VIEW_ACTIONS[item.name]
        for item in node.body
        if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef) and item.name in VIEW_ACTIONS
    }
    bases = " ".join(pyast.base_names(node))
    if re.search(r"ReadOnly|\bList\w*APIView|\bRetrieveAPIView", bases):
        defined.add("GET")
    if re.search(r"ModelViewSet|Create|Update|Destroy", bases) and "ReadOnly" not in bases:
        defined |= {"GET", "POST"}
    return defined or None


def _permission_access(route: Route, kind: str, evidence: str) -> Access:
    if kind == "admin":
        return Access(ADMIN, DJANGO_SUBJECTS, evidence)
    if kind == "authenticated":
        return Access(AUTHENTICATED, DJANGO_SUBJECTS, evidence)
    methods = _view_methods(route.handler)
    if methods is not None and methods <= READ_METHODS:
        return Access(PUBLIC, (), f"{evidence} on a read-only view")
    if methods is not None and not methods & READ_METHODS:
        return Access(AUTHENTICATED, DJANGO_SUBJECTS, evidence)
    return Access(
        PUBLIC, (), f"{evidence} (reads need no sign-in)", MIXED, f"{evidence} for writes"
    )


def _django_marker(route: Route) -> Access | None:
    node = route.handler
    for name, dec in _decorator_names(node):
        match = DJANGO_DECORATORS.fullmatch(name)
        if match:
            admin = match.group(1) in ("staff_member_required", "superuser_required")
            return Access(ADMIN if admin else AUTHENTICATED, DJANGO_SUBJECTS, f"@{match.group(1)}")
        if name.endswith("permission_classes"):
            names = _permission_names(dec)
            if "AllowAny" in names and not _permission_kind(names):
                return Access(PUBLIC, (), "AllowAny")
            kind = _permission_kind(names) or "authenticated"
            evidence = "IsAdminUser" if kind == "admin" else "permission_classes"
            return _permission_access(route, kind, evidence)
    if isinstance(node, ast.ClassDef):
        if any(DJANGO_MIXINS.search(b) for b in pyast.base_names(node)):
            return Access(AUTHENTICATED, DJANGO_SUBJECTS, "login mixin")
        value = pyast.assignments(node.body).get("permission_classes")
        if value is not None:
            names = _permission_names(value)
            if "AllowAny" in names and not _permission_kind(names):
                return Access(PUBLIC, (), "AllowAny")
            kind = _permission_kind(names) or "authenticated"
            evidence = "IsAdminUser" if kind == "admin" else "permission_classes"
            return _permission_access(route, kind, evidence)
    return None


def _login_not_required(node: ast.AST) -> bool:
    return any(
        name.endswith("login_not_required")
        or (name.endswith("method_decorator") and "login_not_required" in ast.unparse(dec))
        for name, dec in _decorator_names(node)
    )


def _is_drf(route: Route) -> bool:
    node = route.handler
    if route.framework == "drf":
        return True
    if isinstance(node, ast.ClassDef):
        return any(DRF_VIEW.search(base) for base in pyast.base_names(node))
    return any(name.endswith("api_view") for name, _ in _decorator_names(node))


def django(ctx: Context, route: Route) -> Access:
    node = route.handler
    marker = _django_marker(route) if node is not None else None
    if marker is not None and marker.level != PUBLIC:
        return marker
    login, drf, unread = django_settings(ctx)
    drf_view = _is_drf(route)
    exempt = node is not None and _login_not_required(node)
    if login and not exempt and not drf_view:
        return Access(AUTHENTICATED, DJANGO_SUBJECTS, "LoginRequiredMiddleware")
    if exempt:
        return Access(PUBLIC, (), "@login_not_required")
    if marker is not None:
        return marker
    if node is None:
        return public("view not resolved", unread)
    if drf and drf_view:
        return _permission_access(route, drf, "DEFAULT_PERMISSION_CLASSES")
    return public("no login decorator or permission class", unread)


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
