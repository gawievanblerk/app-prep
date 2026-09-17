"""Route access: public, authenticated or admin, and the names that hold the caller."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from dpr.model import Route
from dpr.parsing import jsts, pyast
from dpr.rules import Context

PUBLIC, AUTHENTICATED, ADMIN = "public", "authenticated", "admin"
AUTH_WORD = re.compile(
    r"(?i)user|auth|login|session|token|principal|identity|staff|agent|member|account|verify"
    r"|require|current|jwt|bearer|api_?key|oauth|protect|ensure|logged|passport"
)
ADMIN_WORD = re.compile(r"(?i)admin|superuser|super_user")
PY_DEP = re.compile(r"(?:\w+\.)*(?:Depends|Security)")
FLASK_DECORATORS = re.compile(
    r"(?:\w+\.)*(login_required|jwt_required|fresh_jwt_required|auth_required|token_required"
    r"|requires_auth|roles_required|roles_accepted|admin_required|permission_required)"
)
DJANGO_DECORATORS = re.compile(
    r"(?:\w+\.)*(login_required|permission_required|user_passes_test|staff_member_required"
    r"|superuser_required)"
)
DJANGO_MIXINS = re.compile(r"(LoginRequired|PermissionRequired|UserPassesTest)Mixin")
JS_AUTH_CALL = re.compile(
    r"\b(auth|getServerSession|getSession|currentUser|getAuth|requireAuth|requireUser"
    r"|getCurrentUser|verifyToken|getToken|validateRequest|getKindeServerSession|getUser"
    r"|withAuth)\s*\("
)
JS_ADMIN_CHECK = re.compile(r"""isAdmin|role\s*[!=]==?\s*['"]admin['"]|['"]admin['"]\s*[!=]==?""")
EXPRESS_SUBJECTS = ("req.user", "req.auth", "req.session", "request.user")
DJANGO_SUBJECTS = ("request.user", "self.request.user")
FLASK_SUBJECTS = ("current_user", "g.user", "get_jwt_identity")


@dataclass(frozen=True)
class Access:
    level: str
    subjects: tuple[str, ...] = ()
    evidence: str = ""


def _dep_level(name: str) -> str | None:
    roles = set(
        re.findall(
            r"admin|superuser|staff|manager|agent|member|client|customer|editor"
            r"|viewer|owner|above|any",
            name.lower(),
        )
    )
    if roles and roles <= {"admin", "superuser", "staff"} and ADMIN_WORD.search(name):
        return ADMIN
    if AUTH_WORD.search(name) or ADMIN_WORD.search(name):
        return AUTHENTICATED
    return None


def _strongest(levels: list[str]) -> str:
    if ADMIN in levels:
        return ADMIN
    return AUTHENTICATED if AUTHENTICATED in levels else PUBLIC


def _dep_names(node: ast.AST | None, aliases: dict[str, str]) -> list[str]:
    names = []
    for sub in ast.walk(node) if node is not None else []:
        if isinstance(sub, ast.Call) and PY_DEP.fullmatch(pyast.dotted(sub.func) or ""):
            if sub.args:
                names.append((pyast.dotted(sub.args[0]) or "").split(".")[-1])
        elif isinstance(sub, ast.Name) and sub.id in aliases:
            names.append(aliases[sub.id])
    return [n for n in names if n]


def fastapi_aliases(ctx: Context) -> dict[str, str]:
    key = ("fastapi-aliases", "")
    if key in ctx.index.cache:
        return ctx.index.cache[key]
    aliases: dict[str, str] = {}
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if "Annotated" not in text or "Depends" not in text and "Security" not in text:
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for name, value in pyast.assignments(tree.body if tree else []).items():
            if isinstance(value, ast.Subscript) and pyast.dotted(value.value) in (
                "Annotated",
                "typing.Annotated",
            ):
                found = _dep_names(value.slice, {})
                if found:
                    aliases[name] = found[0]
    ctx.index.cache[key] = aliases
    return aliases


def _router_deps(tree: ast.Module, aliases: dict[str, str]) -> list[str]:
    names = []
    for value in pyast.assignments(tree.body).values():
        if isinstance(value, ast.Call) and re.fullmatch(
            r"(?:\w+\.)?(APIRouter|FastAPI)", pyast.dotted(value.func) or ""
        ):
            names += _dep_names(pyast.kwarg(value, "dependencies"), aliases)
    return names


def _fastapi(ctx: Context, route: Route) -> Access:
    aliases = fastapi_aliases(ctx)
    fn = route.handler
    levels: list[tuple[str, str]] = []
    subjects = []
    params = [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
    defaults = [None] * (len(fn.args.posonlyargs) + len(fn.args.args) - len(fn.args.defaults))
    defaults += [*fn.args.defaults, *fn.args.kw_defaults]
    for param, default in zip(params, defaults, strict=True):
        for name in _dep_names(param.annotation, aliases) + _dep_names(default, aliases):
            level = _dep_level(name)
            if level:
                levels.append((level, name))
                subjects.append(param.arg)
    for dec in fn.decorator_list:
        if isinstance(dec, ast.Call):
            for name in _dep_names(pyast.kwarg(dec, "dependencies"), aliases):
                if _dep_level(name):
                    levels.append((_dep_level(name), name))
    for name in _router_deps(route.tree, aliases):
        if _dep_level(name):
            levels.append((_dep_level(name), name))
    if not levels:
        return Access(PUBLIC, (), "no authentication dependency")
    level = _strongest([lv for lv, _ in levels])
    names = ", ".join(dict.fromkeys(name for _, name in levels))
    return Access(level, tuple(dict.fromkeys(subjects)), f"Depends({names})")


def _decorator_names(node: ast.AST) -> list[tuple[str, ast.AST]]:
    found = []
    for dec in getattr(node, "decorator_list", []):
        target = dec.func if isinstance(dec, ast.Call) else dec
        found.append(((pyast.dotted(target) or ""), dec))
    return found


def _flask(route: Route) -> Access:
    for name, dec in _decorator_names(route.handler):
        match = FLASK_DECORATORS.fullmatch(name)
        if not match:
            continue
        text = ast.unparse(dec)
        admin = "admin" in text.lower()
        return Access(ADMIN if admin else AUTHENTICATED, FLASK_SUBJECTS, f"@{match.group(1)}")
    return Access(PUBLIC, (), "no login decorator")


def _drf_default(ctx: Context) -> bool:
    key = ("drf-default-auth", "")
    if key not in ctx.index.cache:
        ctx.index.cache[key] = any(
            "DEFAULT_PERMISSION_CLASSES" in ctx.index.text(f.rel)
            and "IsAuthenticated" in ctx.index.text(f.rel)
            for f in ctx.index.named("settings.py", "base.py", "production.py")
        )
    return ctx.index.cache[key]


def _django(ctx: Context, route: Route) -> Access:
    node = route.handler
    if node is None:
        return Access(PUBLIC, (), "view not resolved")
    for name, dec in _decorator_names(node):
        match = DJANGO_DECORATORS.fullmatch(name)
        if match:
            admin = match.group(1) in ("staff_member_required", "superuser_required")
            return Access(ADMIN if admin else AUTHENTICATED, DJANGO_SUBJECTS, f"@{match.group(1)}")
        if name.endswith("permission_classes"):
            text = ast.unparse(dec)
            if "IsAdminUser" in text:
                return Access(ADMIN, DJANGO_SUBJECTS, "IsAdminUser")
            if "AllowAny" in text:
                return Access(PUBLIC, (), "AllowAny")
            return Access(AUTHENTICATED, DJANGO_SUBJECTS, "permission_classes")
    if isinstance(node, ast.ClassDef):
        if any(DJANGO_MIXINS.search(b) for b in pyast.base_names(node)):
            return Access(AUTHENTICATED, DJANGO_SUBJECTS, "login mixin")
        value = pyast.assignments(node.body).get("permission_classes")
        if value is not None:
            text = ast.unparse(value)
            if "IsAdminUser" in text:
                return Access(ADMIN, DJANGO_SUBJECTS, "IsAdminUser")
            if "AllowAny" not in text:
                return Access(AUTHENTICATED, DJANGO_SUBJECTS, "permission_classes")
            return Access(PUBLIC, (), "AllowAny")
    if route.framework == "drf" and _drf_default(ctx):
        return Access(AUTHENTICATED, DJANGO_SUBJECTS, "DEFAULT_PERMISSION_CLASSES")
    return Access(PUBLIC, (), "no login decorator or permission class")


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


def _matcher_covers(text: str, path: str) -> bool:
    patterns = re.findall(r"""['"](/[^'"]*)['"]""", text[text.find("matcher") :])
    if "matcher" not in text or not patterns:
        return True
    for pattern in patterns:
        prefix = re.split(r"[:(\[*]", pattern, maxsplit=1)[0].rstrip("/")
        if "(?!" in pattern or not prefix or path == prefix or path.startswith(prefix + "/"):
            return True
    return False


def _next_middleware(ctx: Context, path: str) -> bool:
    for entry in ctx.index.named("middleware.ts", "middleware.js"):
        if entry.rel not in (
            "middleware.ts",
            "middleware.js",
            "src/middleware.ts",
            "src/middleware.js",
        ):
            continue
        text = ctx.index.text(entry.rel)
        if re.search(r"auth|clerkMiddleware|withAuth|getToken|updateSession|session", text):
            if _matcher_covers(text, path):
                return True
    return False


def _auth_wrappers(route: Route) -> list[str]:
    return [name for name in route.wrappers if AUTH_WORD.search(name) or ADMIN_WORD.search(name)]


def _next(ctx: Context, route: Route) -> Access:
    handler = route.handler
    text = jsts.node_text(handler) if handler is not None else ""
    if JS_AUTH_CALL.search(text) or "auth.getUser" in text:
        level = ADMIN if JS_ADMIN_CHECK.search(text) else AUTHENTICATED
        return Access(level, _js_subjects(handler), "auth call in handler")
    names = _auth_wrappers(route)
    if names:
        level = ADMIN if any(ADMIN_WORD.search(name) for name in names) else AUTHENTICATED
        return Access(
            level,
            _js_subjects(handler) if handler is not None else (),
            "wrapper " + ", ".join(names[:3]),
        )
    if _next_middleware(ctx, route.path):
        return Access(AUTHENTICATED, (), "middleware matcher")
    return Access(PUBLIC, (), "no auth call and no middleware matcher")


def _express(route: Route) -> Access:
    tree = route.tree
    names: list[str] = []
    for call in jsts.calls(tree, r"(?:\w+\.)*(?:get|post|put|patch|delete|all|use)"):
        if jsts.line(tree, call) > route.line:
            continue
        args = jsts.arguments(call)
        is_route = jsts.line(tree, call) == route.line
        middle = args[1:-1] if is_route else args
        if not is_route and not jsts.callee(call).endswith(".use"):
            continue
        names += [jsts.node_text(a) for a in middle if a.type != "string"]
    names += route.wrappers
    names = list(dict.fromkeys(names))
    auth = [n for n in names if AUTH_WORD.search(n) or ADMIN_WORD.search(n)]
    if not auth:
        return Access(PUBLIC, (), "no auth middleware")
    admin = any(ADMIN_WORD.search(n) or "role" in n.lower() for n in auth)
    return Access(ADMIN if admin else AUTHENTICATED, EXPRESS_SUBJECTS, ", ".join(auth[:3]))


def _classify(ctx: Context, route: Route) -> Access:
    if route.framework == "fastapi" and isinstance(route.handler, ast.AST):
        return _fastapi(ctx, route)
    if route.framework == "flask" and isinstance(route.handler, ast.AST):
        return _flask(route)
    if route.framework in ("django", "drf"):
        return _django(ctx, route)
    if route.framework.startswith("next"):
        return _next(ctx, route)
    if route.framework in ("express", "fastify") and route.tree is not None:
        return _express(route)
    return Access(PUBLIC, (), "framework not classified")


def access(ctx: Context, route: Route) -> Access:
    cache = ctx.facts.setdefault("access", {})
    if route not in cache:
        cache[route] = _classify(ctx, route)
    return cache[route]


def path_params(route: Route) -> list[str]:
    path = route.path
    found = re.findall(r"\{(\w+)(?::[^}]*)?\}", path)
    found += re.findall(r"<(?:\w+:)?(\w+)>", path)
    found += re.findall(r"\(\?P<(\w+)>", path)
    found += re.findall(r"(?:^|/):(\w+)", path)
    found += re.findall(r"(?:^|/)\*(\w+)", path)
    return list(dict.fromkeys(found))
