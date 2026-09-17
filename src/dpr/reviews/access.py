"""Route access: public, authenticated or admin, and the names that hold the caller.

Router mounts are read here as well: FastAPI include_router dependencies and Express
middleware placed in front of a router where another file mounts it.
"""

from __future__ import annotations

import ast
import re

from dpr.model import Route
from dpr.parsing import imports, jsts, pyast
from dpr.reviews import access_frameworks as frameworks
from dpr.reviews.access_names import (
    ABSENCE,
    ADMIN,
    ADMIN_WORD,
    AUTHENTICATED,
    EXPLICIT,
    PUBLIC,
    PY_DEP,
    Access,
    auth_name,
    dep_level,
    public,
    strongest,
    unread_guard,
)
from dpr.rules import Context

__all__ = [
    "ABSENCE",
    "ADMIN",
    "AUTHENTICATED",
    "EXPLICIT",
    "PUBLIC",
    "PY_DEP",
    "Access",
    "access",
    "fastapi_aliases",
    "path_params",
    "unread_guard",
]
SESSION_TYPE = re.compile(r"(?:^|[\[.\s|,(])(?:Async)?Session\b")
ROUTE_VERBS = ("get", "post", "put", "patch", "delete", "head", "options", "route", "api_route")
SERVER_VERB = re.compile(r"(?:\w+\.)*(?:get|post|put|patch|delete|all)")
USE_CALL = re.compile(r"(?:\w+\.)+use")
NON_AUTH_MIDDLEWARE = re.compile(
    r"(?i)(?:^|\.)(?:json|urlencoded|static|raw|text|initialize|session|cookieSession"
    r"|expressSession|cookieParser|bodyParser|cors|helmet|morgan|compression|\w*logger|\w*logging"
    r"|\w*errorHandler|notFound\w*|rateLimit\w*|\w*limiter|slowDown|csrf|csurf|multer|hpp|xss\w*"
    r"|\w*sanitize\w*|timeout|responseTime|serveStatic|favicon|methodOverride|pino\w*"
    r"|requestHandler|tracingHandler|i18n\w*)$"
)
ROUTER_NAME = re.compile(r"(?i)(?:router|routes)$")
EXPRESS_SUBJECTS = ("req.user", "req.auth", "req.session", "request.user")


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


def _router_name(fn: ast.AST) -> str | None:
    for dec in getattr(fn, "decorator_list", []):
        if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
            if dec.func.attr in ROUTE_VERBS:
                return pyast.dotted(dec.func.value)
    return None


def _constructor_deps(tree: ast.Module | None, name: str, aliases: dict[str, str]) -> list[str]:
    value = pyast.assignments(tree.body).get(name) if tree is not None else None
    if isinstance(value, ast.Call) and re.fullmatch(
        r"(?:\w+\.)?(APIRouter|FastAPI)", pyast.dotted(value.func) or ""
    ):
        return _dep_names(pyast.kwarg(value, "dependencies"), aliases)
    return []


def _router_ref(rel: str, names: dict, expr: ast.AST) -> tuple[str, str] | None:
    """The (file, variable) of the router passed to include_router."""
    if isinstance(expr, ast.Name):
        file, attr, _module = names.get(expr.id, (rel, expr.id, ""))
        return (file, attr) if file and attr else None
    if isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name):
        file, attr, _module = names.get(expr.value.id, (None, "", ""))
        return (file, expr.attr) if file and not attr else None
    return None


def _include_edges(ctx: Context) -> dict[tuple[str, str], list[tuple[tuple[str, str], list]]]:
    """Included router to the routers that include it, with the include call's dependencies."""
    key = ("fastapi-include-edges", "")
    if key not in ctx.index.cache:
        aliases = fastapi_aliases(ctx)
        edges: dict[tuple[str, str], list[tuple[tuple[str, str], list]]] = {}
        for entry in ctx.index.py_files:
            if "include_router" not in ctx.index.text(entry.rel):
                continue
            tree = pyast.parse_file(ctx.index, entry.rel)
            names = imports.py_imports(ctx.index, entry.rel, tree)
            for call in pyast.calls(tree, r"(?:\w+\.)*\w+\.include_router") if tree else []:
                child = _router_ref(entry.rel, names, call.args[0]) if call.args else None
                if child is None or not isinstance(call.func, ast.Attribute):
                    continue
                parent = (entry.rel, pyast.dotted(call.func.value) or "")
                deps = _dep_names(pyast.kwarg(call, "dependencies"), aliases)
                edges.setdefault(child, []).append((parent, deps))
        ctx.index.cache[key] = edges
    return ctx.index.cache[key]


def _inherited(ctx: Context, node: tuple[str, str], depth: int = 0) -> list[str]:
    """Dependencies that include_router chains add above a router, along the weakest chain."""
    parents = _include_edges(ctx).get(node, [])
    if not parents or depth > 4:
        return []
    aliases = fastapi_aliases(ctx)
    options = []
    for (rel, name), deps in parents:
        found = deps + _constructor_deps(pyast.parse_file(ctx.index, rel), name, aliases)
        options.append(found + _inherited(ctx, (rel, name), depth + 1))
    return next((o for o in options if not any(dep_level(n) for n in o)), options[0])


def _fastapi(ctx: Context, route: Route) -> Access:
    aliases = fastapi_aliases(ctx)
    fn = route.handler
    levels: list[tuple[str, str]] = []
    subjects = []
    params = [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
    defaults = [None] * (len(fn.args.posonlyargs) + len(fn.args.args) - len(fn.args.defaults))
    defaults += [*fn.args.defaults, *fn.args.kw_defaults]
    for param, default in zip(params, defaults, strict=True):
        if param.annotation is not None and SESSION_TYPE.search(ast.unparse(param.annotation)):
            continue
        for name in _dep_names(param.annotation, aliases) + _dep_names(default, aliases):
            if dep_level(name):
                levels.append((dep_level(name), name))
                subjects.append(param.arg)
    names = []
    for dec in fn.decorator_list:
        if isinstance(dec, ast.Call):
            names += _dep_names(pyast.kwarg(dec, "dependencies"), aliases)
    router = _router_name(fn)
    if router:
        names += _constructor_deps(route.tree, router, aliases)
        names += _inherited(ctx, (route.file, router))
    levels += [(dep_level(name), name) for name in names if dep_level(name)]
    if not levels:
        return public("no authentication dependency", frameworks.py_unread(ctx))
    level = strongest([lv for lv, _ in levels])
    evidence = ", ".join(dict.fromkeys(name for _, name in levels))
    return Access(level, tuple(dict.fromkeys(subjects)), f"Depends({evidence})")


def _covers(mount: str, path: str) -> bool:
    mount = mount.rstrip("/")
    if not mount:
        return True
    parts = re.split(r"(:\w+|\*)", mount)
    pattern = "".join(
        "[^/]+" if p.startswith(":") else ".*" if p == "*" else re.escape(p) for p in parts
    )
    return re.match(rf"{pattern}(?:/|$)", path) is not None


def _use_args(call) -> tuple[list[str] | None, list]:
    """Mount paths of a .use call (None when it has none) and its middleware arguments."""
    args = jsts.arguments(call)
    first = jsts.unwrap(args[0]) if args else None
    if first is None:
        return None, []
    if first.type == "string":
        return [jsts.string_value(first) or ""], args[1:]
    if first.type == "array":
        return [jsts.string_value(item) or "" for item in first.named_children], args[1:]
    if first.type in ("regex", "template_string"):
        return [""], args[1:]
    return None, args


def _route_files(ctx: Context) -> set[str]:
    if "express-route-files" not in ctx.facts:
        ctx.facts["express-route-files"] = {
            r.file for r in ctx.detection.routes if r.framework in ("express", "fastify")
        }
    return ctx.facts["express-route-files"]


def _mounted_file(ctx: Context, rel: str, node) -> str | None:
    node = jsts.unwrap(node)
    if node is not None and node.type == "identifier":
        target = imports.js_imports(ctx.index, rel).get(jsts.node_text(node), (None, "", ""))[0]
    elif node is not None and node.type == "call_expression" and jsts.callee(node) == "require":
        spec = jsts.string_value(jsts.arguments(node)[0]) if jsts.arguments(node) else None
        target = imports.js_target(ctx.index, rel, spec) if spec else None
    else:
        return None
    return target if target in _route_files(ctx) else None


def _middleware(ctx: Context, rel: str, tree, node) -> tuple[str, str] | None:
    """("auth", name) or ("unknown", name) for a .use argument; None for routers and known
    non-auth middleware such as session(), passport.initialize() or express.json()."""
    node = jsts.unwrap(node)
    if node is not None and node.type in jsts.FUNCTION_TYPES:
        return "unknown", "an inline middleware function"
    if node is None or node.type not in ("identifier", "member_expression", "call_expression"):
        return None
    call = node.type == "call_expression"
    name = jsts.callee(node) if call else re.sub(r"\s+", "", jsts.node_text(node))
    if _mounted_file(ctx, rel, node) or NON_AUTH_MIDDLEWARE.search(name):
        return None
    if node.type == "identifier":
        value = jsts.declared_value(tree.root, name)
        if ROUTER_NAME.search(name) or (value is not None and "Router(" in jsts.node_text(value)):
            return None
    full = jsts.node_text(node)
    if auth_name(name) or ADMIN_WORD.search(full):
        return "auth", full if ADMIN_WORD.search(full) else name
    return "unknown", name


def _uses_before(ctx: Context, rel: str, tree, line: int, path: str) -> tuple[list, list]:
    auth, unknown = [], []
    for call in jsts.calls(tree, USE_CALL):
        if jsts.line(tree, call) >= line:
            continue
        mounts, middleware = _use_args(call)
        if mounts is not None and not any(_covers(m, path) for m in mounts):
            continue
        for arg in middleware:
            kind = _middleware(ctx, rel, tree, arg)
            if kind is not None:
                (auth if kind[0] == "auth" else unknown).append(f"{kind[1]} in {rel}")
    return auth, unknown


def _mounts(ctx: Context) -> dict[str, list[tuple[str, object, int, list[str] | None, list]]]:
    """Route file to every .use call in another file that mounts it."""
    if "express-mounts" not in ctx.facts:
        found: dict[str, list] = {}
        for entry in ctx.index.js_files:
            if ".use(" not in ctx.index.text(entry.rel):
                continue
            for tree in jsts.parse_file(ctx.index, entry.rel):
                for call in jsts.calls(tree, USE_CALL):
                    mounts, middleware = _use_args(call)
                    for arg in middleware:
                        target = _mounted_file(ctx, entry.rel, arg)
                        if target and target != entry.rel:
                            line = jsts.line(tree, call)
                            found.setdefault(target, []).append(
                                (entry.rel, tree, line, mounts, middleware)
                            )
        ctx.facts["express-mounts"] = found
    return ctx.facts["express-mounts"]


def _mount_guards(ctx: Context, rel: str, path: str, depth: int = 0) -> tuple[list, list]:
    """Middleware other files put in front of this router file: auth names along the weakest
    mount, and unknown names from every mount."""
    options, unknown = [], []
    for mount_rel, tree, line, mounts, middleware in _mounts(ctx).get(rel, []) if depth < 4 else []:
        full = (mounts or [""])[0].rstrip("/") + (path if path != "/" else "")
        auth, other = _uses_before(ctx, mount_rel, tree, line, full)
        for arg in middleware:
            kind = _middleware(ctx, mount_rel, tree, arg)
            if kind is not None:
                (auth if kind[0] == "auth" else other).append(f"{kind[1]} in {mount_rel}")
        up_auth, up_other = _mount_guards(ctx, mount_rel, full, depth + 1)
        options.append(auth + up_auth)
        unknown += other + up_other
    return next((o for o in options if not o), options[0] if options else []), unknown


def _express(ctx: Context, route: Route) -> Access:
    tree = route.tree
    same_auth, unknown = _uses_before(ctx, route.file, tree, route.line, route.path)
    names = [name.rsplit(" in ", 1)[0] for name in same_auth]
    for call in jsts.calls(tree, SERVER_VERB):
        if jsts.line(tree, call) == route.line:
            names += [jsts.node_text(a) for a in jsts.arguments(call)[1:-1] if a.type != "string"]
    mount_auth, mount_unknown = _mount_guards(ctx, route.file, route.path)
    names += [*route.wrappers, *(name.rsplit(" in ", 1)[0] for name in mount_auth)]
    auth = [n for n in dict.fromkeys(names) if auth_name(n) or ADMIN_WORD.search(n)]
    if not auth:
        unread = ", ".join(dict.fromkeys(unknown + mount_unknown))
        return public("no auth middleware", f"app-level middleware {unread}" if unread else "")
    admin = any(ADMIN_WORD.search(n) or "role" in n.lower() for n in auth)
    return Access(ADMIN if admin else AUTHENTICATED, EXPRESS_SUBJECTS, ", ".join(auth[:3]))


def _classify(ctx: Context, route: Route) -> Access:
    if route.framework == "fastapi" and isinstance(route.handler, ast.AST):
        return _fastapi(ctx, route)
    if route.framework == "flask" and isinstance(route.handler, ast.AST):
        return frameworks.flask(ctx, route)
    if route.framework in ("django", "drf"):
        return frameworks.django(ctx, route)
    if route.framework.startswith("next"):
        return frameworks.next_js(ctx, route)
    if route.framework in ("express", "fastify") and route.tree is not None:
        return _express(ctx, route)
    return public("framework not classified")


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
