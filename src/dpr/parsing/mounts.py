"""Router mount prefixes: FastAPI include_router and Express app.use, applied to route paths."""

from __future__ import annotations

import ast
import re
from dataclasses import replace

from dpr.discovery.approots import app_roots as _detect_app_roots
from dpr.discovery.approots import root_of
from dpr.model import AppRoot, Route
from dpr.parsing import jsts, pyast
from dpr.parsing.imports import js_target, py_imports
from dpr.reviews.paths import is_test
from dpr.walk import RepoIndex

# A router mount only ever binds a local name to the mounted file's default export (or a bare
# require()); dpr.parsing.imports.js_imports resolves every import kind (named, namespace, ...),
# which is more than mount detection needs, so this keeps its own narrower regex and reuses only
# js_target's spec-to-file resolution (which also covers the `@/` and `~/` aliases js_target
# supports, unlike the previous local copy).
JS_DEFAULT_IMPORT = re.compile(
    r"""import\s+(\w+)\s+from\s+['"]((?:\.|[@~]/)[^'"]+)['"]"""
    r"""|(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*['"]((?:\.|[@~]/)[^'"]+)['"]\s*\)"""
)
LIMITER = re.compile(r"(?i)rate_?limit|limiter|slow_?down|throttle")
VERBS = ("get", "post", "put", "patch", "delete", "route", "api_route")
Node = tuple[str, str]


def _app_roots(index: RepoIndex) -> list[AppRoot]:
    """App roots by folder alone (no routes or CI needed: only `.path` is used here), so this
    can run before `dpr.discovery.detect` has computed the real `Detection.app_roots`."""
    key = ("mounts-app-roots", "")
    if key not in index.cache:
        index.cache[key] = _detect_app_roots(index, [], [])
    return index.cache[key]


def _settings_default(index: RepoIndex, rel: str, attribute: str) -> str | None:
    """The literal string every class defining `attribute` in `rel`'s app root gives it (the
    whole repository when no app roots are known); None when a defining class in scope gives a
    non-literal value, two disagree, or none defines it."""
    roots = _app_roots(index)
    home = root_of(roots, rel) if roots else None
    values: set[str] = set()
    for entry in index.py_files:
        if attribute not in index.text(entry.rel):
            continue
        if roots and root_of(roots, entry.rel) != home:
            continue
        tree = pyast.parse_file(index, entry.rel)
        for cls in pyast.class_defs(tree) if tree else []:
            assignments = pyast.assignments(cls.body)
            if attribute not in assignments:
                continue
            text = pyast.constant(assignments[attribute], None)
            if not isinstance(text, str):
                return None
            values.add(text)
    return values.pop() if len(values) == 1 else None


def _py_prefix(index: RepoIndex, rel: str, tree: ast.Module, node: ast.AST | None) -> str | None:
    if node is None:
        return ""
    value = pyast.constant(node, None)
    if isinstance(value, str):
        return value
    if isinstance(node, ast.Name):
        found = pyast.constant(pyast.assignments(tree.body).get(node.id), None)
        return found if isinstance(found, str) else None
    if isinstance(node, ast.Attribute):
        return _settings_default(index, rel, node.attr)
    return None


def _py_edges(index: RepoIndex) -> dict[Node, tuple[Node, str]]:
    """Included router to (parent router, prefix added at the include). Test files are never
    mount evidence, matching access.py's own mount reading."""
    edges: dict[Node, tuple[Node, str]] = {}
    for entry in index.py_files:
        if is_test(entry.rel):
            continue
        text = index.text(entry.rel)
        if "include_router" not in text:
            continue
        tree = pyast.parse_file(index, entry.rel)
        if tree is None:
            continue
        imports = py_imports(index, entry.rel, tree)
        for call in pyast.calls(tree, r"(?:\w+\.)*\w+\.include_router"):
            if not call.args or not isinstance(call.func, ast.Attribute):
                continue
            parent = (entry.rel, pyast.dotted(call.func.value) or "")
            child_expr = call.args[0]
            if isinstance(child_expr, ast.Name):
                found = imports.get(child_expr.id)
                child = (found[0], found[1]) if found and found[0] else (entry.rel, child_expr.id)
            elif isinstance(child_expr, ast.Attribute) and isinstance(child_expr.value, ast.Name):
                found = imports.get(child_expr.value.id)
                if found is None or found[0] is None or found[1]:
                    continue
                child = (found[0], child_expr.attr)
            else:
                continue
            prefix = _py_prefix(index, entry.rel, tree, pyast.kwarg(call, "prefix"))
            if prefix is not None and child not in edges:
                edges[child] = (parent, prefix.rstrip("/"))
    return edges


def _full_prefix(edges: dict[Node, tuple[Node, str]], node: Node) -> str:
    parts, seen = [], set()
    while node in edges and node not in seen:
        seen.add(node)
        node, prefix = edges[node]
        parts.append(prefix)
    return "".join(reversed(parts))


def _router_name(route: Route) -> str | None:
    for dec in getattr(route.handler, "decorator_list", []):
        if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
            if dec.func.attr in VERBS:
                return pyast.dotted(dec.func.value)
    return None


def _handler_name(handler) -> str | None:
    """The name a mounted handler is known by: an identifier or member name, or the callee of an
    inline call such as `rateLimit({...})`. An inline function has no name and is not read."""
    if handler.type in ("identifier", "member_expression"):
        return jsts.node_text(handler)
    if handler.type == "call_expression":
        return jsts.callee(handler)
    return None


def _js_mounts(index: RepoIndex) -> tuple[dict[str, str], list[tuple[str, str]]]:
    """Route file to mount prefix, and (mounting file, prefix) for each limiter middleware.

    Test files are never mount evidence, matching access.py's own mount reading.
    """
    routers: dict[str, str] = {}
    limiters: list[tuple[str, str]] = []
    for entry in index.js_files:
        if is_test(entry.rel):
            continue
        text = index.text(entry.rel)
        if ".use(" not in text:
            continue
        imports = {}
        for match in JS_DEFAULT_IMPORT.finditer(text):
            name, spec = match.group(1) or match.group(3), match.group(2) or match.group(4)
            target = js_target(index, entry.rel, spec)
            if target:
                imports[name] = target
        for tree in jsts.parse_file(index, entry.rel):
            for call in jsts.calls(tree, r"\w+\.use"):
                args = jsts.arguments(call)
                prefix = jsts.string_value(args[0]) if args else None
                handlers = args[1:] if prefix is not None else args
                for handler in handlers:
                    name = _handler_name(handler)
                    if name is None:
                        continue
                    if handler.type == "identifier" and name in imports and prefix:
                        routers.setdefault(imports[name], prefix.rstrip("/"))
                    declared = re.search(
                        rf"(?:const|let|var)\s+{re.escape(name)}\s*=\s*([\w.]+)\(", text
                    )
                    if LIMITER.search(name) or (declared and LIMITER.search(declared.group(1))):
                        limiters.append((entry.rel, (prefix or "/").rstrip("/")))
    return routers, limiters


def limiter_mounts(index: RepoIndex) -> list[tuple[str, str]]:
    key = ("js-limiter-mounts", "")
    if key not in index.cache:
        index.cache[key] = _js_mounts(index)[1]
    return index.cache[key]


def apply_mounts(index: RepoIndex, routes: list[Route]) -> list[Route]:
    edges = _py_edges(index)
    js_routers, _ = _js_mounts(index)
    mounted = []
    for route in routes:
        prefix = ""
        if route.framework == "fastapi":
            name = _router_name(route)
            prefix = _full_prefix(edges, (route.file, name)) if name else ""
        elif route.framework in ("express", "fastify"):
            prefix = js_routers.get(route.file, "")
        if prefix and not route.path.startswith(prefix + "/"):
            path = prefix + (route.path if route.path != "/" else "")
            route = replace(route, path=path)
        mounted.append(route)
    return mounted
