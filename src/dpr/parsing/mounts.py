"""Router mount prefixes: FastAPI include_router and Express app.use, applied to route paths."""

from __future__ import annotations

import ast
import re
from dataclasses import replace
from pathlib import PurePosixPath

from dpr.model import Route
from dpr.parsing import jsts, pyast
from dpr.walk import RepoIndex

JS_DEFAULT_IMPORT = re.compile(
    r"""import\s+(\w+)\s+from\s+['"](\.[^'"]+)['"]"""
    r"""|(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*['"](\.[^'"]+)['"]\s*\)"""
)
LIMITER = re.compile(r"(?i)rate_?limit|limiter|slow_?down|throttle")
JS_EXTENSIONS = (".ts", ".tsx", ".js", ".mjs", ".cjs", ".jsx")
VERBS = ("get", "post", "put", "patch", "delete", "route", "api_route")
Node = tuple[str, str]


def _shared(a: str, b: str) -> int:
    count = 0
    for left, right in zip(a.split("/"), b.split("/"), strict=False):
        if left != right:
            break
        count += 1
    return count


def _module_file(index: RepoIndex, importer: str, module: str, level: int = 0) -> str | None:
    if level:
        base = PurePosixPath(importer).parent
        for _ in range(level - 1):
            base = base.parent
        stem = (base / module.replace(".", "/")).as_posix() if module else base.as_posix()
        wanted = (f"{stem}.py", f"{stem}/__init__.py")
        return next((f.rel for f in index.py_files if f.rel in wanted), None)
    tail = module.replace(".", "/")
    found = [
        f.rel
        for f in index.py_files
        if f.rel in (f"{tail}.py", f"{tail}/__init__.py")
        or f.rel.endswith((f"/{tail}.py", f"/{tail}/__init__.py"))
    ]
    return max(found, key=lambda rel: _shared(rel, importer)) if found else None


def _py_imports(index: RepoIndex, rel: str, tree: ast.Module) -> dict[str, Node]:
    """Local name to (file, attribute); attribute "" means the name is the module itself."""
    names: dict[str, Node] = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                local = alias.asname or alias.name
                sub = f"{node.module}.{alias.name}" if node.module else alias.name
                as_module = _module_file(index, rel, sub, node.level)
                if as_module is not None:
                    names[local] = (as_module, "")
                    continue
                owner = _module_file(index, rel, node.module or "", node.level)
                if owner is not None:
                    names[local] = (owner, alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                owner = _module_file(index, rel, alias.name)
                if owner is not None and alias.asname:
                    names[alias.asname] = (owner, "")
    return names


def _settings_default(index: RepoIndex, attribute: str) -> str | None:
    values = set()
    for entry in index.py_files:
        if attribute not in index.text(entry.rel):
            continue
        tree = pyast.parse_file(index, entry.rel)
        for cls in pyast.class_defs(tree) if tree else []:
            value = pyast.assignments(cls.body).get(attribute)
            text = pyast.constant(value, None)
            if isinstance(text, str):
                values.add(text)
    return values.pop() if len(values) == 1 else None


def _py_prefix(index: RepoIndex, tree: ast.Module, node: ast.AST | None) -> str | None:
    if node is None:
        return ""
    value = pyast.constant(node, None)
    if isinstance(value, str):
        return value
    if isinstance(node, ast.Name):
        found = pyast.constant(pyast.assignments(tree.body).get(node.id), None)
        return found if isinstance(found, str) else None
    if isinstance(node, ast.Attribute):
        return _settings_default(index, node.attr)
    return None


def _py_edges(index: RepoIndex) -> dict[Node, tuple[Node, str]]:
    """Included router to (parent router, prefix added at the include)."""
    edges: dict[Node, tuple[Node, str]] = {}
    for entry in index.py_files:
        text = index.text(entry.rel)
        if "include_router" not in text:
            continue
        tree = pyast.parse_file(index, entry.rel)
        if tree is None:
            continue
        imports = _py_imports(index, entry.rel, tree)
        for call in pyast.calls(tree, r"(?:\w+\.)*\w+\.include_router"):
            if not call.args or not isinstance(call.func, ast.Attribute):
                continue
            parent = (entry.rel, pyast.dotted(call.func.value) or "")
            child_expr = call.args[0]
            if isinstance(child_expr, ast.Name):
                child = imports.get(child_expr.id, (entry.rel, child_expr.id))
            elif isinstance(child_expr, ast.Attribute) and isinstance(child_expr.value, ast.Name):
                module = imports.get(child_expr.value.id)
                if module is None or module[1]:
                    continue
                child = (module[0], child_expr.attr)
            else:
                continue
            prefix = _py_prefix(index, tree, pyast.kwarg(call, "prefix"))
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


def _js_target(index: RepoIndex, importer: str, spec: str) -> str | None:
    base = (PurePosixPath(importer).parent / spec).as_posix()
    parts = []
    for part in base.split("/"):
        if part == "..":
            parts = parts[:-1]
        elif part not in (".", ""):
            parts.append(part)
    stem = "/".join(parts)
    stripped = re.sub(r"\.(?:[cm]?js|jsx|ts|tsx)$", "", stem)
    files = {f.rel for f in index.js_files}
    candidates = [stem] + [stripped + ext for ext in JS_EXTENSIONS]
    candidates += [f"{stripped}/index{ext}" for ext in JS_EXTENSIONS]
    return next((c for c in candidates if c in files), None)


def _js_mounts(index: RepoIndex) -> tuple[dict[str, str], list[tuple[str, str]]]:
    """Route file to mount prefix, and (mounting file, prefix) for each limiter middleware."""
    routers: dict[str, str] = {}
    limiters: list[tuple[str, str]] = []
    for entry in index.js_files:
        text = index.text(entry.rel)
        if ".use(" not in text:
            continue
        imports = {}
        for match in JS_DEFAULT_IMPORT.finditer(text):
            name, spec = match.group(1) or match.group(3), match.group(2) or match.group(4)
            target = _js_target(index, entry.rel, spec)
            if target:
                imports[name] = target
        for tree in jsts.parse_file(index, entry.rel):
            for call in jsts.calls(tree, r"\w+\.use"):
                args = jsts.arguments(call)
                prefix = jsts.string_value(args[0]) if args else None
                handlers = args[1:] if prefix is not None else args
                for handler in handlers:
                    name = jsts.node_text(handler)
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
