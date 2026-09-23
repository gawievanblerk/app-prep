"""Routes for Django, Django REST Framework, Django Ninja, FastAPI and Flask."""

from __future__ import annotations

import ast
import re
from pathlib import PurePosixPath

from dpr.model import Route
from dpr.parsing import imports, pyast
from dpr.walk import RepoIndex

VERBS = ("get", "post", "put", "patch", "delete")
URL_CALL = re.compile(r"(?:\w+\.)?(path|re_path|url)")
REGISTER_CALL = re.compile(r"(?:\w+\.)*register")
TOP_LEVEL_DEF = re.compile(r"^(?:async\s+def|def|class)\s", re.MULTILINE)
DEFS_KEY = ("py", "top-level definitions")
CELERY_TASK = re.compile(r"(?:\w+\.)*(?:shared_task|task|periodic_task)")


def _methods(decorator: ast.Call, default: list[str]) -> list[str]:
    node = pyast.kwarg(decorator, "methods")
    if isinstance(node, ast.List | ast.Tuple):
        values = [pyast.constant(e, None) for e in node.elts]
        return [v.upper() for v in values if isinstance(v, str)] or default
    return default


def _router_prefixes(tree: ast.Module) -> dict[str, str]:
    found = {}
    for name, value in pyast.assignments(tree.body).items():
        if not isinstance(value, ast.Call):
            continue
        kind = (pyast.dotted(value.func) or "").split(".")[-1]
        keyword = {"APIRouter": "prefix", "Blueprint": "url_prefix"}.get(kind)
        prefix = pyast.constant(pyast.kwarg(value, keyword), None) if keyword else None
        if isinstance(prefix, str):
            found[name] = prefix.rstrip("/")
    return found


def decorator_routes(index: RepoIndex) -> list[Route]:
    routes = []
    for entry in index.py_files:
        text = index.text(entry.rel).lower()
        framework = next((name for name in ("ninja", "fastapi", "flask") if name in text), None)
        if framework is None:
            continue
        tree = pyast.parse_file(index, entry.rel)
        if tree is None:
            continue
        prefixes = _router_prefixes(tree)
        for fn in pyast.functions(tree):
            for dec in fn.decorator_list:
                if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
                    continue
                first = dec.args[0] if dec.args else pyast.kwarg(dec, "path")
                path = pyast.constant(first, None)
                if not isinstance(path, str):
                    continue
                verb = dec.func.attr
                if verb in VERBS:
                    methods = [verb.upper()]
                elif verb == "route":
                    methods = _methods(dec, ["GET"])
                elif verb == "api_route":
                    methods = _methods(dec, ["ANY"])
                else:
                    continue
                full = prefixes.get(pyast.dotted(dec.func.value) or "", "") + path
                for method in methods:
                    routes.append(
                        Route(method, full, entry.rel, fn.lineno, framework, handler=fn, tree=tree)
                    )
    return routes


def _view_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        node = node.func
    parts = [p for p in (pyast.dotted(node) or "").split(".") if p and p != "as_view"]
    return parts[-1] if parts else None


def top_level_defs(index: RepoIndex) -> dict[str, list[tuple[str, ast.stmt, ast.Module]]]:
    """Top-level function and class names mapped to (file, node, tree), built once per index."""
    if DEFS_KEY not in index.cache:
        defs: dict[str, list[tuple[str, ast.stmt, ast.Module]]] = {}
        for entry in sorted(index.py_files, key=lambda f: f.rel):
            if not TOP_LEVEL_DEF.search(index.text(entry.rel)):
                continue
            tree = pyast.parse_file(index, entry.rel)
            for node in tree.body if tree else []:
                if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                    defs.setdefault(node.name, []).append((entry.rel, node, tree))
        index.cache[DEFS_KEY] = defs
    return index.cache[DEFS_KEY]


def _task(node: ast.stmt) -> bool:
    """A Celery task (`@shared_task`, `@app.task`, `@periodic_task`), never a view."""
    for dec in getattr(node, "decorator_list", []):
        name = pyast.dotted(dec.func if isinstance(dec, ast.Call) else dec) or ""
        if CELERY_TASK.fullmatch(name):
            return True
    return False


def defined_in(index: RepoIndex, rel: str | None, name: str, hops: int = 1):
    """The top-level definition of `name` in `rel`, or in the file `rel` imports it from."""
    if rel is None:
        return None
    found = next((c for c in top_level_defs(index).get(name, []) if c[0] == rel), None)
    if found is None and hops:
        target = imports.py_imports(index, rel, pyast.parse_file(index, rel)).get(name)
        if target and target[0] and target[1]:
            return defined_in(index, target[0], target[1], hops - 1)
    return found


def _imported_view(index: RepoIndex, urls_rel: str, tree: ast.Module, view: ast.AST):
    """The definition a urls module's own imports give the view expression, or None."""
    parts = [p for p in (pyast.dotted(view) or "").split(".") if p and p != "as_view"]
    if not parts:
        return None
    names = imports.py_imports(index, urls_rel, tree)
    if len(parts) == 1:
        own = defined_in(index, urls_rel, parts[0], 0)
        target = names.get(parts[0])
        if own is not None or not target or not target[1]:
            return own
        return defined_in(index, target[0], target[1])
    target = names.get(parts[0])
    if not target or target[1]:
        return None
    module = imports.module_file(index, urls_rel, ".".join([target[2], *parts[1:-1]]))
    return defined_in(index, module if len(parts) > 2 else target[0], parts[-1])


def _find_view(index: RepoIndex, urls_rel: str, tree: ast.Module, view: ast.AST):
    """The view named in a URL pattern: the definition the urls module imports, else a view of
    that name (never a Celery task) preferring one under the urls.py folder."""
    name = _view_name(view)
    if not name:
        return None, None, None
    found = _imported_view(index, urls_rel, tree, view.func if isinstance(view, ast.Call) else view)
    if found is not None:
        rel, node, view_tree = found
        return node, rel, view_tree
    folder = PurePosixPath(urls_rel).parent.as_posix()
    prefix = "" if folder == "." else folder + "/"
    candidates = [c for c in top_level_defs(index).get(name, []) if not _task(c[1])]
    local = next((c for c in candidates if c[0].startswith(prefix)), None)
    rel, node, view_tree = local or (candidates[0] if candidates else (None, None, None))
    return node, rel, view_tree


def _url_path(route: str) -> str:
    return "/" + route.strip().lstrip("^").rstrip("$").strip("/")


def django_routes(index: RepoIndex) -> list[Route]:
    routes = []
    for entry in index.named("urls.py"):
        tree = pyast.parse_file(index, entry.rel)
        if tree is None:
            continue
        for call in pyast.calls(tree, URL_CALL):
            route = pyast.constant(call.args[0], None) if len(call.args) >= 2 else None
            if not isinstance(route, str):
                continue
            view = call.args[1]
            if isinstance(view, ast.Call) and (pyast.dotted(view.func) or "").endswith("include"):
                continue
            if isinstance(view, ast.Attribute) and view.attr == "urls":
                continue  # a Django Ninja API or DRF router mounted as a whole
            handler, rel, view_tree = _find_view(index, entry.rel, tree, view)
            routes.append(
                Route(
                    "ANY",
                    _url_path(route),
                    rel or entry.rel,
                    handler.lineno if handler else call.lineno,
                    "django",
                    handler=handler,
                    tree=view_tree,
                )
            )
        for call in pyast.calls(tree, REGISTER_CALL):
            prefix = pyast.constant(call.args[0], None) if len(call.args) >= 2 else None
            if not isinstance(prefix, str):
                continue
            handler, rel, view_tree = _find_view(index, entry.rel, tree, call.args[1])
            routes.append(
                Route(
                    "ANY",
                    _url_path(prefix),
                    rel or entry.rel,
                    handler.lineno if handler else call.lineno,
                    "drf",
                    handler=handler,
                    tree=view_tree,
                )
            )
    return routes
