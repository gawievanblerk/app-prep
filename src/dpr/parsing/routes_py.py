"""Routes for Django, Django REST Framework, FastAPI and Flask."""

from __future__ import annotations

import ast
import re
from pathlib import PurePosixPath

from dpr.model import Route
from dpr.parsing import pyast
from dpr.walk import RepoIndex

VERBS = ("get", "post", "put", "patch", "delete")
URL_CALL = re.compile(r"(?:\w+\.)?(path|re_path|url)")
REGISTER_CALL = re.compile(r"(?:\w+\.)*register")
TOP_LEVEL_DEF = re.compile(r"^(?:async\s+def|def|class)\s", re.MULTILINE)
DEFS_KEY = ("py", "top-level definitions")


def _methods(decorator: ast.Call, default: list[str]) -> list[str]:
    node = pyast.kwarg(decorator, "methods")
    if isinstance(node, ast.List | ast.Tuple):
        values = [pyast.constant(e, None) for e in node.elts]
        return [v.upper() for v in values if isinstance(v, str)] or default
    return default


def decorator_routes(index: RepoIndex) -> list[Route]:
    routes = []
    for entry in index.py_files:
        text = index.text(entry.rel).lower()
        framework = "fastapi" if "fastapi" in text else "flask" if "flask" in text else None
        if framework is None:
            continue
        tree = pyast.parse_file(index, entry.rel)
        if tree is None:
            continue
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
                for method in methods:
                    routes.append(
                        Route(method, path, entry.rel, fn.lineno, framework, handler=fn, tree=tree)
                    )
    return routes


def _view_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        node = node.func
    parts = [p for p in (pyast.dotted(node) or "").split(".") if p and p != "as_view"]
    return parts[-1] if parts else None


def _top_level_defs(index: RepoIndex) -> dict[str, list[tuple[str, ast.stmt, ast.Module]]]:
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


def _find_view(index: RepoIndex, urls_rel: str, name: str | None):
    """The view named in a URL pattern, preferring a definition under the urls.py folder."""
    if not name:
        return None, None, None
    folder = PurePosixPath(urls_rel).parent.as_posix()
    prefix = "" if folder == "." else folder + "/"
    candidates = _top_level_defs(index).get(name, [])
    local = next((c for c in candidates if c[0].startswith(prefix)), None)
    rel, node, tree = local or (candidates[0] if candidates else (None, None, None))
    return node, rel, tree


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
            handler, rel, view_tree = _find_view(index, entry.rel, _view_name(view))
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
            handler, rel, view_tree = _find_view(index, entry.rel, _view_name(call.args[1]))
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
