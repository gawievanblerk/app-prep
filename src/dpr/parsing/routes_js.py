"""Routes for Next.js (app router, pages router, server actions), Express and Fastify."""

from __future__ import annotations

import re

from dpr.model import Route
from dpr.parsing import jsts
from dpr.walk import RepoIndex

HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
APP_ROUTE = re.compile(r"(?:^|/)app/((?:[^/]+/)*)route\.(?:[cm]?[jt]s)$")
PAGES_API = re.compile(r"(?:^|/)pages/api/(.+)\.(?:[cm]?[jt]sx?)$")
SERVER_CALL = re.compile(
    r"(?:app|router|server|fastify|routes|\w+Router|\w+router)\.(get|post|put|patch|delete|all)"
)
SERVER_HINT = re.compile(r"\.(?:get|post|put|patch|delete|all)\(\s*['\"`]/")
PAGES_METHOD = re.compile(r"""req\.method\s*[!=]==?\s*['"]([A-Z]+)['"]""")


def segments_to_path(segments: list[str]) -> str:
    parts = []
    for seg in segments:
        if not seg or (seg.startswith("(") and seg.endswith(")")) or seg.startswith("@"):
            continue
        if seg.startswith("[[...") and seg.endswith("]]"):
            parts.append("*" + seg[5:-2])
        elif seg.startswith("[...") and seg.endswith("]"):
            parts.append("*" + seg[4:-1])
        elif seg.startswith("[") and seg.endswith("]"):
            parts.append(":" + seg[1:-1])
        else:
            parts.append(seg)
    return "/" + "/".join(parts)


def next_app_routes(index: RepoIndex) -> list[Route]:
    routes = []
    for entry in index.js_files:
        match = APP_ROUTE.search(entry.rel)
        if not match:
            continue
        path = segments_to_path(match.group(1).strip("/").split("/"))
        for tree in jsts.parse_file(index, entry.rel):
            for name, fn in jsts.exported_functions(tree).items():
                if name in HTTP_METHODS:
                    routes.append(
                        Route(
                            name,
                            path,
                            entry.rel,
                            jsts.line(tree, fn),
                            "next-app",
                            handler=fn,
                            tree=tree,
                        )
                    )
    return routes


def next_pages_routes(index: RepoIndex) -> list[Route]:
    routes = []
    for entry in index.js_files:
        match = PAGES_API.search(entry.rel)
        if not match:
            continue
        segments = match.group(1).split("/")
        if segments[-1] == "index":
            segments = segments[:-1]
        path = segments_to_path(["api", *segments])
        for tree in jsts.parse_file(index, entry.rel):
            handler = jsts.exported_functions(tree).get("default")
            if handler is None:
                continue
            methods = sorted(set(PAGES_METHOD.findall(jsts.node_text(handler)))) or ["ANY"]
            for method in methods:
                routes.append(
                    Route(
                        method,
                        path,
                        entry.rel,
                        jsts.line(tree, handler),
                        "next-pages",
                        handler=handler,
                        tree=tree,
                    )
                )
    return routes


def server_actions(index: RepoIndex) -> list[Route]:
    routes = []
    for entry in index.js_files:
        if "use server" not in index.text(entry.rel):
            continue
        for tree in jsts.parse_file(index, entry.rel):
            if not jsts.has_directive(tree):
                continue
            exported = jsts.exported_functions(tree)
            seen: set[int] = set()
            for name, fn in exported.items():
                if name == "default" or fn.start_byte in seen:
                    continue
                seen.add(fn.start_byte)
                routes.append(
                    Route(
                        "ACTION",
                        f"action:{name}",
                        entry.rel,
                        jsts.line(tree, fn),
                        "next-action",
                        handler=fn,
                        tree=tree,
                    )
                )
            default = exported.get("default")
            if default is not None and default.start_byte not in seen:
                routes.append(
                    Route(
                        "ACTION",
                        "action:default",
                        entry.rel,
                        jsts.line(tree, default),
                        "next-action",
                        handler=default,
                        tree=tree,
                    )
                )
    return routes


def server_routes(index: RepoIndex) -> list[Route]:
    routes = []
    for entry in index.js_files:
        text = index.text(entry.rel)
        if not SERVER_HINT.search(text):
            continue
        framework = "fastify" if "fastify" in text else "express"
        for tree in jsts.parse_file(index, entry.rel):
            for call in jsts.calls(tree, SERVER_CALL):
                args = jsts.arguments(call)
                path = jsts.string_value(args[0]) if len(args) >= 2 else None
                if path is None or not path.startswith("/"):
                    continue
                handler = jsts.unwrap(args[-1])
                if handler is not None and handler.type == "identifier":
                    handler = _function_named(tree, jsts.node_text(handler)) or handler
                allowed = jsts.FUNCTION_TYPES | {"identifier", "member_expression"}
                if handler is None or handler.type not in allowed:
                    continue
                method = jsts.callee(call).rsplit(".", 1)[1].upper()
                routes.append(
                    Route(
                        "ANY" if method == "ALL" else method,
                        path,
                        entry.rel,
                        jsts.line(tree, call),
                        framework,
                        handler=handler,
                        tree=tree,
                    )
                )
    return routes


def _function_named(tree: jsts.JsTree, name: str):
    for node in jsts.walk(tree.root, {"function_declaration"}):
        if jsts.node_text(node.child_by_field_name("name")) == name:
            return node
    for decl in jsts.walk(tree.root, {"variable_declarator"}):
        value = jsts.unwrap(decl.child_by_field_name("value"))
        if jsts.node_text(decl.child_by_field_name("name")) == name and value is not None:
            if value.type in jsts.FUNCTION_TYPES:
                return value
    return None
