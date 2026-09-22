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
FASTIFY_HOOKS = ("onRequest", "preParsing", "preValidation", "preHandler")
SERVER_HANDLER_TYPES = jsts.FUNCTION_TYPES | {"identifier", "member_expression", "call_expression"}
RESPONSE_ROOTS = frozenset({"res", "reply", "NextResponse", "Response"})
RESPONSE_METHODS = frozenset({"json", "send"})


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
            for name, (fn, wrappers) in jsts.exported_handlers(tree).items():
                if name in HTTP_METHODS:
                    routes.append(
                        Route(
                            name,
                            path,
                            entry.rel,
                            jsts.line(tree, fn),
                            "next-app",
                            wrappers=wrappers,
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
            handler, wrappers = jsts.exported_handlers(tree).get("default", (None, ()))
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
                        wrappers=wrappers,
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
            exported = jsts.exported_handlers(tree)
            seen: set[int] = set()
            named = [(n, h) for n, h in exported.items() if n != "default"]
            if "default" in exported:
                named.append(("default", exported["default"]))
            for name, (fn, wrappers) in named:
                if fn.start_byte in seen:
                    continue
                seen.add(fn.start_byte)
                routes.append(
                    Route(
                        "ACTION",
                        f"action:{name}",
                        entry.rel,
                        jsts.line(tree, fn),
                        "next-action",
                        wrappers=wrappers,
                        handler=fn,
                        tree=tree,
                    )
                )
    return routes


def _middleware_names(node) -> list[str]:
    node = jsts.unwrap(node)
    if node is None:
        return []
    if node.type in ("identifier", "shorthand_property_identifier", "member_expression"):
        return [re.sub(r"\s+", "", jsts.node_text(node))]
    if node.type == "call_expression":
        return [jsts.callee(node)]
    if node.type == "array":
        return [name for item in node.named_children for name in _middleware_names(item)]
    if node.type == "object":
        pairs = jsts.object_pairs(node)
        return [name for hook in FASTIFY_HOOKS for name in _middleware_names(pairs.get(hook))]
    return []


def _server_handler(tree: jsts.JsTree, node) -> tuple[object, tuple[str, ...]]:
    handler, wrappers = jsts.resolve_handler(tree.root, node)
    if handler is None:
        return jsts.unwrap(node), ()
    return handler, wrappers


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
                handler, wrappers = _server_handler(tree, args[-1])
                if handler is None or handler.type not in SERVER_HANDLER_TYPES:
                    continue
                middleware = [name for arg in args[1:-1] for name in _middleware_names(arg)]
                method = jsts.callee(call).rsplit(".", 1)[1].upper()
                routes.append(
                    Route(
                        "ANY" if method == "ALL" else method,
                        path,
                        entry.rel,
                        jsts.line(tree, call),
                        framework,
                        wrappers=(*middleware, *wrappers),
                        handler=handler,
                        tree=tree,
                    )
                )
    return routes


def is_response_call(call) -> bool:
    """True for .json or .send at the end of a res, reply, NextResponse or Response chain.

    A bare json(...) call (the Remix helper) also counts.
    """
    function = jsts.unwrap(call.child_by_field_name("function"))
    if function is not None and function.type == "identifier":
        return jsts.node_text(function) == "json"
    if function is None or function.type != "member_expression":
        return False
    if jsts.node_text(function.child_by_field_name("property")) not in RESPONSE_METHODS:
        return False
    node = jsts.unwrap(function.child_by_field_name("object"))
    while node is not None and node.type in ("call_expression", "member_expression"):
        field = "function" if node.type == "call_expression" else "object"
        node = jsts.unwrap(node.child_by_field_name(field))
    return node is not None and node.type == "identifier" and jsts.node_text(node) in RESPONSE_ROOTS


def response_calls(within) -> list:
    return [c for c in jsts.walk(within, {"call_expression"}) if is_response_call(c)]
