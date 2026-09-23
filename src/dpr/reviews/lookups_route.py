"""Unscoped lookups per route: Python function and class views, and JS and TS handlers."""

from __future__ import annotations

import ast
import re

from dpr.model import Location, Route
from dpr.parsing import jsts, pyast
from dpr.reviews.access import Access
from dpr.reviews.lookups import (
    NOT_A_CHECK,
    VIEW_METHODS,
    Lookup,
    py_checked_after,
    py_lookups,
    request_keys,
    statement_target,
    statements,
    subject_text,
)
from dpr.reviews.request_values import trace
from dpr.reviews.visibility import js_visible, js_written_after
from dpr.rules import Context

JS_ORM = re.compile(
    r"(?:\w+)\.(\w+)\.(findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow|update|delete"
    r"|upsert)$|^(\w+)\.(findById|findByIdAndUpdate|findByIdAndDelete|findOne)$"
)
JS_KEY = re.compile(
    r"\b(?:params|req\.params|req\.query|request\.params|context\.params)\.(\w+)"
    r"|searchParams\.get\(\s*['\"](\w+)['\"]"
)

ONE_TIME_KEYS = re.compile(r"(?i)token|code|otp|nonce|signature|secret")


def js_keys(handler) -> set[str]:
    text = jsts.node_text(handler)
    keys = {next(g for g in m.groups() if g) for m in JS_KEY.finditer(text)}
    for match in re.finditer(r"\{\s*([\w\s,:]+)\}\s*=\s*(?:await\s+)?(?:\w+\.)?params\b", text):
        keys.update(n.strip().split(":")[-1].strip() for n in match.group(1).split(","))
    return {k for k in keys if k and not ONE_TIME_KEYS.search(k)}


def js_lookups(route: Route, subjects: tuple[str, ...]) -> list[Lookup]:
    tree, handler = route.tree, route.handler
    keys = js_keys(handler)
    found = []
    for call in jsts.calls(tree, re.compile(r".*"), handler):
        match = JS_ORM.search(jsts.callee(call))
        if not match:
            continue
        text = jsts.node_text(call)
        used = {k for k in keys if re.search(rf"\b{re.escape(k)}\b", text)}
        if not used or subject_text(text, subjects):
            continue
        model = match.group(1) or match.group(3)
        target = None
        parent = call.parent
        while parent is not None and parent.type in (
            "await_expression",
            "parenthesized_expression",
        ):
            parent = parent.parent
        if parent is not None and parent.type == "variable_declarator":
            target = jsts.node_text(parent.child_by_field_name("name"))
        pk = bool(re.search(r"\bid\s*:|findById", text))
        found.append(
            Lookup(
                Location(route.file, jsts.line(tree, call)),
                tuple(sorted(used)),
                model,
                pk,
                target,
                visible=js_visible(call) and not js_written_after(handler, call, target),
            )
        )
    return found


def js_checked_after(route: Route, lookup: Lookup, subjects: tuple[str, ...]) -> str:
    for node in jsts.walk(route.handler, {"binary_expression"}):
        if jsts.line(route.tree, node) <= lookup.location.line:
            continue
        text = jsts.node_text(node)
        if subject_text(text, subjects) and (
            lookup.target is None or re.search(rf"\b{re.escape(lookup.target)}\b", text)
        ):
            return "owner"
    return ""


PY_FRAMEWORKS = ("fastapi", "flask", "django", "drf", "ninja")


def handler_functions(handler: ast.AST) -> list[ast.AST]:
    """A function view, or the HTTP method and action handlers of a class view."""
    if isinstance(handler, ast.FunctionDef | ast.AsyncFunctionDef):
        return [handler]
    if not isinstance(handler, ast.ClassDef):
        return []
    return [
        item
        for item in handler.body
        if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef)
        and (item.name in VIEW_METHODS or "action" in ast.unparse(item).split("\n", 1)[0])
    ]


def _passes_caller(value: ast.AST) -> bool:
    """A serializer, form or response built with the caller in its context: it holds the
    caller, but is not the caller."""
    return isinstance(value, ast.Call) and bool(NOT_A_CHECK.search(pyast.dotted(value.func) or ""))


def _py_route(
    ctx: Context, route: Route, fn: ast.AST, subjects: tuple[str, ...]
) -> list[tuple[Lookup, str]]:
    derived = tuple(
        statement_target(s)
        for s in statements(fn)
        if statement_target(s)
        and subject_text(ast.unparse(s.value), subjects)
        and not _passes_caller(s.value)
    )
    subjects = (*subjects, *derived)
    keys = request_keys(route, fn)
    taint = trace(fn, {k: k for k in keys}, route.framework)
    checked = [
        (item, py_checked_after(fn, item, subjects))
        for item in py_lookups(ctx, route.file, fn, keys, subjects, taint=taint)
    ]
    verified = {k for item, check in checked if check == "owner" for k in item.keys}
    return [(item, check) for item, check in checked if not set(item.keys) <= verified]


def route_lookups(ctx: Context, route: Route, access: Access) -> list[tuple[Lookup, str]]:
    """Unscoped lookups of a route with the later check kind: 'owner', 'helper' or ''."""
    subjects = access.subjects
    if isinstance(route.handler, ast.AST) and route.framework in PY_FRAMEWORKS:
        return [
            found
            for fn in handler_functions(route.handler)
            for found in _py_route(ctx, route, fn, subjects)
        ]
    if route.tree is not None and route.handler is not None and hasattr(route.handler, "type"):
        if route.handler.type in jsts.FUNCTION_TYPES:
            subjects = (*subjects, *(("req.user",) if route.framework == "express" else ()))
            return [
                (item, js_checked_after(route, item, subjects))
                for item in js_lookups(route, subjects)
            ]
    return []
