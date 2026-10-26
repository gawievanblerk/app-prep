"""Internal service calls: a JS/TS route that reaches a paid route of another app root.

The handler is followed up to two calls deep through the calling file's own definitions and
its imports. An outbound `fetch` or `axios` call counts when its URL is a service base (an
environment value, or a constant plain-http URL of a local or bare host name) followed by a
path. A helper whose URL is the base plus one of its own parameters is read at each call site,
where that argument gives the path. The path is matched against the routes of every other app
root; a match that reaches a paid SDK is a service call. The environment name plays no part.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from dpr.discovery.approots import root_of
from dpr.model import Route
from dpr.parsing import imports, jsts
from dpr.reviews.paid import PaidRoute, js_call_target, js_name_target, paid_routes
from dpr.reviews.paths import is_test
from dpr.rules import Context

SERVICE_DEPTH = 2
OUTBOUND = re.compile(r"fetch|axios(?:\.(get|post|put|patch|delete|head|request))?")
ENV_READ = re.compile(
    r"\bprocess\.env\b|\bimport\.meta\.env\b|^(?:env|config|settings)\.\w+|\bgetenv\("
)
LOCAL_URL = re.compile(r"^http://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|[A-Za-z][\w-]*)(?::\d+)?/?$")
CREDIT_CALL = re.compile(
    r"(?i)\b(?:require|check|deduct|consume|charge|spend|reserve)\w*credits?\w*\s*\("
)
PARAM_SEGMENT = re.compile(r"^(?:\{[^{}]*\}|:[^/]+|<[^<>]*>|\*[^/]*)$")
HOLE = "\0"
Segments = tuple[str | None, ...]


@dataclass(frozen=True)
class ServiceCall:
    route: Route
    targets: tuple[PaidRoute, ...]
    helpers: tuple[str, ...]
    exact: bool
    credited: bool


def _declared(ctx: Context, tree, node):
    """The value a name is bound to: in its own scope, at file level, or in the file it is
    imported from."""
    value = jsts.resolve_identifier(node) or jsts.declared_value(tree.root, jsts.node_text(node))
    if value is not None:
        return tree, value
    file, exported, _spec = imports.js_imports(ctx.index, tree.rel).get(
        jsts.node_text(node), (None, "", "")
    )
    for other in jsts.parse_file(ctx.index, file) if file and exported not in ("*", "") else []:
        found = jsts.declared_value(other.root, exported)
        if found is not None:
            return other, found
    return None


def _base_ok(ctx: Context, tree, node, depth: int = 0) -> bool:
    node = jsts.unwrap(node)
    if node is None or depth > 3:
        return False
    text = jsts.node_text(node)
    if ENV_READ.search(text):
        return True
    if node.type == "binary_expression" and re.search(r"\|\||\?\?", text):
        sides = (node.child_by_field_name("left"), node.child_by_field_name("right"))
        return any(_base_ok(ctx, tree, side, depth + 1) for side in sides)
    value = jsts.string_value(node)
    if value is not None:
        return bool(LOCAL_URL.match(value))
    if node.type == "identifier":
        found = _declared(ctx, tree, node)
        return found is not None and _base_ok(ctx, found[0], found[1], depth + 1)
    return False


def _concat(node) -> list:
    node = jsts.unwrap(node)
    if node is not None and node.type == "binary_expression":
        operator = node.child_by_field_name("operator")
        if operator is not None and jsts.node_text(operator) == "+":
            left = node.child_by_field_name("left")
            return [*_concat(left), jsts.unwrap(node.child_by_field_name("right"))]
    return [node]


def _pieces(node) -> list:
    """A URL as a list of literal strings and expression nodes, in order."""
    node = jsts.unwrap(node)
    if node is not None and node.type == "template_string":
        found = []
        for child in node.named_children:
            if child.type == "template_substitution":
                found.append(child.named_children[0] if child.named_children else None)
            elif child.type == "string_fragment":
                found.append(jsts.node_text(child))
        return found
    parts = _concat(node)
    if len(parts) > 1:
        return [p for part in parts for p in _pieces(part)]
    value = jsts.string_value(node)
    return [value] if value is not None else [node]


def _segments(pieces: list) -> Segments | None:
    text = "".join(p if isinstance(p, str) else HOLE for p in pieces)
    if not text.startswith("/"):
        return None
    path = re.split(r"[?#]", text, maxsplit=1)[0]
    return tuple(None if HOLE in s else s for s in path.split("/") if s)


def _route_segments(path: str) -> Segments:
    return tuple(None if PARAM_SEGMENT.match(s) else s for s in path.split("/") if s)


def _params(fn) -> list[str]:
    params = fn.child_by_field_name("parameters")
    names = []
    for param in params.named_children if params is not None else []:
        pattern = param.child_by_field_name("pattern") if param.type != "identifier" else param
        names.append(jsts.node_text(pattern))
    return names


def _method(call, verb: str | None) -> str | None:
    if verb:
        return verb.upper() if verb != "request" else None
    args = jsts.arguments(call)
    if len(args) < 2:
        return "GET"
    options = jsts.unwrap(args[1])
    if options is None or options.type != "object":
        return None
    value = jsts.object_pairs(options).get("method")
    if value is None:
        return None if jsts.has_spread(options) else "GET"
    text = jsts.string_value(value)
    return text.upper() if text else None


def _outbound(ctx: Context, tree, fn, call):
    """("path", segments, method) or ("param", index, method) for a call to another service."""
    match = OUTBOUND.fullmatch(jsts.callee(call))
    args = jsts.arguments(call)
    if match is None or not args:
        return None
    url = jsts.unwrap(args[0])
    if url is not None and url.type == "identifier":
        found = _declared(ctx, tree, url)
        url = found[1] if found is not None and found[0] is tree else url
    pieces = _pieces(url)
    if len(pieces) < 2 or isinstance(pieces[0], str) or not _base_ok(ctx, tree, pieces[0]):
        return None
    method = _method(call, match.group(1))
    rest = pieces[1:]
    if len(rest) == 1 and not isinstance(rest[0], str) and rest[0] is not None:
        name = jsts.node_text(rest[0])
        params = _params(fn)
        return ("param", params.index(name), method) if name in params else None
    segments = _segments(rest)
    return ("path", segments, method) if segments else None


def _path_helper(ctx: Context, tree, fn) -> tuple[int, str | None] | None:
    """(parameter index, method) when the function sends its parameter as the path."""
    key = ("service-path-helper", f"{tree.rel}:{fn.start_byte}")
    if key not in ctx.index.cache:
        found = None
        for call in jsts.walk(fn, {"call_expression"}):
            out = _outbound(ctx, tree, fn, call)
            if out is not None and out[0] == "param":
                found = (out[1], out[2])
                break
        ctx.index.cache[key] = found
    return ctx.index.cache[key]


def _handler(ctx: Context, route: Route):
    node = route.handler
    for _ in range(4):
        node = jsts.unwrap(node)
        if node is None or route.tree is None:
            return None
        if node.type in jsts.FUNCTION_TYPES:
            return route.tree, node, True
        if node.type in ("identifier", "member_expression"):
            return js_name_target(ctx, route.tree, node)
        if node.type != "call_expression" or not jsts.arguments(node):
            return None
        node = jsts.arguments(node)[-1]
    return None


def _trace(ctx: Context, start) -> tuple[list[tuple[Segments, str | None, str, bool]], bool]:
    """Outbound service paths reached from a handler, and whether the code checks credits."""
    hits = []
    credited = False
    queue = [(start[0], start[1], 0, start[2], "")]
    seen = {(start[0].rel, start[1].start_byte)}
    while queue:
        tree, fn, level, exact, via = queue.pop(0)
        credited = credited or bool(CREDIT_CALL.search(jsts.node_text(fn)))
        for call in jsts.walk(fn, {"call_expression"}):
            out = _outbound(ctx, tree, fn, call)
            if out is not None and out[0] == "path":
                hits.append((out[1], out[2], via, exact))
            target = js_call_target(ctx, tree, call)
            if target is None or target[1] is None or is_test(target[0].rel):
                continue
            name = re.findall(r"[\w$]+", jsts.node_text(call.child_by_field_name("function")))[-1]
            helper = _path_helper(ctx, target[0], target[1])
            args = jsts.arguments(call)
            if helper is not None and helper[0] < len(args):
                segments = _segments(_pieces(args[helper[0]]))
                if segments:
                    hits.append((segments, helper[1], name, exact and target[2]))
            key = (target[0].rel, target[1].start_byte)
            if level < SERVICE_DEPTH and key not in seen:
                seen.add(key)
                queue.append((target[0], target[1], level + 1, exact and target[2], name))
    return hits, credited


def _matches(path: Segments, route: Route) -> bool:
    other = _route_segments(route.path)
    if len(path) != len(other):
        return False
    pairs = list(zip(path, other, strict=True))
    if any(a is not None and b is not None and a != b for a, b in pairs):
        return False
    return any(a is not None and a == b for a, b in pairs)


def service_calls(ctx: Context) -> list[ServiceCall]:
    if "service_calls" not in ctx.facts:
        found = []
        paid = paid_routes(ctx)
        direct = {p.route for p in paid}
        roots = ctx.detection.app_roots
        for route in ctx.detection.routes if paid else []:
            if route in direct or isinstance(route.handler, ast.AST) or is_test(route.file):
                continue
            start = _handler(ctx, route)
            if start is None or start[1] is None:
                continue
            hits, credited = _trace(ctx, start)
            home = root_of(roots, route.file)
            targets, helpers, exact = [], [], True
            for path, method, via, chain in hits:
                for p in paid:
                    if root_of(roots, p.route.file) == home or not _matches(path, p.route):
                        continue
                    if method is not None and p.route.method not in (method, "ANY"):
                        continue
                    if p not in targets:
                        targets.append(p)
                        helpers.append(via)
                        exact = exact and chain and p.exact
            if targets:
                found.append(ServiceCall(route, tuple(targets), tuple(helpers), exact, credited))
        ctx.facts["service_calls"] = found
    return ctx.facts["service_calls"]
