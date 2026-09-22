"""Review 3 inputs: which routes carry each account flow, and the code each flow runs."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from dpr.discovery.approots import root_of, same_root
from dpr.model import DataModel, Location, Route, Tag
from dpr.parsing import jsts, pyast
from dpr.reviews.access import ADMIN, PUBLIC, access
from dpr.reviews.lookups import _helper
from dpr.reviews.paid import _js_target
from dpr.reviews.paths import is_test
from dpr.rules import Context
from dpr.walk import line_of

KINDS = (
    ("logout", re.compile(r"log-?out|sign-?out")),
    ("refresh", re.compile(r"(?:auth|token|session)\S*refresh|refresh\S*(?:token|session)")),
    ("register", re.compile(r"sign-?up|register|create-?account")),
    ("forgot", re.compile(r"forgot|request-?reset|reset-?request|send-?reset|recover")),
    ("reset", re.compile(r"reset")),
    ("verify", re.compile(r"verif|confirm-?email|activate")),
    ("login", re.compile(r"log-?in|sign-?in|/token$|authenticate")),
)
WRITE_METHODS = ("POST", "PUT", "PATCH", "ANY", "ACTION")
SELF_SEGMENT = re.compile(r"^(?:users?|me|profile|account|settings)$")
PARAM_SEGMENT = re.compile(r"^\{[^{}]*\}$|^:[^/]+$|^<[^<>]*>$|^\*[^/]*$")
USER_MODEL = re.compile(
    r"(?i)^(?:auth_?)?(?:user|users|account|accounts|member|members|customer|customers|profile|profiles)$"
)
MANAGED = {
    "supabase-auth": "Supabase Auth",
    "clerk": "Clerk",
    "auth0": "Auth0",
    "nextauth": "Auth.js",
    "firebase-auth": "Firebase Authentication",
    "better-auth": "Better Auth",
}
LIFETIME_NAME = re.compile(
    r"(?i)(?:access|refresh|session|jwt|token|cookie)\w*(?:expire|expiry|expiration|lifetime|max_?age|ttl|age)\w*"
    r"|SESSION_COOKIE_AGE"
)
JS_EXPIRES = re.compile(r"""\b(expiresIn|maxAge)\s*:\s*(['"][^'"]+['"]|\d[\d_*\s]*)""")
GENERIC_RECEIVER = re.compile(
    r"(?i)^(?:self|db|session|conn|connection|cursor|dict|data|payload|result|request|response"
    r"|cache|redis|client|settings|os|json|\w*_?(?:db|session|dict|list|map))$"
)
GENERIC_CALLS = frozenset(
    {"get", "items", "keys", "values", "append", "extend", "add", "commit", "execute", "refresh",
     "close", "copy", "update", "pop", "setdefault", "scalars", "scalar_one_or_none", "all",
     "first", "one", "flush", "delete", "merge", "format", "strip", "lower", "upper", "split",
     "join", "encode", "decode", "startswith", "endswith", "replace", "model_dump", "dict"}
)  # fmt: skip


@dataclass(frozen=True)
class Code:
    rel: str
    node: object = field(compare=False)
    tree: object = field(compare=False)
    line: int = 0

    @property
    def python(self) -> bool:
        return isinstance(self.node, ast.AST)

    def text(self) -> str:
        return ast.unparse(self.node) if self.python else jsts.node_text(self.node)


@dataclass(frozen=True)
class Flow:
    kind: str
    route: Route
    code: tuple[Code, ...]

    @property
    def location(self) -> Location:
        return Location(self.route.file, self.route.line)


def record_pass(ctx: Context, case: int | str, tag: Tag, text: str, location: Location) -> None:
    """Rules call this with evidence that a case holds, so the section can say PASSES."""
    ctx.facts.setdefault("auth_passes", {}).setdefault(case, []).append((tag, text, location))


def managed_provider(ctx: Context) -> str | None:
    names = [MANAGED[p] for p in ctx.detection.auth_providers if p in MANAGED]
    return ", ".join(names) or None


def _is_self_path(path: str) -> bool:
    """A self word (users, me, profile, account, settings) counts only when no path parameter
    segment (`{id}`, `:id`, `<id>`, a catch-all) comes before it in the route path."""
    seen_param = False
    for segment in path.split("/"):
        if not segment:
            continue
        if PARAM_SEGMENT.fullmatch(segment):
            seen_param = True
        elif not seen_param and SELF_SEGMENT.fullmatch(segment):
            return True
    return False


def _kind(ctx: Context, route: Route) -> str | None:
    name = getattr(route.handler, "name", "")
    name = name if isinstance(name, str) else ""
    subject = f"{route.path} {name}".lower()
    level = access(ctx, route).level
    for kind, pattern in KINDS:
        if pattern.search(subject):
            if kind != "verify" and route.method not in WRITE_METHODS:
                return None
            if kind in ("register", "login", "forgot", "reset") and level != PUBLIC:
                return None
            return kind
    if route.method in ("PUT", "PATCH") and _is_self_path(route.path) and level != ADMIN:
        return "update_self" if level != PUBLIC else None
    return None


def _py_code(ctx: Context, route: Route, depth: int = 2) -> list[Code]:
    found = [Code(route.file, route.handler, route.tree, route.line)]
    queue = [(route.file, route.handler, 0)]
    seen = {(route.file, route.line)}
    while queue:
        rel, fn, level = queue.pop(0)
        if level >= depth:
            continue
        for call in [n for n in ast.walk(fn) if isinstance(n, ast.Call)]:
            parts = (pyast.dotted(call.func) or "").split(".")
            receiver = parts[-2] if len(parts) > 1 else ""
            if parts[-1] in GENERIC_CALLS and (not receiver or GENERIC_RECEIVER.search(receiver)):
                continue
            helper = _helper(ctx, rel, call, fn)
            if helper is None or is_test(helper[0]):
                continue
            key = (helper[0], helper[1].lineno)
            if key in seen:
                continue
            seen.add(key)
            tree = pyast.parse_file(ctx.index, helper[0])
            found.append(Code(helper[0], helper[1], tree, helper[1].lineno))
            queue.append((helper[0], helper[1], level + 1))
    return found


def _js_code(ctx: Context, route: Route, depth: int = 2) -> list[Code]:
    handler = route.handler
    if handler is None or getattr(handler, "type", "") not in jsts.FUNCTION_TYPES:
        return []
    found = [Code(route.file, handler, route.tree, route.line)]
    queue = [(route.tree, handler, 0)]
    seen = {(route.file, handler.start_byte)}
    while queue:
        tree, fn, level = queue.pop(0)
        if level >= depth:
            continue
        for call in jsts.walk(fn, {"call_expression"}):
            target = _js_target(ctx, tree, call)
            if target is None:
                continue
            target_tree, target_fn, _exact = target
            if target_fn is None or target_fn is fn:
                continue
            key = (target_tree.rel, target_fn.start_byte)
            if key in seen or is_test(target_tree.rel):
                continue
            seen.add(key)
            found.append(
                Code(target_tree.rel, target_fn, target_tree, jsts.line(target_tree, target_fn))
            )
            queue.append((target_tree, target_fn, level + 1))
    return found


def route_code(ctx: Context, route: Route, depth: int = 2) -> list[Code]:
    """The handler plus the helpers it calls, followed `depth` calls deep."""
    if isinstance(route.handler, ast.AST):
        return _py_code(ctx, route, depth)
    return _js_code(ctx, route, depth)


def flows(ctx: Context) -> list[Flow]:
    if "auth_flows" not in ctx.facts:
        found = []
        for route in ctx.detection.routes:
            if is_test(route.file):
                continue
            kind = _kind(ctx, route)
            if kind is None:
                continue
            code = route_code(ctx, route)
            if code:
                found.append(Flow(kind, route, tuple(code)))
        ctx.facts["auth_flows"] = found
    return ctx.facts["auth_flows"]


def flows_of(ctx: Context, *kinds: str) -> list[Flow]:
    return [f for f in flows(ctx) if f.kind in kinds]


def user_models(ctx: Context) -> list[DataModel]:
    return [
        m
        for m in ctx.detection.models
        if USER_MODEL.match(m.name) or USER_MODEL.match(m.table.split(".")[-1])
    ]


def user_models_in(ctx: Context, rel: str) -> list[DataModel]:
    """User models in the app root of `rel`: a model in another root never decides a flow."""
    roots = ctx.detection.app_roots
    return [m for m in user_models(ctx) if same_root(roots, m.location.file, rel)]


def lifetimes(ctx: Context, root: str | None = None) -> list[tuple[str, str, Location]]:
    """Session and token lifetimes written as constants: (name, value, location).

    With `root` (an `AppRoot.path`), only settings inside that app root are returned. Code that
    pairs a lifetime with a flow must pass that flow's root so evidence never crosses app roots.
    """
    found = []
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel) or not LIFETIME_NAME.search(text):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for node in ast.walk(tree) if tree else []:
            target = (
                node.target
                if isinstance(node, ast.AnnAssign)
                else (node.targets[0] if isinstance(node, ast.Assign) else None)
            )
            if not isinstance(target, ast.Name) or not LIFETIME_NAME.fullmatch(target.id):
                continue
            value = node.value
            if isinstance(value, ast.Constant | ast.BinOp) and not isinstance(
                pyast.constant(value, None), str | bool
            ):
                found.append((target.id, ast.unparse(value), Location(entry.rel, node.lineno)))
    for entry in ctx.index.js_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel):
            continue
        for match in JS_EXPIRES.finditer(text):
            found.append(
                (
                    match.group(1),
                    match.group(2).strip(),
                    Location(entry.rel, line_of(text, match.start())),
                )
            )
    if root is None:
        return found
    return [
        item
        for item in found
        if (home := root_of(ctx.detection.app_roots, item[2].file)) is not None
        and home.path == root
    ]
