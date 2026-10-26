"""Review 1, inventory: where personal data comes in (request schemas, bodies, runtime values)."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from dataclasses import dataclass

from dpr.model import Location, Route
from dpr.parsing import jsts, pyast
from dpr.reviews.paths import is_test
from dpr.reviews.personal import classify
from dpr.rules import Context
from dpr.walk import line_of

WRITE_METHODS = ("POST", "PUT", "PATCH", "ANY", "ACTION")
SCHEMA_BASE = r"BaseModel|Serializer|Schema|Form$"
PY_BODY_READ = re.compile(
    r"request\.(?:json|form|POST|data|args|values)\s*(?:\[\s*['\"](\w+)['\"]|\.get\(\s*['\"](\w+)['\"])"
)
JS_BODY_READ = re.compile(r"\b(?:req\.body|body|data|input)\??\.(\w+)")
JS_DESTRUCTURE = re.compile(
    r"\{\s*([\w\s,:]+)\}\s*=\s*(?:await\s+)?(?:req\.body|await\s+req\.json\(\)|body)\b"
)
ZOD_SCHEMA = re.compile(r"(?:export\s+)?const\s+(\w+)\s*=\s*z\.object\(\s*\{([^{}]*)\}")
ZOD_FIELD = re.compile(r"(\w+)\s*:")
ZOD_PARSE = re.compile(r"\b(\w+)\.(?:parse|safeParse|parseAsync)\(\s*([^)]*?)\s*\)")
REQUEST_BODY_EXPR = r"(?:await\s+)?req(?:uest)?\.(?:body|json\(\))"
RUNTIME_SOURCE = "captured at runtime"
RUNTIME = (
    (
        re.compile(
            r"request\.client\.host|req\.ip\b|REMOTE_ADDR|x-forwarded-for|x-real-ip|cf-connecting-ip",
            re.I,
        ),
        "IP address",
    ),
    (re.compile(r"user-agent|HTTP_USER_AGENT|userAgent", re.I), "user agent"),
    (
        re.compile(r"cf-ipcountry|x-vercel-ip-(?:country|city|latitude)|geoip", re.I),
        "approximate location",
    ),
)


@dataclass(frozen=True)
class Collection:
    route: Route | None
    fields: tuple[str, ...]
    location: Location
    source: str


def _schema_classes(ctx: Context) -> dict[str, tuple[str, ast.ClassDef]]:
    """Request and form schema classes, including subclasses of other schema classes."""
    key = ("schema-classes", "")
    if key not in ctx.index.cache:
        classes: dict[str, tuple[str, ast.ClassDef]] = {}
        for entry in ctx.index.py_files:
            text = ctx.index.text(entry.rel)
            if is_test(entry.rel) or not re.search(r"BaseModel|Serializer|Schema|Form\b", text):
                continue
            tree = pyast.parse_file(ctx.index, entry.rel)
            for cls in pyast.class_defs(tree) if tree else []:
                classes.setdefault(cls.name, (entry.rel, cls))
        found: dict[str, tuple[str, ast.ClassDef]] = {}
        for _ in range(4):
            for name, (rel, cls) in classes.items():
                bases = [b.split(".")[-1] for b in pyast.base_names(cls)]
                if any(re.search(SCHEMA_BASE, b) or b in found for b in bases):
                    found.setdefault(name, (rel, cls))
        ctx.index.cache[key] = found
    return ctx.index.cache[key]


def _class_fields(ctx: Context, name: str, depth: int = 0) -> list[str]:
    item = _schema_classes(ctx).get(name)
    if item is None or depth > 2:
        return []
    _rel, cls = item
    fields = [
        s.target.id
        for s in cls.body
        if isinstance(s, ast.AnnAssign) and isinstance(s.target, ast.Name)
    ]
    fields += [
        t.id
        for s in cls.body
        if isinstance(s, ast.Assign) and isinstance(s.value, ast.Call)
        for t in s.targets
        if isinstance(t, ast.Name)
        and re.search(r"Field$|Char|Email", pyast.dotted(s.value.func) or "")
    ]
    for base in pyast.base_names(cls):
        fields += _class_fields(ctx, base.split(".")[-1], depth + 1)
    return fields


def _py_fields(ctx: Context, route: Route) -> tuple[list[str], str]:
    fn = route.handler
    fields, sources = [], []
    # A class-based view is its methods: read the arguments of each one.
    methods = [
        n for n in getattr(fn, "body", []) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    functions = methods if isinstance(fn, ast.ClassDef) else [fn]
    args = [a for f in functions for a in [*f.args.args, *f.args.kwonlyargs]]
    for arg in args:
        if arg.annotation is None:
            continue
        names = re.findall(r"[A-Za-z_]\w*", ast.unparse(arg.annotation))
        for name in names:
            found = _class_fields(ctx, name)
            if found:
                fields += found
                sources.append(name)
    text = ast.unparse(fn)
    fields += [a or b for a, b in PY_BODY_READ.findall(text)]
    for name in re.findall(r"\b(\w+Serializer)\(", text):
        found = _class_fields(ctx, name)
        fields += found
        sources.append(name)
    return fields, ", ".join(sources) or "request body"


def _js_fields(route: Route) -> tuple[list[str], str]:
    text = jsts.node_text(route.handler)
    fields = JS_BODY_READ.findall(text)
    for match in JS_DESTRUCTURE.finditer(text):
        fields += [n.split(":")[0].strip() for n in match.group(1).split(",")]
    return fields, "request body"


def _js_request_body(text: str, arg: str) -> bool:
    """The parse argument is a request body directly, or a variable assigned from one."""
    arg = arg.strip()
    if re.fullmatch(REQUEST_BODY_EXPR, arg):
        return True
    if re.fullmatch(r"[A-Za-z_]\w*", arg):
        return bool(
            re.search(rf"(?:const|let|var)\s+{re.escape(arg)}\s*=\s*{REQUEST_BODY_EXPR}", text)
        )
    return False


def _enclosing_route(ctx: Context, rel: str, line: int) -> Route | None:
    """The innermost route in `rel` whose handler spans `line`."""
    best, size = None, None
    for route in ctx.detection.routes:
        handler = route.handler
        if route.file != rel or handler is None or isinstance(handler, ast.AST):
            continue
        offset = getattr(route.tree, "line_offset", 0)
        start, end = handler.start_point[0] + 1 + offset, handler.end_point[0] + 1 + offset
        if start <= line <= end and (size is None or end - start < size):
            best, size = route, end - start
    return best


def _zod_collections(ctx: Context, rel: str) -> Iterator[Collection]:
    """Zod schemas (`z.object({...})`, with or without a trailing `.strict()` and similar chains)
    parsed from a request body in the same file, tied to the route whose handler holds the parse
    call. Top-level keys only."""
    text = ctx.index.text(rel)
    if "z.object(" not in text:
        return
    schemas = {m.group(1): ZOD_FIELD.findall(m.group(2)) for m in ZOD_SCHEMA.finditer(text)}
    for match in ZOD_PARSE.finditer(text):
        name, arg = match.group(1), match.group(2)
        fields = schemas.get(name)
        if not fields or not _js_request_body(text, arg):
            continue
        personal = tuple(dict.fromkeys(f for f in fields if classify(f)))
        if personal:
            line = line_of(text, match.start())
            yield Collection(_enclosing_route(ctx, rel, line), personal, Location(rel, line), name)


def collection_points(ctx: Context) -> list[Collection]:
    if "collection_points" not in ctx.facts:
        found = []
        for route in ctx.detection.routes:
            if route.method not in WRITE_METHODS or is_test(route.file) or route.handler is None:
                continue
            if isinstance(route.handler, ast.AST):
                fields, source = _py_fields(ctx, route)
            elif getattr(route.handler, "type", "") in jsts.FUNCTION_TYPES:
                fields, source = _js_fields(route)
            else:
                continue
            personal = tuple(dict.fromkeys(f for f in fields if classify(f)))
            if personal:
                found.append(Collection(route, personal, Location(route.file, route.line), source))
        for entry in [*ctx.index.py_files, *ctx.index.js_files]:
            if is_test(entry.rel):
                continue
            text = ctx.index.text(entry.rel)
            for pattern, label in RUNTIME:
                match = pattern.search(text)
                if match:
                    location = Location(entry.rel, line_of(text, match.start()))
                    found.append(Collection(None, (label,), location, RUNTIME_SOURCE))
        for entry in ctx.index.js_files:
            if is_test(entry.rel):
                continue
            found.extend(_zod_collections(ctx, entry.rel))
        ctx.facts["collection_points"] = found
    return ctx.facts["collection_points"]
