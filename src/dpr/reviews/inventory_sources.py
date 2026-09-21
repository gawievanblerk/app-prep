"""Review 1, inventory: where personal data comes in, and which third parties receive a copy."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from dataclasses import dataclass

from dpr.discovery.approots import root_of
from dpr.model import Finding, Location, Route, SdkUse, Tag
from dpr.parsing import jsts, pyast
from dpr.redact import snippet
from dpr.reviews.inventory_callers import caller_value
from dpr.reviews.paid import _names_from_import
from dpr.reviews.paths import is_test
from dpr.reviews.personal import classify
from dpr.rules import Context, make_finding, rule
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
REQUEST_BODY = re.compile(REQUEST_BODY_EXPR)
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
RECIPIENT_KEYS = {
    "to",
    "recipients",
    "recipient",
    "address",
    "displayname",
    "cc",
    "bcc",
    "reply_to",
}
CONTENT_KEYS = {
    "messages",
    "prompt",
    "input",
    "system",
    "content",
    "text",
    "html",
    "body",
    "contents",
}
WHOLE_OBJECTS = {"user", "current_user", "customer", "client", "profile", "member", "patient"}
SKIP_RECIPIENT_CATEGORIES = ("fonts",)
SENDER_KEY = re.compile(r"(?i)^(?:sender|from|reply)")


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
    for arg in [*fn.args.args, *fn.args.kwonlyargs]:
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


def _zod_collections(ctx: Context, rel: str) -> Iterator[Collection]:
    """Zod schemas (`z.object({...})`, with or without a trailing `.strict()` and similar chains)
    parsed from a request body in the same file. Top-level keys only."""
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
            yield Collection(None, personal, Location(rel, line_of(text, match.start())), name)


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
                    found.append(Collection(None, (label,), location, "captured at runtime"))
        for entry in ctx.index.js_files:
            if is_test(entry.rel):
                continue
            found.extend(_zod_collections(ctx, entry.rel))
        ctx.facts["collection_points"] = found
    return ctx.facts["collection_points"]


def _py_clients(tree: ast.Module, names: set[str]) -> set[str]:
    clients = set(names)
    for _ in range(2):
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call | ast.Attribute):
                root = (
                    pyast.dotted(
                        node.value.func if isinstance(node.value, ast.Call) else node.value
                    )
                    or ""
                ).split(".")[0]
                if root in clients:
                    for target in node.targets:
                        dotted = pyast.dotted(target)
                        if dotted:
                            clients.add(dotted)
    return clients


def _py_dict_keys(node: ast.AST, fn: ast.AST | None, tree: ast.Module | None = None) -> list[str]:
    if isinstance(node, ast.Name) and fn is not None:
        for sub in ast.walk(fn):
            if isinstance(sub, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == node.id for t in sub.targets
            ):
                return _py_dict_keys(sub.value, None)
        if tree is not None:
            value = caller_value(tree, fn, node.id)
            if value is not None:
                return _py_dict_keys(value, pyast.function_at(tree, value.lineno))
        return [node.id] if node.id in WHOLE_OBJECTS else []
    keys = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Dict):
            keys += [
                k for k in (pyast.constant(key, None) for key in sub.keys) if isinstance(k, str)
            ]
    return keys


def _py_sites(ctx: Context, rel: str, names: set[str]) -> Iterator[tuple[int, list[str]]]:
    tree = pyast.parse_file(ctx.index, rel)
    if tree is None:
        return
    clients = _py_clients(tree, names)
    for call in pyast.calls(tree, r"[\w.()]+"):
        callee = pyast.dotted(call.func) or ""
        owner = callee.rsplit(".", 1)[0] if "." in callee else ""
        if not owner or not any(owner == c or owner.startswith(c + ".") for c in clients):
            continue
        fn = pyast.function_at(tree, call.lineno)
        keys = [k.arg for k in call.keywords if k.arg]
        for arg in [*call.args, *(k.value for k in call.keywords)]:
            keys += _py_dict_keys(arg, fn, tree)
        if keys:
            yield call.lineno, keys


def _js_keys(node) -> list[str]:
    node = jsts.unwrap(node)
    if node is None:
        return []
    if node.type == "identifier":
        resolved = jsts.resolve_identifier(node)
        return (
            _js_keys(resolved)
            if resolved is not None
            else ([jsts.node_text(node)] if jsts.node_text(node) in WHOLE_OBJECTS else [])
        )
    keys = []
    for obj in jsts.walk(node, {"object"}):
        keys += list(jsts.object_pairs(obj))
    return keys


def _js_sites(ctx: Context, rel: str, names: set[str]) -> Iterator[tuple[int, list[str]]]:
    for tree in jsts.parse_file(ctx.index, rel):
        clients = set(names)
        for decl in jsts.walk(tree.root, {"variable_declarator"}):
            value = jsts.node_text(decl.child_by_field_name("value"))
            if (
                re.match(r"(?:new\s+)?(\w+)", value)
                and re.match(r"(?:new\s+)?(\w+)", value).group(1) in names
            ):
                clients.add(jsts.node_text(decl.child_by_field_name("name")))
        for call in jsts.walk(tree.root, {"call_expression"}):
            callee = jsts.callee(call)
            if "." not in callee or callee.split(".")[0] not in clients:
                continue
            keys = [k for arg in jsts.arguments(call) for k in _js_keys(arg)]
            if keys:
                yield jsts.line(tree, call), keys


def recipient_sites(ctx: Context, sdk: SdkUse) -> list[tuple[Location, list[str]]]:
    found = []
    for rel in sorted({loc.file for loc in sdk.locations}):
        if is_test(rel) or rel.endswith((".html", ".htm")):
            continue
        lines = ctx.index.text(rel).splitlines()
        names: set[str] = set()
        for loc in sdk.locations:
            if loc.file == rel:
                names |= _names_from_import(lines[loc.line - 1], rel.endswith(".py"))
        sites = _py_sites(ctx, rel, names) if rel.endswith(".py") else _js_sites(ctx, rel, names)
        found += [(Location(rel, line), keys) for line, keys in sites]
    return found


def _identifying(key: str) -> bool:
    if key.lower() in RECIPIENT_KEYS:
        return True
    if SENDER_KEY.match(key):
        return False
    category = classify(key)
    return category is not None and category.key not in ("content", "account")


def _kinds(keys: list[str]) -> tuple[list[str], list[str], list[str]]:
    identifying = [k for k in keys if _identifying(k)]
    content = [
        k
        for k in keys
        if k.lower() in CONTENT_KEYS or (classify(k) and classify(k).key == "content")
    ]
    whole = [k for k in keys if k.lower() in WHOLE_OBJECTS]
    return identifying, content, whole


def sdk_receipts(ctx: Context) -> list[tuple[SdkUse, list[Location], Tag, str]]:
    """One receipt per SDK per app root: evidence from one root's call sites never merges into
    another root's tag, keys or locations."""
    if "sdk_receipts" not in ctx.facts:
        found = []
        multi_root = len(ctx.detection.app_roots) > 1
        for sdk in ctx.detection.sdks:
            if not sdk.recipient or sdk.category in SKIP_RECIPIENT_CATEGORIES:
                continue
            by_root: dict[str, list[tuple[Location, list[str], list[str], list[str]]]] = {}
            for location, keys in recipient_sites(ctx, sdk):
                i, c, w = _kinds(keys)
                if not (i or c or w):
                    continue
                home = root_of(ctx.detection.app_roots, location.file)
                by_root.setdefault(home.path if home else "", []).append((location, i, c, w))
            for root_path, sites in sorted(by_root.items()):
                locations = [site[0] for site in sites]
                identifying = [k for site in sites for k in site[1]]
                content = [k for site in sites for k in site[2]]
                whole = [k for site in sites for k in site[3]]
                parts = []
                if identifying:
                    parts.append(
                        "identifying fields (" + ", ".join(dict.fromkeys(identifying)) + ")"
                    )
                if content:
                    parts.append("free text or prompts (" + ", ".join(dict.fromkeys(content)) + ")")
                if whole:
                    parts.append("whole records (" + ", ".join(dict.fromkeys(whole)) + ")")
                what = " and ".join(parts)
                if multi_root:
                    what += f" in {root_path or 'the repository root'}"
                tag = Tag.CONFIRMED if identifying else Tag.INFERRED
                found.append((sdk, locations, tag, what))
        ctx.facts["sdk_receipts"] = found
    return ctx.facts["sdk_receipts"]


@rule("INV-SDK-RECEIVES-PII", review="inventory", severity="medium", exploitability="low")
def sdk_receives_pii(ctx: Context) -> Iterator[Finding]:
    for sdk, locations, tag, what in sdk_receipts(ctx):
        yield make_finding(
            "INV-SDK-RECEIVES-PII",
            tag=tag,
            locations=locations[:10],
            snippet=snippet(ctx.index.text(locations[0].file), locations[0].line),
            sdk=sdk.name,
            category=sdk.category,
            what=what,
        )
