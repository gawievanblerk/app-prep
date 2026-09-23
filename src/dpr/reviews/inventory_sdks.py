"""Review 1, inventory: which third parties receive a copy of personal data."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.discovery.approots import root_of
from dpr.model import Finding, Location, SdkUse, Tag
from dpr.parsing import jsts, pyast
from dpr.redact import snippet
from dpr.reviews.inventory_callers import caller_value
from dpr.reviews.paid import names_from_import
from dpr.reviews.paths import is_test
from dpr.reviews.personal import classify
from dpr.rules import Context, make_finding, rule

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
NO_CONTENT_CATEGORIES = ("storage",)
SENDER_KEY = re.compile(r"(?i)^(?:sender|from|reply)")


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
                names |= names_from_import(lines[loc.line - 1], rel.endswith(".py"))
        sites = _py_sites(ctx, rel, names) if rel.endswith(".py") else _js_sites(ctx, rel, names)
        found += [(Location(rel, line), keys) for line, keys in sites]
    return found


def _identifying(key: str) -> bool:
    if key.lower() in RECIPIENT_KEYS:
        return True
    if SENDER_KEY.match(key):
        return False
    # A keyword argument names an SDK setting, not a person: region_name or bucket_name is not
    # a personal name, so the bare "name" term does not count here.
    category = classify(key, person=False)
    return category is not None and category.key not in ("content", "account")


def _kinds(keys: list[str], category: str) -> tuple[list[str], list[str], list[str]]:
    identifying = [k for k in keys if _identifying(k)]
    # The Body of a storage upload is a file of unknown contents, not free text about a person.
    content = [
        k
        for k in keys
        if category not in NO_CONTENT_CATEGORIES
        and (k.lower() in CONTENT_KEYS or (classify(k) and classify(k).key == "content"))
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
                i, c, w = _kinds(keys, sdk.category)
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
