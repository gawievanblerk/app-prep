"""Routes that spend money when they run: paid SDK calls reached from a route handler."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from dpr.data import load
from dpr.model import Route, SdkUse
from dpr.parsing import jsts, pyast
from dpr.reviews.lookups import helper_index
from dpr.rules import Context

PY_IMPORT_NAMES = re.compile(r"^\s*(?:from\s+[\w.]+\s+import\s+(.+)|import\s+([\w., ]+))")
JS_IMPORT_NAMES = re.compile(
    r"import\s+(?:(\w+)|\*\s+as\s+(\w+)|\{([^}]*)\})|(?:const|let|var)\s+(?:(\w+)|\{([^}]*)\})\s*="
    r"\s*require\("
)


@dataclass(frozen=True)
class PaidRoute:
    route: Route
    sdk: SdkUse
    via: str


def _names_from_import(text: str, python: bool) -> set[str]:
    names: set[str] = set()
    match = PY_IMPORT_NAMES.match(text) if python else JS_IMPORT_NAMES.search(text)
    groups = match.groups() if match else ()
    for group in groups:
        for part in (group or "").replace("(", " ").replace(")", " ").split(","):
            token = part.strip().split(" as ")[-1].split(":")[-1].strip().split(".")[0]
            if re.fullmatch(r"[A-Za-z_]\w*", token):
                names.add(token)
    return names


def sdk_names(ctx: Context) -> dict[str, SdkUse]:
    """Imported identifier to the paid SDK it comes from, from the import sites."""
    if "paid_sdk_names" not in ctx.facts:
        found: dict[str, SdkUse] = {}
        for sdk in ctx.detection.sdks:
            if not sdk.paid:
                continue
            for loc in sdk.locations:
                line = ctx.index.text(loc.file).splitlines()[loc.line - 1]
                for name in _names_from_import(line, loc.file.endswith(".py")):
                    found[name] = sdk
        ctx.facts["paid_sdk_names"] = found
    return ctx.facts["paid_sdk_names"]


def _uses(text: str, names: dict[str, SdkUse]) -> SdkUse | None:
    for name, sdk in names.items():
        if re.search(rf"\b{re.escape(name)}\b\s*[.(]", text):
            return sdk
    return None


def _tree_names(tree, names: dict[str, SdkUse]) -> dict[str, SdkUse]:
    """Add module-level clients built from an SDK, such as `const ai = new OpenAI()`."""
    local = dict(names)
    if isinstance(tree, ast.Module):
        for name, value in pyast.assignments(tree.body).items():
            sdk = _uses(ast.unparse(value), names)
            if sdk:
                local[name] = sdk
    elif tree is not None and hasattr(tree, "root"):
        for decl in jsts.walk(tree.root, {"variable_declarator"}):
            if jsts.enclosing_function(decl) is not None:
                continue
            sdk = _uses(jsts.node_text(decl.child_by_field_name("value")), names)
            target = decl.child_by_field_name("name")
            if sdk and target is not None and target.type == "identifier":
                local[jsts.node_text(target)] = sdk
    return local


def _js_function_index(ctx: Context) -> dict[str, list]:
    key = ("js-function-index", "")
    if key not in ctx.index.cache:
        found: dict[str, list] = {}
        for entry in ctx.index.js_files:
            for tree in jsts.parse_file(ctx.index, entry.rel):
                for name, fn in jsts.exported_functions(tree).items():
                    found.setdefault(name, []).append((tree, fn))
        ctx.index.cache[key] = found
    return ctx.index.cache[key]


def _py_paid(
    ctx: Context, fn: ast.AST, names: dict[str, SdkUse], depth: int
) -> tuple[SdkUse, str] | None:
    sdk = _uses(ast.unparse(fn), names)
    if sdk:
        return sdk, getattr(fn, "name", "")
    if depth >= 2:
        return None
    base = sdk_names(ctx)
    for call in [n for n in ast.walk(fn) if isinstance(n, ast.Call)]:
        name = (pyast.dotted(call.func) or "").split(".")[-1]
        for rel, helper in helper_index(ctx).get(name, [])[:3]:
            if helper is fn:
                continue
            local = _tree_names(pyast.parse_file(ctx.index, rel), base)
            found = _py_paid(ctx, helper, local, depth + 1)
            if found:
                return found[0], name
    return None


def _js_paid(ctx: Context, fn, names: dict[str, SdkUse], depth: int) -> tuple[SdkUse, str] | None:
    sdk = _uses(jsts.node_text(fn), names)
    if sdk:
        return sdk, ""
    if depth >= 2:
        return None
    base = sdk_names(ctx)
    for call in jsts.walk(fn, {"call_expression"}):
        name = jsts.callee(call).split(".")[-1]
        for tree, helper in _js_function_index(ctx).get(name, [])[:3]:
            if helper is fn:
                continue
            found = _js_paid(ctx, helper, _tree_names(tree, base), depth + 1)
            if found:
                return found[0], name
    return None


def paid_routes(ctx: Context) -> list[PaidRoute]:
    if "paid_routes" not in ctx.facts:
        names = sdk_names(ctx)
        found = []
        for route in ctx.detection.routes if names else []:
            handler = route.handler
            local = _tree_names(route.tree, names)
            if isinstance(handler, ast.FunctionDef | ast.AsyncFunctionDef):
                hit = _py_paid(ctx, handler, local, 0)
            elif handler is not None and getattr(handler, "type", "") in jsts.FUNCTION_TYPES:
                hit = _js_paid(ctx, handler, local, 0)
            else:
                hit = None
            if hit:
                found.append(PaidRoute(route, hit[0], hit[1]))
        ctx.facts["paid_routes"] = found
    return ctx.facts["paid_routes"]


def costs() -> dict:
    return load("costs.yaml")
