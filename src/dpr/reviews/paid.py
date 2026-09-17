"""Routes that spend money when they run: paid SDK calls reached from a route handler.

SDK names are read per file. A helper is followed only when the call resolves through the
caller file's own definitions or imports (a function, or a function of an imported module);
method calls on other objects are never followed. When an import names a local module that
cannot be found, the helper is matched by name alone and the result is marked as not exact.
"""

from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass

from dpr.data import load
from dpr.discovery.packages import (
    JS_IMPORT,
    PY_IMPORT,
    _js_package,
    _manifest_packages,
    normalise,
)
from dpr.model import Route, SdkUse
from dpr.parsing import imports, jsts, pyast
from dpr.reviews.lookups import helper_index
from dpr.rules import Context
from dpr.walk import line_of

PY_IMPORT_NAMES = re.compile(r"^\s*(?:from\s+[\w.]+\s+import\s+(.+)|import\s+([\w., ]+))")
JS_IMPORT_NAMES = re.compile(
    r"import\s+(?:(\w+)|\*\s+as\s+(\w+)|\{([^}]*)\})|(?:const|let|var)\s+(?:(\w+)|\{([^}]*)\})\s*="
    r"\s*require\("
)
MAX_DEPTH = 2


@dataclass(frozen=True)
class PaidRoute:
    route: Route
    sdk: SdkUse
    via: str
    exact: bool = True


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


def sdk_names(ctx: Context) -> dict[str, dict[str, SdkUse]]:
    """File to the identifiers that file imports from a paid SDK."""
    if "paid_sdk_names" not in ctx.facts:
        packages = {
            normalise(package): sdk
            for sdk in ctx.detection.sdks
            if sdk.paid
            for entry in load("sdks.yaml")
            if entry["name"] == sdk.name
            for package in entry["packages"]
        }
        found: dict[str, dict[str, SdkUse]] = {}
        for entry in ctx.index.js_files + ctx.index.py_files if packages else []:
            python = entry.rel.endswith(".py")
            text = ctx.index.text(entry.rel)
            lines = text.splitlines()
            for match in (PY_IMPORT if python else JS_IMPORT).finditer(text):
                module = match.group(1) or (match.group(2) if python else "")
                sdk = packages.get(normalise(module if python else _js_package(module)))
                if sdk is not None:
                    line = lines[line_of(text, match.start(1 if match.group(1) else 2)) - 1]
                    for name in _names_from_import(line, python):
                        found.setdefault(entry.rel, {})[name] = sdk
        ctx.facts["paid_sdk_names"] = found
    return ctx.facts["paid_sdk_names"]


def _uses(text: str, names: dict[str, SdkUse]) -> SdkUse | None:
    for name, sdk in names.items():
        if re.search(rf"(?<![\w.$]){re.escape(name)}\b\s*[.(]", text):
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


def _file_names(ctx: Context, rel: str, tree) -> dict[str, SdkUse]:
    key = ("paid-file-names", rel)
    if key not in ctx.index.cache:
        ctx.index.cache[key] = _tree_names(tree, sdk_names(ctx).get(rel, {}))
    return ctx.index.cache[key]


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


def _top_function(ctx: Context, rel: str | None, name: str) -> ast.AST | None:
    tree = pyast.parse_file(ctx.index, rel) if rel else None
    for node in tree.body if tree else []:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == name:
            return node
    return None


def _declared_package(ctx: Context, name: str) -> bool:
    """True when a manifest (package.json, pyproject, requirements) or the standard library
    provides the module or package name."""
    key = ("manifest-packages", "")
    if key not in ctx.index.cache:
        ctx.index.cache[key] = _manifest_packages(ctx.index)
    parts = name.split("/")
    root = "/".join(parts[:2] if name.startswith("@") else parts[:1]).split(".")[0]
    return normalise(root) in ctx.index.cache[key] or root in sys.stdlib_module_names


def _by_name(ctx: Context, name: str) -> tuple[str, ast.AST] | None:
    defs = [d for d in helper_index(ctx).get(name, []) if _top_function(ctx, d[0], name)]
    return defs[0] if len(defs) == 1 else None


def _py_target(ctx: Context, rel: str, call: ast.Call) -> tuple[str, ast.AST, bool] | None:
    """The helper a call reaches through this file's definitions or imports: (file, fn, exact).

    An imported name from a local module that cannot be read to its definition (a star
    re-export, a module path that does not match the tree) is matched by name, not exactly.
    """
    names = imports.py_imports(ctx.index, rel, pyast.parse_file(ctx.index, rel))
    func = call.func
    if isinstance(func, ast.Name):
        local = _top_function(ctx, rel, func.id)
        if local is not None:
            return rel, local, True
        file, attr, module = names.get(func.id, (None, "", ""))
        if not attr:
            return None
        found = _top_function(ctx, file, attr)
        if found is None and file is not None:
            tree = pyast.parse_file(ctx.index, file)
            again = imports.py_imports(ctx.index, file, tree).get(attr, (None, "", ""))
            found = _top_function(ctx, again[0], again[1]) if again[1] else None
            file = again[0] if found is not None else file
        if found is not None:
            return file, found, True
        if file is not None or not _declared_package(ctx, module.lstrip(".")):
            hit = _by_name(ctx, attr)
            return (hit[0], hit[1], False) if hit is not None else None
        return None
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        file, attr, _module = names.get(func.value.id, (None, "x", ""))
        found = _top_function(ctx, file, func.attr) if file and not attr else None
        return (file, found, True) if found is not None else None
    return None


def _py_paid(ctx: Context, rel: str, fn: ast.AST, depth: int) -> tuple[SdkUse, str, bool] | None:
    sdk = _uses(ast.unparse(fn), _file_names(ctx, rel, pyast.parse_file(ctx.index, rel)))
    if sdk:
        return sdk, getattr(fn, "name", ""), True
    if depth >= MAX_DEPTH:
        return None
    for call in [n for n in ast.walk(fn) if isinstance(n, ast.Call)]:
        target = _py_target(ctx, rel, call)
        if target is None or target[1] is fn:
            continue
        found = _py_paid(ctx, target[0], target[1], depth + 1)
        if found:
            return found[0], getattr(target[1], "name", ""), found[2] and target[2]
    return None


def _js_exported(ctx: Context, rel: str | None, name: str) -> tuple[object, object] | None:
    for tree in jsts.parse_file(ctx.index, rel) if rel else []:
        found = jsts.exported_functions(tree).get(name)
        if found is not None:
            return tree, found
    return None


def _js_target(ctx: Context, tree, call) -> tuple[object, object, bool] | None:
    """(tree, function, exact) for a call that resolves through this file or its imports."""
    func = jsts.unwrap(call.child_by_field_name("function"))
    names = imports.js_imports(ctx.index, tree.rel)
    if func is not None and func.type == "identifier":
        name = jsts.node_text(func)
        if name not in names:
            value = jsts.declared_value(tree.root, name)
            return (
                (tree, value, True)
                if value is not None and value.type in jsts.FUNCTION_TYPES
                else None
            )
        file, exported, spec = names[name]
        found = _js_exported(ctx, file, exported)
        if found is not None:
            return found[0], found[1], True
        local = file is not None or imports.is_local_spec(spec) or not _declared_package(ctx, spec)
        candidates = _js_function_index(ctx).get(exported, []) if local else []
        if exported not in ("*", "default") and len(candidates) == 1:
            return candidates[0][0], candidates[0][1], False
        return None
    if func is not None and func.type == "member_expression":
        receiver = jsts.unwrap(func.child_by_field_name("object"))
        if receiver is not None and receiver.type == "identifier":
            file, exported, _spec = names.get(jsts.node_text(receiver), (None, "", ""))
            prop = jsts.node_text(func.child_by_field_name("property"))
            found = _js_exported(ctx, file, prop) if exported == "*" else None
            return (found[0], found[1], True) if found is not None else None
    return None


def _js_paid(ctx: Context, tree, fn, depth: int) -> tuple[SdkUse, str, bool] | None:
    sdk = _uses(jsts.node_text(fn), _file_names(ctx, tree.rel, tree))
    if sdk:
        return sdk, "", True
    if depth >= MAX_DEPTH:
        return None
    for call in jsts.walk(fn, {"call_expression"}):
        target = _js_target(ctx, tree, call)
        if target is None or target[1] is fn:
            continue
        found = _js_paid(ctx, target[0], target[1], depth + 1)
        if found:
            name = jsts.callee(call).split(".")[-1]
            return found[0], name, found[2] and target[2]
    return None


def paid_routes(ctx: Context) -> list[PaidRoute]:
    if "paid_routes" not in ctx.facts:
        found = []
        for route in ctx.detection.routes if sdk_names(ctx) else []:
            handler = route.handler
            if isinstance(handler, ast.FunctionDef | ast.AsyncFunctionDef):
                hit = _py_paid(ctx, route.file, handler, 0)
            elif handler is not None and getattr(handler, "type", "") in jsts.FUNCTION_TYPES:
                hit = _js_paid(ctx, route.tree, handler, 0)
            else:
                hit = None
            if hit:
                found.append(PaidRoute(route, hit[0], hit[1], hit[2]))
        ctx.facts["paid_routes"] = found
    return ctx.facts["paid_routes"]


def costs() -> dict:
    return load("costs.yaml")
