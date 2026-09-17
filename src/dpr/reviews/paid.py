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


def _own_names(ctx: Context, rel: str | None) -> dict[str, SdkUse]:
    """SDK names a file imports, plus its module-level clients built from them."""
    if rel is None:
        return {}
    key = ("paid-own-names", rel)
    if key not in ctx.index.cache:
        base = sdk_names(ctx).get(rel, {})
        if rel.endswith(".py"):
            names = _tree_names(pyast.parse_file(ctx.index, rel), base)
        else:
            names = dict(base)
            for tree in jsts.parse_file(ctx.index, rel):
                names.update(_tree_names(tree, base))
        ctx.index.cache[key] = names
    return ctx.index.cache[key]


def _file_names(ctx: Context, rel: str) -> dict[str, SdkUse]:
    """Names in a file that stand for a paid SDK: its own, and clients it imports from another
    repository file (`from app.clients import client`, `import { openai } from "@/lib/ai"`, or
    `clients.client` through an imported module)."""
    key = ("paid-file-names", rel)
    if key not in ctx.index.cache:
        names = dict(_own_names(ctx, rel))
        if rel.endswith(".py"):
            found = imports.py_imports(ctx.index, rel, pyast.parse_file(ctx.index, rel))
            modules = {local: file for local, (file, attr, _m) in found.items() if not attr}
        else:
            found = imports.js_imports(ctx.index, rel)
            modules = {local: file for local, (file, attr, _m) in found.items() if attr == "*"}
        for local, (file, attr, _module) in found.items():
            if file and attr in _own_names(ctx, file):
                names.setdefault(local, _own_names(ctx, file)[attr])
        for local, file in modules.items():
            for name, sdk in _own_names(ctx, file).items() if file else []:
                names.setdefault(f"{local}.{name}", sdk)
        ctx.index.cache[key] = names
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


def _class_method(
    ctx: Context, rel: str, class_name: str, method: str
) -> tuple[str, ast.AST] | None:
    """A method of a class defined in `rel` or imported into it from a repository file."""
    tree = pyast.parse_file(ctx.index, rel)
    classes = {n.name: n for n in tree.body if isinstance(n, ast.ClassDef)} if tree else {}
    if class_name not in classes:
        file, attr, _module = imports.py_imports(ctx.index, rel, tree).get(
            class_name, (None, "", "")
        )
        other = pyast.parse_file(ctx.index, file) if file and attr else None
        classes = {n.name: n for n in other.body if isinstance(n, ast.ClassDef)} if other else {}
        rel, class_name = file or rel, attr
    for item in classes[class_name].body if class_name in classes else []:
        if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef) and item.name == method:
            return rel, item
    return None


def _instance_class(scope: list[ast.stmt], name: str) -> str | None:
    """The class a name was built from (`name = Service(...)`) in the given statements."""
    value = None
    for node in (n for stmt in scope for n in ast.walk(stmt)):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == name for t in node.targets
        ):
            value = node.value
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
        return value.func.id
    return None


def _py_method_target(
    ctx: Context, rel: str, call: ast.Call, fn: ast.AST | None
) -> tuple[str, ast.AST, bool] | None:
    """A method called on a module, on a service instance, or on a freshly built instance."""
    func = call.func
    if not isinstance(func, ast.Attribute):
        return None
    if isinstance(func.value, ast.Call) and isinstance(func.value.func, ast.Name):
        found = _class_method(ctx, rel, func.value.func.id, func.attr)
        return (*found, True) if found is not None else None
    if not isinstance(func.value, ast.Name):
        return None
    receiver = func.value.id
    tree = pyast.parse_file(ctx.index, rel)
    names = imports.py_imports(ctx.index, rel, tree)
    file, attr, _module = names.get(receiver, (None, "x", ""))
    if file and not attr:
        method = _top_function(ctx, file, func.attr)
        return (file, method, True) if method is not None else None
    if file and attr:
        other = pyast.parse_file(ctx.index, file)
        class_name = _instance_class(other.body if other else [], attr)
        found = _class_method(ctx, file, class_name, func.attr) if class_name else None
        return (*found, True) if found is not None else None
    scope = [*(getattr(fn, "body", []) or []), *(tree.body if tree else [])]
    class_name = _instance_class(scope, receiver)
    found = _class_method(ctx, rel, class_name, func.attr) if class_name else None
    return (*found, True) if found is not None else None


def _py_target(
    ctx: Context, rel: str, call: ast.Call, fn: ast.AST | None = None
) -> tuple[str, ast.AST, bool] | None:
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
    return _py_method_target(ctx, rel, call, fn)


def _py_paid(ctx: Context, rel: str, fn: ast.AST, depth: int) -> tuple[SdkUse, str, bool] | None:
    sdk = _uses(ast.unparse(fn), _file_names(ctx, rel))
    if sdk:
        return sdk, getattr(fn, "name", ""), True
    if depth >= MAX_DEPTH:
        return None
    for call in [n for n in ast.walk(fn) if isinstance(n, ast.Call)]:
        target = _py_target(ctx, rel, call, fn)
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


def _js_local_functions(ctx: Context, tree) -> dict[str, object]:
    """Functions a file declares by name, top-level declarations first."""
    key = ("js-local-functions", f"{tree.rel}:{tree.line_offset}")
    if key not in ctx.index.cache:
        found: dict[str, object] = {}
        nodes = [*tree.root.named_children, *jsts.walk(tree.root, set(jsts.NAMED_FUNCTIONS))]
        nodes += list(jsts.walk(tree.root, {"variable_declarator"}))
        for node in nodes:
            if node.type == "export_statement":
                node = node.child_by_field_name("declaration") or node
            items = node.named_children if node.type.endswith("_declaration") else []
            for item in [node, *items]:
                if item.type in jsts.NAMED_FUNCTIONS:
                    found.setdefault(jsts.node_text(item.child_by_field_name("name")), item)
                elif item.type == "variable_declarator":
                    value = jsts.unwrap(item.child_by_field_name("value"))
                    if value is not None and value.type in jsts.FUNCTION_TYPES:
                        name = jsts.node_text(item.child_by_field_name("name"))
                        found.setdefault(name, value)
        ctx.index.cache[key] = found
    return ctx.index.cache[key]


def _js_target(ctx: Context, tree, call) -> tuple[object, object, bool] | None:
    """(tree, function, exact) for a call that resolves through this file or its imports."""
    func = jsts.unwrap(call.child_by_field_name("function"))
    names = imports.js_imports(ctx.index, tree.rel)
    if func is not None and func.type == "identifier":
        name = jsts.node_text(func)
        if name not in names:
            value = _js_local_functions(ctx, tree).get(name)
            return (tree, value, True) if value is not None else None
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
    sdk = _uses(jsts.node_text(fn), _file_names(ctx, tree.rel))
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
