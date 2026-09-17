"""Python helper targets for paid routes: a call resolved through the calling file's own
definitions and imports, including methods of service instances built in the calling function
or at module level. Method calls on any other receiver are never followed."""

from __future__ import annotations

import ast
import sys

from dpr.discovery.packages import _manifest_packages, normalise
from dpr.parsing import imports, pyast
from dpr.reviews.lookups import helper_index
from dpr.rules import Context


def top_function(ctx: Context, rel: str | None, name: str) -> ast.AST | None:
    tree = pyast.parse_file(ctx.index, rel) if rel else None
    for node in tree.body if tree else []:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == name:
            return node
    return None


def declared_package(ctx: Context, name: str) -> bool:
    """True when a manifest (package.json, pyproject, requirements) or the standard library
    provides the module or package name."""
    key = ("manifest-packages", "")
    if key not in ctx.index.cache:
        ctx.index.cache[key] = _manifest_packages(ctx.index)
    parts = name.split("/")
    root = "/".join(parts[:2] if name.startswith("@") else parts[:1]).split(".")[0]
    return normalise(root) in ctx.index.cache[key] or root in sys.stdlib_module_names


def _by_name(ctx: Context, name: str) -> tuple[str, ast.AST] | None:
    defs = [d for d in helper_index(ctx).get(name, []) if top_function(ctx, d[0], name)]
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


def _built_from(value: ast.AST | None) -> str | None:
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
        return value.func.id
    return None


def _own_nodes(fn: ast.AST):
    """Nodes of a function body, not descending into nested functions, lambdas or classes."""
    stack = list(getattr(fn, "body", []))
    while stack:
        node = stack.pop()
        yield node
        stack.extend(
            child
            for child in ast.iter_child_nodes(node)
            if not isinstance(
                child, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | ast.ClassDef
            )
        )


def _instance_class(
    fn: ast.AST | None, module_body: list[ast.stmt], name: str, line: int
) -> str | None:
    """The class a receiver was built from: the last `name = Class(...)` in the calling
    function's own body before the call, else a module-level assignment when the function does
    not bind the name. Parameters (including `Depends(...)` defaults) are never resolved."""
    if fn is not None:
        arguments = fn.args
        params = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
        params += [a for a in (arguments.vararg, arguments.kwarg) if a is not None]
        if name in {a.arg for a in params}:
            return None
        local = [
            node
            for node in _own_nodes(fn)
            if isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == name for t in node.targets)
        ]
        if local:
            before = [node for node in local if node.lineno < line]
            return _built_from(max(before, key=lambda n: n.lineno).value) if before else None
    return _built_from(pyast.assignments(module_body).get(name))


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
        method = top_function(ctx, file, func.attr)
        return (file, method, True) if method is not None else None
    if file and attr:
        other = pyast.parse_file(ctx.index, file)
        class_name = _instance_class(None, other.body if other else [], attr, 0)
        found = _class_method(ctx, file, class_name, func.attr) if class_name else None
        return (*found, True) if found is not None else None
    class_name = _instance_class(fn, tree.body if tree else [], receiver, call.lineno)
    found = _class_method(ctx, rel, class_name, func.attr) if class_name else None
    return (*found, True) if found is not None else None


def py_target(
    ctx: Context, rel: str, call: ast.Call, fn: ast.AST | None = None
) -> tuple[str, ast.AST, bool] | None:
    """The helper a call reaches through this file's definitions or imports: (file, fn, exact).

    An imported name from a local module that cannot be read to its definition (a star
    re-export, a module path that does not match the tree) is matched by name, not exactly.
    """
    names = imports.py_imports(ctx.index, rel, pyast.parse_file(ctx.index, rel))
    func = call.func
    if isinstance(func, ast.Name):
        local = top_function(ctx, rel, func.id)
        if local is not None:
            return rel, local, True
        file, attr, module = names.get(func.id, (None, "", ""))
        if not attr:
            return None
        found = top_function(ctx, file, attr)
        if found is None and file is not None:
            tree = pyast.parse_file(ctx.index, file)
            again = imports.py_imports(ctx.index, file, tree).get(attr, (None, "", ""))
            found = top_function(ctx, again[0], again[1]) if again[1] else None
            file = again[0] if found is not None else file
        if found is not None:
            return file, found, True
        if file is not None or not declared_package(ctx, module.lstrip(".")):
            hit = _by_name(ctx, attr)
            return (hit[0], hit[1], False) if hit is not None else None
        return None
    return _py_method_target(ctx, rel, call, fn)
