"""Review 5, OWASP A01: mass assignment and admin screens guarded only in the browser."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Route, Tag
from dpr.parsing import jsts, pyast
from dpr.redact import snippet
from dpr.reviews.access import ADMIN, access
from dpr.reviews.lookups import model_for, snake
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule
from dpr.walk import line_of

SENSITIVE_FIELDS = {
    "role", "roles", "is_admin", "admin", "is_staff", "is_superuser", "org_id", "organization_id",
    "tenant_id", "plan", "permissions", "balance", "credits", "email_verified", "verified",
    "owner_id", "user_id",
}  # fmt: skip
JS_WRITE = re.compile(
    r"\w+\.(\w+)\.(create|update|upsert|createMany|updateMany)$"
    r"|^(\w+)\.(create|findByIdAndUpdate|findOneAndUpdate|updateOne|insertMany|bulkCreate)$"
    r"|^Object\.assign$"
)
JS_BODY = re.compile(r"(?:\breq|\brequest)\.(?:body\b|json\(\))(?!\s*\??\.\s*\w)|\bformData\(\)")
PY_BODY = re.compile(
    r"^(?:await )?request\.(?:json\(\)|get_json\(\)|json|data|POST|form)(?:\.dict\(\))?$"
)
UI_ADMIN = re.compile(
    r"""\bisAdmin\b|role\s*={2,3}\s*['"]admin['"]|['"]admin['"]\s*={2,3}\s*\w*\.?role"""
)
UI_SUFFIXES = (".tsx", ".jsx", ".vue", ".svelte")


def _js_body(node) -> bool:
    node = jsts.unwrap(node)
    if node is None:
        return False
    if node.type == "identifier":
        resolved = jsts.resolve_identifier(node)
        return resolved is not None and bool(JS_BODY.search(jsts.node_text(resolved)))
    if node.type == "object":
        pairs = jsts.object_pairs(node)
        if "data" in pairs:
            return _js_body(pairs["data"])
        return any(
            _js_body(child.named_children[0])
            for child in node.named_children
            if child.type == "spread_element" and child.named_children
        )
    return bool(JS_BODY.search(jsts.node_text(node)))


def _model_fields(ctx: Context, name: str | None) -> set[str]:
    model = model_for(ctx, name)
    return {snake(f.name) for f in model.fields} if model else set()


def _finding(ctx: Context, route: Route, line: int, model: str | None) -> Finding:
    sensitive = sorted(_model_fields(ctx, model) & SENSITIVE_FIELDS)
    return make_finding(
        "OWASP-A01-MASS-ASSIGNMENT",
        tag=Tag.CONFIRMED if sensitive else Tag.INFERRED,
        locations=[Location(route.file, line)],
        snippet=snippet(ctx.index.text(route.file), line),
        model=model or "record",
        fields=", ".join(sensitive) if sensitive else "any column the model has",
    )


def _js_mass(ctx: Context, route: Route) -> Iterator[Finding]:
    for call in jsts.calls(route.tree, JS_WRITE, route.handler):
        match = JS_WRITE.search(jsts.callee(call))
        args = jsts.arguments(call)
        candidates = args[-1:] if match.group(3) else args[:1]
        if jsts.callee(call) == "Object.assign":
            candidates = args[1:]
        if any(_js_body(a) for a in candidates):
            model = match.group(1) or match.group(3)
            yield _finding(ctx, route, jsts.line(route.tree, call), model)


def _py_body_names(fn: ast.AST) -> set[str]:
    names = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            if PY_BODY.match(ast.unparse(node.value)):
                names.add(node.targets[0].id)
    return names


def _py_is_body(node: ast.AST, names: set[str]) -> bool:
    return (isinstance(node, ast.Name) and node.id in names) or bool(
        PY_BODY.match(ast.unparse(node))
    )


def _py_mass(ctx: Context, route: Route) -> Iterator[Finding]:
    fn = route.handler
    names = _py_body_names(fn)
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                if keyword.arg is None and _py_is_body(keyword.value, names):
                    dotted = pyast.dotted(node.func) or ""
                    model = dotted.split(".")[0] if dotted[:1].isupper() else None
                    yield _finding(ctx, route, node.lineno, model)
        if isinstance(node, ast.For) and isinstance(node.iter, ast.Call):
            source = node.iter.func.value if isinstance(node.iter.func, ast.Attribute) else None
            body = " ".join(ast.unparse(s) for s in node.body)
            if source is not None and _py_is_body(source, names) and "setattr(" in body:
                yield _finding(ctx, route, node.lineno, None)


@rule(
    "OWASP-A01-MASS-ASSIGNMENT",
    review="owasp",
    severity="high",
    exploitability="high",
    owasp="A01",
)
def mass_assignment(ctx: Context) -> Iterator[Finding]:
    for route in ctx.detection.routes:
        if is_test(route.file) or route.handler is None:
            continue
        if isinstance(route.handler, ast.FunctionDef | ast.AsyncFunctionDef):
            yield from _py_mass(ctx, route)
        elif route.tree is not None and getattr(route.handler, "type", "") in jsts.FUNCTION_TYPES:
            yield from _js_mass(ctx, route)


@rule(
    "OWASP-A01-CLIENT-ONLY-GUARD",
    review="owasp",
    severity="medium",
    exploitability="medium",
    owasp="A01",
)
def client_only_guard(ctx: Context) -> Iterator[Finding]:
    ui = None
    for entry in ctx.index.files:
        if entry.rel.endswith(UI_SUFFIXES) and not is_test(entry.rel):
            text = ctx.index.text(entry.rel)
            match = UI_ADMIN.search(text)
            if match:
                ui = Location(entry.rel, line_of(text, match.start()))
                break
    if ui is None:
        return
    for route in ctx.detection.routes:
        if re.search(r"(?:^|/)admin(?:/|$)", route.path) and access(ctx, route).level != ADMIN:
            yield make_finding(
                "OWASP-A01-CLIENT-ONLY-GUARD",
                tag=Tag.INFERRED,
                locations=[Location(route.file, route.line), ui],
                snippet=snippet(ctx.index.text(route.file), route.line),
                method=route.method,
                path=route.path,
            )
