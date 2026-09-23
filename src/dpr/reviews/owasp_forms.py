"""Review 5, OWASP A01 and A04: Django forms and upload settings.

`OWASP-A01-PRIVILEGE-FIELDS`: a model form or serializer that lets its user set superuser,
staff, group or permission fields, used by a view that is not superuser-only.
`OWASP-A04-UPLOAD-LIMIT`: request and in-memory upload limits of 100 MB or more, or none.
`OWASP-A04-UNCHECKED-UPLOAD`: `FileField`s with no validators, grouped per app.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from pathlib import PurePosixPath

from dpr.model import Finding, Location, Route, Tag
from dpr.parsing import pyast
from dpr.parsing.pyenv import module_assignments
from dpr.redact import snippet
from dpr.reviews.access import PUBLIC, access
from dpr.reviews.app_code import app_py_files
from dpr.reviews.lookups import user_model
from dpr.reviews.settings_files import production_file, settings_module
from dpr.rules import Context, make_finding, rule

LIMITS = ("DATA_UPLOAD_MAX_MEMORY_SIZE", "FILE_UPLOAD_MAX_MEMORY_SIZE")
LARGE = 100_000_000
ALWAYS = ("is_superuser", "is_staff", "user_permissions")
GRANTS = ("groups", "permissions")
FORM_BASE = re.compile(r"ModelForm|ModelSerializer|UserChangeForm|UserCreationForm")
FILE_FIELD = re.compile(r"(?:(?:models|forms|serializers)\.)?FileField")
PACKAGE_DIRS = frozenset({"forms", "models", "views", "serializers", "api"})
SIZES = ((1 << 30, "GB"), (1 << 20, "MB"), (1 << 10, "KB"))
BOUND = re.compile(r"\b\w+\.(?:POST|data|FILES)\b|\bdata\b")
WRITABLE_VIEW = re.compile(r"ModelViewSet|Create|Update|FormView|GenericViewSet")
WRITE_METHODS = frozenset(
    {"post", "put", "patch", "create", "update", "partial_update", "form_valid"}
)


def _number(node: ast.AST | None) -> int | None:
    """An integer written as a literal or constant arithmetic (1024 * 1024 * 1000)."""
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult | ast.Add | ast.Pow):
        left, right = _number(node.left), _number(node.right)
        if left is None or right is None or (isinstance(node.op, ast.Pow) and right > 64):
            return None
        if isinstance(node.op, ast.Mult):
            return left * right
        return left + right if isinstance(node.op, ast.Add) else left**right
    return None


def _size(value: int) -> str:
    for unit, label in SIZES:
        if value >= unit:
            return f"{value / unit:g} {label}"
    return f"{value} bytes"


@rule(
    "OWASP-A04-UPLOAD-LIMIT",
    review="owasp",
    severity="medium",
    exploitability="medium",
    owasp="A04",
)
def upload_limit(ctx: Context) -> Iterator[Finding]:
    for rel, text, tree in app_py_files(ctx, "UPLOAD_MAX_MEMORY_SIZE"):
        if not settings_module(rel, text) or not production_file(ctx, rel):
            continue
        hits = []
        for name, value, line in module_assignments(tree):
            if name not in LIMITS:
                continue
            number = _number(value)
            if name == LIMITS[0] and pyast.constant(value, 0) is None:
                hits.append((line, f"{name} is None (no limit)"))
            elif number is not None and number >= LARGE:
                hits.append((line, f"{name} is {_size(number)}"))
        if hits:
            yield make_finding(
                "OWASP-A04-UPLOAD-LIMIT",
                tag=Tag.CONFIRMED,
                locations=[Location(rel, line) for line, _ in hits],
                snippet=snippet(text, hits[0][0]),
                limits="; ".join(what for _, what in hits),
            )


def _app_of(rel: str) -> str:
    folder = PurePosixPath(rel).parent
    if folder.name in PACKAGE_DIRS:
        folder = folder.parent
    return folder.as_posix() if folder.as_posix() != "." else "(repository root)"


def _checked_names(cls: ast.ClassDef) -> str:
    """Text of the class's clean methods, where a field can be checked by hand."""
    return " ".join(
        ast.unparse(item)
        for item in cls.body
        if isinstance(item, ast.FunctionDef) and item.name.startswith("clean")
    )


@rule(
    "OWASP-A04-UNCHECKED-UPLOAD", review="owasp", severity="low", exploitability="low", owasp="A04"
)
def unchecked_upload(ctx: Context) -> Iterator[Finding]:
    apps: dict[str, list[tuple[str, int, str]]] = {}
    for rel, _text, tree in app_py_files(ctx, "FileField"):
        for cls in pyast.class_defs(tree):
            checks = _checked_names(cls)
            for stmt in cls.body:
                if not isinstance(stmt, ast.Assign) or not isinstance(stmt.value, ast.Call):
                    continue
                if not FILE_FIELD.fullmatch(pyast.dotted(stmt.value.func) or ""):
                    continue
                names = [t.id for t in stmt.targets if isinstance(t, ast.Name)]
                if pyast.kwarg(stmt.value, "validators") is not None:
                    continue
                if any(re.search(rf"\b{re.escape(n)}\b", checks) for n in names):
                    continue
                apps.setdefault(_app_of(rel), []).append((rel, stmt.lineno, names[0]))
    for app, fields in sorted(apps.items()):
        fields.sort()
        yield make_finding(
            "OWASP-A04-UNCHECKED-UPLOAD",
            tag=Tag.INFERRED,
            locations=[Location(rel, line) for rel, line, _ in fields],
            snippet=snippet(ctx.index.text(fields[0][0]), fields[0][1]),
            count=len(fields),
            app=app,
            fields=", ".join(dict.fromkeys(name for _, _, name in fields)),
        )


def _meta(cls: ast.ClassDef) -> dict[str, ast.expr]:
    for item in cls.body:
        if isinstance(item, ast.ClassDef) and item.name == "Meta":
            return pyast.assignments(item.body)
    return {}


def _strings(node: ast.AST | None) -> list[str]:
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return [e.value for e in node.elts if isinstance(pyast.constant(e, None), str)]
    return []


def _privilege_models(ctx: Context) -> dict[str, set[str]]:
    """Models that declare a superuser or staff flag (such as a role template), with the
    fields they declare."""
    found = {}
    for _rel, _text, tree in app_py_files(ctx, "is_superuser", "is_staff"):
        for cls in pyast.class_defs(tree):
            fields = {n for n, v in pyast.assignments(cls.body).items() if isinstance(v, ast.Call)}
            if fields & set(ALWAYS[:2]):
                found[cls.name] = fields
    return found


def _exposed(cls: ast.ClassDef, privileged: dict[str, set[str]]) -> tuple[list[str], int]:
    """Privilege fields the form accepts, and the line that lists them."""
    meta = _meta(cls)
    model = (pyast.dotted(meta.get("model")) or "").split(".")[-1].replace("()", "")
    user = user_model(model) or model == "get_user_model" or model in privileged
    fields_node = meta.get("fields")
    listed = _strings(fields_node)
    excluded = set(_strings(meta.get("exclude"))) | set(_strings(meta.get("read_only_fields")))
    declared = [
        n
        for n, v in pyast.assignments(cls.body).items()
        if isinstance(v, ast.Call)
        and not any(
            pyast.constant(pyast.kwarg(v, k), None) is True for k in ("read_only", "disabled")
        )
    ]
    if pyast.constant(fields_node, None) == "__all__" and user:
        own = privileged.get(model)
        listed = [f for f in (*ALWAYS, *GRANTS) if own is None or f in own]
    names = [f for f in dict.fromkeys([*listed, *declared]) if f not in excluded]
    exposed = [f for f in names if f in ALWAYS or (f in GRANTS and user)]
    methods = " ".join(ast.unparse(i) for i in cls.body if isinstance(i, ast.FunctionDef))
    exposed = [
        f
        for f in exposed
        if not re.search(rf"(?:fields\.pop\(|del self\.fields\[)\s*['\"]{f}['\"]", methods)
    ]
    line = getattr(fields_node, "lineno", cls.lineno)
    return exposed, line


def _guard_text(route: Route) -> str:
    handler = route.handler
    parts = [ast.unparse(d) for d in getattr(handler, "decorator_list", [])]
    for item in getattr(handler, "body", [])[:3]:
        if isinstance(item, ast.If) and any(
            isinstance(s, ast.Raise | ast.Return) for s in item.body
        ):
            parts.append(ast.unparse(item.test))
        if isinstance(item, ast.FunctionDef) and item.name == "test_func":
            parts.append(ast.unparse(item))
    return " ".join(parts)


def _superuser_only(route: Route) -> bool:
    guard = _guard_text(route)
    return "is_superuser" in guard and not re.search(r"\bor\b", guard)


def _binds(handler: ast.AST, name: str) -> bool:
    """The view fills the form or serializer from the request, so its fields can be set: a
    call with request data or `data=`, or a writable class view whose form or serializer
    class it is."""
    for call in (n for n in ast.walk(handler) if isinstance(n, ast.Call)):
        if (pyast.dotted(call.func) or "").split(".")[-1] != name:
            continue
        given = " ".join(ast.unparse(a) for a in [*call.args, *(k.value for k in call.keywords)])
        if pyast.kwarg(call, "data") is not None or BOUND.search(given):
            return True
    if isinstance(handler, ast.ClassDef):
        values = pyast.assignments(handler.body)
        chosen = [pyast.dotted(values.get(k)) or "" for k in ("serializer_class", "form_class")]
        bases = " ".join(pyast.base_names(handler))
        writes = any(
            isinstance(i, ast.FunctionDef) and i.name in WRITE_METHODS for i in handler.body
        )
        if any(c.split(".")[-1] == name for c in chosen):
            return writes or (bool(WRITABLE_VIEW.search(bases)) and "ReadOnly" not in bases)
    return False


def _users(ctx: Context, name: str) -> list[Route]:
    found = []
    for route in ctx.detection.routes:
        if isinstance(route.handler, ast.AST) and name in ast.unparse(route.handler):
            if _binds(route.handler, name):
                if all(r.file != route.file or r.line != route.line for r in found):
                    found.append(route)
    return found


@rule(
    "OWASP-A01-PRIVILEGE-FIELDS",
    review="owasp",
    severity="high",
    exploitability="medium",
    owasp="A01",
)
def privilege_fields(ctx: Context) -> Iterator[Finding]:
    privileged = _privilege_models(ctx)
    for rel, text, tree in app_py_files(ctx, "Meta", "Field("):
        if PurePosixPath(rel).name == "admin.py":
            continue
        for cls in pyast.class_defs(tree):
            if not any(FORM_BASE.search(b) for b in pyast.base_names(cls)):
                continue
            exposed, line = _exposed(cls, privileged)
            if not exposed:
                continue
            views = [r for r in _users(ctx, cls.name) if not _superuser_only(r)]
            if not views:
                continue
            public = any(access(ctx, r).level == PUBLIC for r in views)
            yield make_finding(
                "OWASP-A01-PRIVILEGE-FIELDS",
                tag=Tag.CONFIRMED,
                locations=[Location(rel, line), *(Location(r.file, r.line) for r in views)],
                snippet=snippet(text, line),
                severity="critical" if public else None,
                form=cls.name,
                fields=", ".join(exposed),
                views=", ".join(f"{r.path} ({access(ctx, r).level})" for r in views[:5]),
            )
