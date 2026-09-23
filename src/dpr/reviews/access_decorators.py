"""Django auth decorators, including ones the repository defines itself, resolved one level.

A decorator such as `def is_complaints_user(f): return login_required(user_passes_test(t)(f))`
guards its views just as the Django decorators it wraps do. So does one whose body redirects
to the login page or raises PermissionDenied when `request.user` fails a check.
"""

from __future__ import annotations

import ast
import re

from dpr.parsing import imports, pyast
from dpr.parsing.routes_py import defined_in
from dpr.reviews.access_names import ADMIN, AUTHENTICATED, Access
from dpr.rules import Context

DJANGO_DECORATORS = re.compile(
    r"(?:\w+\.)*(login_required|permission_required|user_passes_test|staff_member_required"
    r"|superuser_required)"
)
ROLE_DECORATORS = frozenset({"permission_required", "user_passes_test"})
ADMIN_DECORATORS = frozenset({"staff_member_required", "superuser_required"})
DJANGO_SUBJECTS = ("request.user", "self.request.user")
ROLE_CHECK = re.compile(
    r"\bhas_perms?\(|\bis_superuser\b|\bis_staff\b|\bgroups\b|PermissionDenied"
    r"|\b(?:u|user)\.is_(?!authenticated\b|anonymous\b|active\b)\w+"
)
USER_CHECK = re.compile(r"\b(?:request|req|self\.request)\.user\b|\buser\.is_\w+")
LOGIN_EXIT = re.compile(
    r"PermissionDenied|HttpResponseForbidden|redirect_to_login|login_url|LOGIN_URL"
    r"|status=40[13]|['\"][^'\"]*login[^'\"]*['\"]"
)


def django_decorator(name: str) -> Access | None:
    """Access given by one of Django's own auth decorators, by its dotted name."""
    match = DJANGO_DECORATORS.fullmatch(name)
    if not match:
        return None
    kind = match.group(1)
    level = ADMIN if kind in ADMIN_DECORATORS else AUTHENTICATED
    return Access(level, DJANGO_SUBJECTS, f"@{kind}", role=f"@{kind}" * (kind in ROLE_DECORATORS))


def _definition(ctx: Context, rel: str, name: str) -> ast.AST | None:
    parts = name.split(".")
    if len(parts) == 1:
        found = defined_in(ctx.index, rel, parts[0])
    elif len(parts) == 2:
        tree = pyast.parse_file(ctx.index, rel)
        target = imports.py_imports(ctx.index, rel, tree).get(parts[0])
        found = defined_in(ctx.index, target[0], parts[1]) if target and not target[1] else None
    else:
        found = None
    node = found[1] if found else None
    return node if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) else None


def _read(fn: ast.AST, name: str) -> Access | None:
    wrapped = [
        django_decorator(pyast.dotted(call.func) or "")
        for call in ast.walk(fn)
        if isinstance(call, ast.Call)
    ]
    wrapped = [found for found in wrapped if found is not None]
    text = ast.unparse(fn)
    if not wrapped and not (USER_CHECK.search(text) and LOGIN_EXIT.search(text)):
        return None
    admin = any(found.level == ADMIN for found in wrapped)
    role = any(found.role for found in wrapped) or bool(ROLE_CHECK.search(text))
    via = ", ".join(dict.fromkeys(found.evidence.lstrip("@") for found in wrapped))
    evidence = f"@{name} ({via})" if via else f"@{name}"
    return Access(
        ADMIN if admin else AUTHENTICATED, DJANGO_SUBJECTS, evidence, role=f"@{name}" * role
    )


def custom_decorator(ctx: Context, rel: str, name: str) -> Access | None:
    """Access given by a decorator the repository defines: it wraps a Django auth decorator,
    or its body sends a caller who fails a `request.user` check to login or a 403."""
    memo = ctx.facts.setdefault("django-custom-decorators", {})
    if (rel, name) not in memo:
        fn = _definition(ctx, rel, name) if name else None
        memo[(rel, name)] = _read(fn, name.split(".")[-1]) if fn is not None else None
    return memo[(rel, name)]


def decorator_source(ctx: Context, rel: str, name: str) -> str:
    """The source of a decorator the repository defines, or "" when it is not found."""
    fn = _definition(ctx, rel, name) if name else None
    return ast.unparse(fn) if fn is not None else ""
