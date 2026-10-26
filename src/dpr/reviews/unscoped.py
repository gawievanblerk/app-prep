"""Unscoped lookups per route, shared by the A01 rules that report them.

`OWASP-A01-UNSCOPED-QUERY` reports them on their own. A public route that
`OWASP-A01-PUBLIC-SENSITIVE` or `OWASP-A01-UNSIGNED-CALLBACK` already reports carries its lookup
inside that finding instead, so one route gives one finding.
"""

from __future__ import annotations

import ast
import re

from dpr.model import Location, Route
from dpr.parsing import pyast
from dpr.reviews.access import ADMIN, access
from dpr.reviews.access_decorators import decorator_source
from dpr.reviews.leaks_logs import words
from dpr.reviews.lookups import Lookup, model_for, owned
from dpr.reviews.lookups_route import handler_functions, route_lookups
from dpr.reviews.paths import is_test
from dpr.rules import Context

# A record of one of these kinds is a tenant: a caller's role says what they may do, not which
# brokerage, company or branch they belong to.
TENANT_WORDS = frozenset(
    {"brokerage", "company", "branch", "organisation", "organization", "org", "account",
     "agency", "tenant", "workspace", "firm", "franchise", "practice", "team"}
)  # fmt: skip
KEY_WORDS = frozenset({"id", "pk", "uuid", "code", "slug"})
# A back-office gate: superuser or staff tests, and permissions or groups named for
# administering (`brokerage.brokerage_admin`, `manage_brokerages`, a group "Admin").
ADMIN_TEST = re.compile(r"\bis_superuser\b|\bis_staff\b")
MEMBER_TEST = re.compile(
    r"\b(?:u|user)\.is_(?!superuser\b|staff\b|authenticated\b|anonymous\b|active\b)\w+"
)
PERMISSION = re.compile(r"""['"]([a-z_]\w*)\.(\w+)['"]""")
GROUP_NAMES = re.compile(r"groups\.filter\(\s*name\w*\s*=\s*([^)]*)\)")
ADMIN_WORDS = frozenset({"admin", "administrator", "administer", "superuser", "staff", "manage"})
MANAGE_VERBS = frozenset({"add", "change", "delete"})
ROLE_TEST = re.compile(r"\.(?:has_perms?|is_superuser|is_staff|groups)\b|\.is_\w+")


def tenant_key(key: str) -> bool:
    """`brokerage_id`, `company_pk`, `brokerage_branch_id`: every word before the key suffix
    names a tenant kind."""
    parts = words(key)
    if parts and parts[-1] in KEY_WORDS:
        parts = parts[:-1]
    return bool(parts) and all(part in TENANT_WORDS for part in parts)


def tenant_lookup(lookup: Lookup) -> str:
    return next((key for key in lookup.keys if tenant_key(key)), "")


def _gate_text(ctx: Context, route: Route) -> tuple[str, list[str]]:
    """The role checks guarding a route: its decorators (and the source of the repository's own
    decorators), a class view's permission attribute, and role tests in the handler; and the
    names of its decorators and bases."""
    handler = route.handler if isinstance(route.handler, ast.AST) else None
    if handler is None:
        return "", []
    parts, names = [], []
    for dec in getattr(handler, "decorator_list", []):
        name = pyast.dotted(dec.func if isinstance(dec, ast.Call) else dec) or ""
        names.append(name)
        parts += [ast.unparse(dec), decorator_source(ctx, route.file, name)]
    if isinstance(handler, ast.ClassDef):
        names += pyast.base_names(handler)
        value = pyast.assignments(handler.body).get("permission_required")
        parts += [ast.unparse(value)] if value is not None else []
    for fn in handler_functions(handler):
        for node in ast.walk(fn):
            if isinstance(node, ast.If | ast.Assert) and ROLE_TEST.search(ast.unparse(node.test)):
                parts.append(ast.unparse(node.test))
    return "\n".join(parts), names


def admin_gate(ctx: Context, route: Route, key: str) -> bool:
    """Every role check on the route is back-office administration: a superuser or staff test, a
    permission or group named for administering, or a permission to add, change or delete the
    tenant model itself (`change_brokerage` for `brokerage_id`). A permission or role an ordinary
    member or agent may hold (`view_commission`, `is_advisor`) is not, even beside an admin test."""
    text, names = _gate_text(ctx, route)
    kind = words(key)
    kind = kind[:-1] if kind and kind[-1] in KEY_WORDS else kind
    checks = [True for _ in ADMIN_TEST.finditer(text)]
    checks += [False for _ in MEMBER_TEST.finditer(text)]
    checks += [bool(set(words(n)) & ADMIN_WORDS) for n in names if set(words(n)) & ADMIN_WORDS]
    for _app, codename in PERMISSION.findall(text):
        parts = words(codename)
        managed = parts[:1] and parts[0] in MANAGE_VERBS and bool(set(kind) & set(parts[1:]))
        checks.append(bool(set(parts) & ADMIN_WORDS) or bool(managed))
    for group in GROUP_NAMES.findall(text):
        literals = re.findall(r"""['"]([^'"]+)['"]""", group)
        checks += [bool(set(words(name)) & ADMIN_WORDS) for name in literals]
    return bool(checks) and all(checks)


def unscoped(ctx: Context) -> list[tuple[Route, list[Lookup], str]]:
    """Unscoped lookups on owned or unknown models, and on tenants picked by a tenant key,
    grouped per route, first lookup first."""
    if "unscoped_lookups" not in ctx.facts:
        found = []
        for route in ctx.detection.routes:
            level = access(ctx, route)
            if level.level == ADMIN or is_test(route.file):
                continue
            items = [
                (lookup, check)
                for lookup, check in route_lookups(ctx, route, level)
                if check != "owner"
                and not lookup.visible
                and (owned(ctx, lookup.model) is not False or tenant_lookup(lookup))
            ]
            if items:
                checks = {check for _, check in items}
                found.append(
                    (route, [lookup for lookup, _ in items], "helper" if "helper" in checks else "")
                )
        ctx.facts["unscoped_lookups"] = found
    return ctx.facts["unscoped_lookups"]


def route_unscoped(ctx: Context, route: Route) -> list[Lookup]:
    return next((items for r, items, _check in unscoped(ctx) if r == route), [])


def sequential_id(ctx: Context, lookup: Lookup) -> Location | None:
    """The auto-increment integer key of an owned model looked up by primary key."""
    model = model_for(ctx, lookup.model)
    if not lookup.by_primary_key or model is None or not owned(ctx, lookup.model):
        return None
    id_field = next((f for f in model.fields if f.name in ("id", "pk")), None)
    return id_field.location if id_field is not None and id_field.autoincrement else None
