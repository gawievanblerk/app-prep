"""Unscoped lookups per route, shared by the A01 rules that report them.

`OWASP-A01-UNSCOPED-QUERY` reports them on their own. A public route that
`OWASP-A01-PUBLIC-SENSITIVE` or `OWASP-A01-UNSIGNED-CALLBACK` already reports carries its lookup
inside that finding instead, so one route gives one finding.
"""

from __future__ import annotations

from dpr.model import Location, Route
from dpr.reviews.access import ADMIN, access
from dpr.reviews.leaks_logs import words
from dpr.reviews.lookups import Lookup, model_for, owned
from dpr.reviews.lookups_route import route_lookups
from dpr.reviews.paths import is_test
from dpr.rules import Context

# A record of one of these kinds is a tenant: a caller's role says what they may do, not which
# brokerage, company or branch they belong to.
TENANT_WORDS = frozenset(
    {"brokerage", "company", "branch", "organisation", "organization", "org", "account",
     "agency", "tenant", "workspace", "firm", "franchise", "practice", "team"}
)  # fmt: skip
KEY_WORDS = frozenset({"id", "pk", "uuid", "code", "slug"})


def tenant_key(key: str) -> bool:
    """`brokerage_id`, `company_pk`, `brokerage_branch_id`: every word before the key suffix
    names a tenant kind."""
    parts = words(key)
    if parts and parts[-1] in KEY_WORDS:
        parts = parts[:-1]
    return bool(parts) and all(part in TENANT_WORDS for part in parts)


def tenant_lookup(lookup: Lookup) -> str:
    return next((key for key in lookup.keys if tenant_key(key)), "")


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
