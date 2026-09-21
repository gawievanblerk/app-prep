"""Review 1, inventory: rows of the personal data map and one line per data flow."""

from __future__ import annotations

import re

from dpr.discovery.approots import root_of
from dpr.model import DataModel, Location
from dpr.reviews.auth_flows import route_code
from dpr.reviews.inventory_retention import iac_retention, readers, retention_text
from dpr.reviews.inventory_sources import Collection, collection_points, sdk_receipts
from dpr.reviews.leaks import sentry_inits
from dpr.reviews.leaks_logs import destinations, logged_locations, words
from dpr.reviews.paths import is_test
from dpr.reviews.personal import PersonalField, personal_fields
from dpr.rules import Context
from dpr.walk import line_of

BROWSER_STORAGE = re.compile(r"(?:localStorage|sessionStorage)\.setItem\(\s*([^,]+),")
MAX_FLOWS = 25


def _groups(ctx: Context) -> list[list[PersonalField]]:
    """Personal fields grouped per model, computed once per run."""
    if "inventory_groups" not in ctx.facts:
        groups: dict[str, list[PersonalField]] = {}
        for item in personal_fields(ctx):
            if not is_test(item.model.location.file):
                key = f"{item.model.location.file}:{item.model.name}"
                groups.setdefault(key, []).append(item)
        ctx.facts["inventory_groups"] = [groups[k] for k in sorted(groups)]
    return ctx.facts["inventory_groups"]


def _table(model: DataModel) -> str:
    return model.table.split(".")[-1]


def _named(point: Collection, items: list[PersonalField]) -> bool:
    stem = words(items[0].model.name)[-1].rstrip("s")
    subject = f"{point.route.path} {point.source}".lower()
    return (
        bool(stem) and stem in subject and bool({i.field.name for i in items} & set(point.fields))
    )


def _overlaps(point: Collection, items: list[PersonalField]) -> bool:
    overlap = {i.field.name for i in items} & set(point.fields)
    return len(overlap) >= 2 and len(overlap) * 2 >= len(point.fields)


def targets(ctx: Context, point: Collection) -> list[list[PersonalField]]:
    """Models a collection point writes to: models its route names, else models it mostly fills."""
    if point.route is None:
        return []
    home = root_of(ctx.detection.app_roots, point.location.file)
    local = [
        items
        for items in _groups(ctx)
        if root_of(ctx.detection.app_roots, items[0].model.location.file) == home
    ]
    named = [items for items in local if _named(point, items)]
    return named or [items for items in local if _overlaps(point, items)]


def _points(ctx: Context, items: list[PersonalField]) -> list[Collection]:
    return [c for c in collection_points(ctx) if any(g is items for g in targets(ctx, c))]


def _collected(ctx: Context, items: list[PersonalField]) -> str:
    points = _points(ctx, items)
    if not points:
        return "not found in request schemas"
    shown = [f"{c.route.method} {c.route.path} (`{c.location}`)" for c in points[:3]]
    more = f" and {len(points) - 3} more" if len(points) > 3 else ""
    return "; ".join(shown) + more


def _reached_sdks(ctx: Context, point: Collection) -> list[str]:
    route = point.route
    code = route_code(ctx, route)
    files = {c.rel for c in code}
    return [
        sdk.name
        for sdk, locations, _tag, _what in sdk_receipts(ctx)
        if files & {loc.file for loc in locations}
    ]


def _lives(ctx: Context, model: DataModel) -> str:
    engines = ", ".join(d for d in ctx.detection.databases if d not in ("supabase", "firebase"))
    text = f"table {_table(model)}" + (f" ({engines})" if engines else "")
    backups = [f"{s} (`{loc}`)" for _r, s, loc in iac_retention(ctx) if "backup" in s]
    if backups:
        text += "; backups per Terraform: " + ", ".join(backups[:2])
    return text


def _third_parties(ctx: Context, items: list[PersonalField]) -> str:
    names = sorted({name for point in _points(ctx, items) for name in _reached_sdks(ctx, point)})
    return ", ".join(f"{n} (INFERRED, reached from the collecting route)" for n in names) or (
        "none found in code"
    )


def model_rows(ctx: Context) -> list[tuple[str, ...]]:
    rows = []
    for items in _groups(ctx):
        model = items[0].model
        rows.append(
            (
                f"{_table(model)}: " + ", ".join(f"`{i.field.name}`" for i in items),
                ", ".join(dict.fromkeys(i.category.label for i in items)),
                _collected(ctx, items),
                _lives(ctx, model),
                _third_parties(ctx, items),
                retention_text(ctx, model),
                readers(ctx, model),
                f"`{model.location}` CONFIRMED",
            )
        )
    return rows


def _log_retention(ctx: Context) -> str:
    logs = [f"{s} (`{loc}`)" for _r, s, loc in iac_retention(ctx) if "backup" not in s]
    return "per Terraform: " + ", ".join(logs[:3]) if logs else "UNKNOWN"


def runtime_rows(ctx: Context) -> list[tuple[str, ...]]:
    rows = []
    runtime = [c for c in collection_points(ctx) if c.route is None]
    if runtime:
        labels = ", ".join(dict.fromkeys(c.fields[0] for c in runtime))
        exported = sorted({d for c in runtime for d in destinations(ctx, c.location.file)})
        rows.append(
            (
                labels,
                "Technical identifiers",
                "captured from requests: " + ", ".join(f"`{c.location}`" for c in runtime[:3]),
                "request handling and server logs",
                ", ".join(exported) or "none found in code",
                _log_retention(ctx),
                "UNKNOWN",
                "INFERRED",
            )
        )
    logged = logged_locations(ctx)
    if logged:
        exported = sorted({d for loc in logged for d in destinations(ctx, loc.file)})
        rows.append(
            (
                "values written by log calls",
                "Contact and identity, request data",
                f"{len(logged)} log calls (see review 6, LEAK-LOGGED-PII)",
                "application logs",
                ", ".join(exported) or "none found in code",
                _log_retention(ctx),
                "anyone with log access, UNKNOWN",
                "INFERRED",
            )
        )
    inits = sentry_inits(ctx)
    if inits:
        pii = (
            "sends default personal data"
            if any(i.sends_pii for i in inits)
            else "default scrubbing"
        )
        rows.append(
            (
                "error events with request and user context",
                "Technical identifiers, request data",
                "errors raised in the app: " + ", ".join(f"`{i.location}`" for i in inits[:3]),
                "the error tracker",
                f"sentry ({pii})",
                "UNKNOWN",
                "anyone with error tracker access, UNKNOWN",
                "CONFIRMED",
            )
        )
    storage = _browser_storage(ctx)
    if storage:
        keys = ", ".join(dict.fromkeys(k for k, _ in storage))
        rows.append(
            (
                f"browser storage keys: {keys}",
                "Technical identifiers, preferences",
                "set by the frontend: " + ", ".join(f"`{loc}`" for _, loc in storage[:3]),
                "the visitor's browser",
                "none",
                "until the visitor clears it",
                "the visitor",
                "CONFIRMED",
            )
        )
    return rows


def _browser_storage(ctx: Context) -> list[tuple[str, Location]]:
    found = []
    for entry in ctx.index.js_files:
        if is_test(entry.rel):
            continue
        text = ctx.index.text(entry.rel)
        for match in BROWSER_STORAGE.finditer(text):
            found.append(
                (
                    match.group(1).strip().strip("'\"`"),
                    Location(entry.rel, line_of(text, match.start())),
                )
            )
    return found


def flow_lines(ctx: Context) -> list[str]:
    lines = []
    for point in [c for c in collection_points(ctx) if c.route is not None][:MAX_FLOWS]:
        route = point.route
        stores = sorted({_table(items[0].model) for items in targets(ctx, point)})
        exported = destinations(ctx, route.file)
        steps = [f"{route.method} {route.path} (`{point.location}`)"]
        steps.append(", ".join(stores) if stores else "no matching table found")
        steps += _reached_sdks(ctx, point)
        if exported:
            steps.append(f"logs to {', '.join(exported)} on error or log calls")
        lines.append("- " + " -> ".join(steps))
    return lines
