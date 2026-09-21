"""Review 1, data inventory: what personal data the code holds, where it goes, how long it stays."""

from __future__ import annotations

import dpr.reviews.inventory_fields  # noqa: F401  (registers rules)
import dpr.reviews.inventory_sources  # noqa: F401  (registers rules)
from dpr.model import Part, ReviewSection
from dpr.reviews.personal import personal_fields
from dpr.rules import Context

INTRO = (
    "An inventory of what the code shows, not legal advice. Fields are matched to personal data "
    "categories by name. Retention and regions are never assumed: UNKNOWN means the repository "
    "does not say."
)
MAP_COLUMNS = (
    "Field",
    "What it is",
    "Where collected",
    "Where it lives",
    "Third parties with a copy",
    "Retention",
    "Who internally can read it",
    "Evidence",
)


def map_rows(ctx: Context) -> tuple[tuple[str, ...], ...]:
    groups: dict[tuple[str, str], list] = {}
    for item in personal_fields(ctx):
        groups.setdefault((item.model.location.file, item.model.name), []).append(item)
    rows = []
    for (_file, _name), items in sorted(groups.items()):
        model = items[0].model
        fields = ", ".join(f"`{i.field.name}`" for i in items)
        labels = ", ".join(dict.fromkeys(i.category.label for i in items))
        rows.append(
            (
                f"{model.table.split('.')[-1]}: {fields}",
                labels,
                "UNKNOWN",
                f"table {model.table.split('.')[-1]} ({model.source})",
                "none found",
                "UNKNOWN",
                "UNKNOWN",
                f"`{model.location}` CONFIRMED",
            )
        )
    return tuple(rows)


def run(ctx: Context) -> ReviewSection:
    return ReviewSection(
        "inventory",
        [
            Part("text", "How to read this inventory", body=INTRO),
            Part("table", "Personal data map", MAP_COLUMNS, map_rows(ctx)),
            Part("findings", "Findings"),
        ],
    )
