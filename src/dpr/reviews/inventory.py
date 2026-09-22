"""Review 1, data inventory: what personal data the code holds, where it goes, how long it stays."""

from __future__ import annotations

import dpr.reviews.inventory_fields  # noqa: F401  (registers rules)
import dpr.reviews.inventory_files  # noqa: F401  (registers rules)
import dpr.reviews.inventory_retention  # noqa: F401  (registers rules)
import dpr.reviews.inventory_sdks  # noqa: F401  (registers rules)
from dpr.data import load
from dpr.model import Finding, Part, ReviewSection
from dpr.reviews.inventory_answers import answers
from dpr.reviews.inventory_map import flow_lines, model_rows, runtime_rows
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
FLOWS_NOTE = (
    "INFERRED: flows are joined by field names, tables and the code each route calls, not traced "
    "at runtime."
)
OUTSIDE = (
    "- Support inboxes, CRMs, spreadsheets and analytics dashboards that the team uses directly\n"
    "- Provider consoles and their retention, region and access settings\n"
    "- Backups, exports and copies of production data on staff machines"
)
NO_REASON_RULES = ("INV-UNUSED-FIELD", "INV-CATCHALL-JSON", "INV-PII-FILE-IN-REPO")


def _categories(ctx: Context) -> str:
    found: dict[str, set[str]] = {}
    for item in personal_fields(ctx):
        found.setdefault(item.category.key, set()).add(item.model.table.split(".")[-1])
    lines = []
    for category in load("pii_terms.yaml")["categories"]:
        tables = sorted(found.get(category["key"], set()))
        status = f"found in {', '.join(tables[:8])}" if tables else "none found by field name"
        lines.append(f"- {category['label']}: {status}")
    return "\n".join(lines)


def _no_reason(ctx: Context, findings: list[Finding]) -> str:
    lines = [
        f"- {f.title} (`{f.locations[0]}`, {f.rule_id})"
        for f in findings
        if f.rule_id in NO_REASON_RULES and f.locations
    ]
    free_text = sorted(
        {
            f"{i.model.table.split('.')[-1]}.{i.field.name}"
            for i in personal_fields(ctx)
            if i.category.key == "content"
        }
    )
    if free_text:
        lines.append(
            "- Free-text fields that invite more than the product needs: "
            + ", ".join(free_text[:12])
        )
    return "\n".join(lines) or "Nothing flagged from code."


def _not_covered(ctx: Context) -> str:
    detected = {s.name for s in ctx.detection.sdks}
    lines = [OUTSIDE]
    for sdk in load("sdks.yaml"):
        word = sdk["name"].upper().replace("-", "_")
        names = [e.name for e in ctx.detection.env_vars if word in e.name]
        if names and sdk["name"] not in detected:
            lines.append(
                f"- {sdk['name']} is configured by {', '.join(names[:3])}, but no call site was "
                "found in code"
            )
    return "\n".join(lines)


def run(ctx: Context) -> ReviewSection:
    return ReviewSection(
        "inventory",
        [Part("text", "How to read this inventory", body=INTRO), Part("findings", "Findings")],
    )


def finish(ctx: Context, section: ReviewSection, findings: list[Finding]) -> None:
    flows = "\n".join(flow_lines(ctx)) or "No collection route was matched to a table."
    parts = [
        Part("table", "Personal data map", MAP_COLUMNS, tuple(model_rows(ctx) + runtime_rows(ctx))),
        Part("text", "Categories checked", body=_categories(ctx)),
        Part("text", "Data flows", body=f"{FLOWS_NOTE}\n\n{flows}"),
        Part("text", "Collected with no clear reason", body=_no_reason(ctx, findings)),
        Part("text", "Not covered by this repo", body=_not_covered(ctx)),
    ]
    position = next(i for i, p in enumerate(section.parts) if p.kind == "findings")
    section.parts[position:position] = parts
    ctx.facts["answered"] = answers(ctx, findings)
