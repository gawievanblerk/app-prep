"""Review 1, inventory: answers the repository gives to the questions a lawyer asks first."""

from __future__ import annotations

import re

from dpr.model import Answer, Finding
from dpr.parsing import hcl
from dpr.reviews.access import PUBLIC, access
from dpr.reviews.inventory_retention import deletion_paths, iac_retention, soft_delete
from dpr.reviews.inventory_sources import sdk_receipts
from dpr.reviews.personal import personal_fields
from dpr.rules import Context

DATA_REQUEST_ROUTE = re.compile(
    r"(?i)(?:export|download)\S*(?:me|my|account|profile|data)|/me/(?:export|data|download)"
    r"|gdpr|erasure|data-?request|(?:delete|close)-?account"
)
AUDIT_MODEL = re.compile(r"(?i)audit|activity|access_?log|event_?log")
REGION_VARIABLE = re.compile(r"(?i)^(?:location|region|azure_region|aws_region|gcp_region)$")


def _data_held(ctx: Context) -> Answer | None:
    by_label: dict[str, set[str]] = {}
    for item in personal_fields(ctx):
        by_label.setdefault(item.category.label, set()).add(item.model.table.split(".")[-1])
    if not by_label:
        return None
    parts = [f"{label} ({', '.join(sorted(tables)[:6])})" for label, tables in by_label.items()]
    return Answer(
        "What personal data does the code hold?", "; ".join(parts) + ".", "section 1 data map"
    )


def _regions(ctx: Context) -> list[str]:
    found = []
    for entry in ctx.index.with_suffix(".tf"):
        for block in hcl.blocks(ctx.index.text(entry.rel)):
            if block.kind == "variable" and block.labels and REGION_VARIABLE.match(block.labels[0]):
                value, line = hcl.attributes(block).get("default", ("", 0))
                if value:
                    found.append(f"{hcl.unquote(value)} (`{entry.rel}:{line}`)")
    return found


def _where(ctx: Context) -> Answer | None:
    parts = []
    engines = [d for d in ctx.detection.databases]
    if engines:
        parts.append("databases: " + ", ".join(engines))
    storage = [s.name for s in ctx.detection.sdks if s.category == "storage"]
    if storage:
        parts.append("object storage: " + ", ".join(storage))
    logs = [s.name for s in ctx.detection.sdks if s.category in ("monitoring", "error-tracking")]
    if logs:
        parts.append("logs and telemetry: " + ", ".join(logs))
    regions = _regions(ctx)
    if regions:
        parts.append("region per Terraform defaults: " + ", ".join(regions) + ", not verified")
    if not parts:
        return None
    return Answer(
        "Where does it live?", "; ".join(parts) + ".", "detection and infrastructure code"
    )


def _recipients(ctx: Context) -> Answer | None:
    names = [s.name for s in ctx.detection.sdks if s.recipient]
    hosts = [h for h in ctx.detection.hosting if h not in ("docker", "terraform")]
    if not names and not hosts:
        return None
    traced = {sdk.name for sdk, _, _, _ in sdk_receipts(ctx)}
    listed = [f"{n} (call sites traced)" if n in traced else n for n in names]
    text = ", ".join([*listed, *(f"{h} (hosting)" for h in hosts)])
    return Answer(
        "Which third parties receive a copy?", text + ".", "detection and INV-SDK-RECEIVES-PII"
    )


def _retention(ctx: Context) -> Answer:
    people = {f"{p.model.location.file}:{p.model.name}": p.model for p in personal_fields(ctx)}
    hard = [m.name for k, m in people.items() if deletion_paths(ctx).get(k)]
    soft = [
        m.name for k, m in people.items() if not deletion_paths(ctx).get(k) and soft_delete(ctx, m)
    ]
    none = len(people) - len(hard) - len(soft)
    text = (
        f"{len(hard)} of {len(people)} personal data tables have a hard delete path, {len(soft)} "
        f"only set a soft delete flag, {none} have no deletion path. No retention period is "
        "enforced by a scheduled purge in code."
    )
    settings = [f"{s} (`{loc}`)" for _r, s, loc in iac_retention(ctx)]
    if settings:
        text += " Infrastructure settings: " + ", ".join(settings[:4]) + "."
    return Answer("What retention does the code enforce?", text, "INV-NO-DELETION-PATH")


def _requests(ctx: Context) -> Answer:
    routes = [r for r in ctx.detection.routes if DATA_REQUEST_ROUTE.search(r.path)]
    if not routes:
        text = "No export-my-data or erase-my-account route was found."
    else:
        text = "Routes that may serve data requests: " + ", ".join(
            f"{r.method} {r.path} (`{r.file}:{r.line}`)" for r in routes[:5]
        )
    return Answer("Is there a path for access or deletion requests?", text, "route table")


def _who(ctx: Context) -> Answer | None:
    evidence = sorted(
        {access(ctx, r).evidence for r in ctx.detection.routes if access(ctx, r).level != PUBLIC}
    )
    if not evidence:
        return None
    text = (
        "Routes are guarded by: "
        + ", ".join(evidence[:10])
        + ". Database and console access UNKNOWN."
    )
    return Answer("Who internally can read personal data?", text, "review 5 route classification")


def _audit(ctx: Context) -> Answer:
    models = [
        m.name
        for m in ctx.detection.models
        if AUDIT_MODEL.search(m.name) or AUDIT_MODEL.search(m.table)
    ]
    if models:
        text = (
            f"Audit tables exist ({', '.join(models)}); whether reads and "
            "exports are recorded is not decided from code."
        )
    else:
        text = (
            "No audit or activity table was found, so reads and "
            "exports are not recorded in the database."
        )
    return Answer("Is access to personal data logged?", text, "data models")


def _special(findings: list[Finding]) -> Answer:
    special = [f for f in findings if f.rule_id in ("INV-SPECIAL-CATEGORY", "INV-CHILDREN-SIGNAL")]
    if special:
        text = "; ".join(f"{f.title} (`{f.locations[0]}`)" for f in special)
    else:
        text = "No special category or children's data fields were found by name."
    return Answer(
        "Is special category or children's data involved?",
        text,
        "INV-SPECIAL-CATEGORY, INV-CHILDREN-SIGNAL",
    )


def _automated(ctx: Context) -> Answer | None:
    llm = [sdk.name for sdk, _, _, _ in sdk_receipts(ctx) if sdk.category in ("llm", "ml")]
    if not llm:
        return None
    return Answer(
        "Is personal data sent to AI or automated processing services?",
        (
            f"Prompts or free text reach {', '.join(llm)}; whether they "
            "include personal data depends on runtime content."
        ),
        "INV-SDK-RECEIVES-PII",
    )


def answers(ctx: Context, findings: list[Finding]) -> list[Answer]:
    items = [
        _data_held(ctx),
        _where(ctx),
        _recipients(ctx),
        _retention(ctx),
        _requests(ctx),
        _who(ctx),
        _audit(ctx),
        _special(findings),
        _automated(ctx),
    ]
    return [a for a in items if a is not None]
