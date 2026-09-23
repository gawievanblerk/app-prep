"""Review 1, inventory: personal fields nothing reads, and personal data files in the repository."""

from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import Iterator
from pathlib import PurePosixPath
from string import Template

from dpr.model import Finding, Location, Tag
from dpr.parsing.pymigrations import migration_folders
from dpr.reviews.leaks_logs import words
from dpr.reviews.paths import is_test
from dpr.reviews.personal import classify, personal_fields
from dpr.rules import Context, make_finding, rule

CODE_SUFFIXES = (
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".vue",
    ".svelte",
    ".html",
    ".j2",
    ".jinja",
    ".jinja2",
)
CONFIG_JSON = re.compile(
    r"(?:^|/)(?:package(?:-lock)?|tsconfig[\w.-]*|jsconfig|composer|vercel|firebase|staticwebapp\.config"
    r"|\.eslintrc|\.prettierrc|renovate|manifest|app|turbo|nx|project|components|angular)\.json$"
    r"|\.schema\.json$|openapi\.json$|swagger\.json$"
)
DATA_CATEGORIES = ("identifiers", "government_ids", "financial", "special", "children")
REQUEST_INPUT = re.compile(
    r"(?i)req|request|body|data|input|payload|form|params|query|args|values|json|validated_data"
)
STRONG_KEYS = re.compile(
    r"(?i)e_?mail|phone|mobile|first_?name|last_?name|full_?name|surname|birth|dob|ssn|passport"
    r"|id_?number|iban|account_?number|street|address_?(?:line)?1"
)


def _read(line: str, name: str) -> bool:
    """The line reads the field as an attribute of a record (`planned.name`) that is not being
    assigned. An attribute of the request input (`req.body.name`, `data.name`) is not a read."""
    pattern = rf"([\w$]+)\??\.{re.escape(name)}\b(?!\s*=(?!=))"
    return any(not REQUEST_INPUT.fullmatch(m.group(1)) for m in re.finditer(pattern, line))


def _write(line: str, name: str) -> bool:
    return bool(
        re.search(rf"\b{re.escape(name)}\b\s*[:=](?!=)", line)
        or re.search(rf"[\"']{re.escape(name)}[\"']\s*[:,\]}})]", line)
    )


def field_reads(ctx: Context, name: str, skip: set[str]) -> tuple[int, int]:
    """(reads, writes) of a field name across code files outside models and migrations."""
    pattern = re.compile(rf"\b{re.escape(name)}\b")
    reads = writes = 0
    for entry in ctx.index.files:
        if entry.rel in skip or is_test(entry.rel) or not entry.rel.endswith(CODE_SUFFIXES):
            continue
        text = ctx.index.text(entry.rel)
        if name not in text:
            continue
        for line in text.splitlines():
            if pattern.search(line):
                if _write(line, name) and not _read(line, name):
                    writes += 1
                else:
                    reads += 1
    return reads, writes


@rule("INV-UNUSED-FIELD", review="inventory", severity="low", exploitability="low")
def unused_field(ctx: Context) -> Iterator[Finding]:
    folders = [f for f, _ in migration_folders(ctx.index)]
    skip = {m.location.file for m in ctx.detection.models}
    skip |= {f.rel for f in ctx.index.files if any(f.rel.startswith(d + "/") for d in folders)}
    groups: dict[str, list] = {}
    for item in personal_fields(ctx):
        name = item.field.name
        if len(words(name)) < 2 or item.category.key == "account":
            continue
        reads, _writes = field_reads(ctx, name, skip)
        if reads == 0:
            groups.setdefault(f"{item.model.location.file}:{item.model.name}", []).append(item)
    for items in groups.values():
        yield make_finding(
            "INV-UNUSED-FIELD",
            tag=Tag.INFERRED,
            locations=[i.field.location for i in items][:10],
            model=items[0].model.name,
            fields=", ".join(i.field.name for i in items),
        )


def _json_keys(text: str) -> list[str]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return list(data[0])
    if isinstance(data, dict):
        rows = next(
            (v for v in data.values() if isinstance(v, list) and v and isinstance(v[0], dict)), None
        )
        return list(rows[0]) if rows else list(data)
    return []


def _csv_keys(text: str) -> list[str]:
    try:
        return next(csv.reader(io.StringIO(text.split("\n", 1)[0])))
    except (StopIteration, csv.Error):
        return []


LOCAL_DETAIL = (
    "${file} is in the working folder and its columns or keys look like personal data "
    "(${columns});${size} anyone who can read this machine, its backups or a copy of the folder "
    "can read the records."
)
LOCAL_FIX = (
    "Confirm whether the records are real. If they are, move them out of the project folder to "
    "storage approved for personal data, delete the local copy, and keep the path in .gitignore "
    "so it is never committed."
)
NO_GIT_DETAIL = (
    "${file} has columns or keys that look like personal data (${columns});${size} git is not "
    "available, so whether the file is committed is not known."
)


def _where(ctx: Context, rel: str) -> dict:
    """Title, severity and text for a data file by what git knows about it: only a tracked
    file is called committed."""
    tracked = ctx.index.tracked
    if tracked is None:
        return {"where": "in the scanned folder", "detail_text": NO_GIT_DETAIL}
    if rel in tracked:
        return {"where": "committed to the repository"}
    return {
        "where": "in the working folder, not committed",
        "detail_text": LOCAL_DETAIL,
        "severity": "medium",
        "fix": LOCAL_FIX,
        "verify": "Search the project folder for the file name and confirm it is gone.",
    }


@rule("INV-PII-FILE-IN-REPO", review="inventory", severity="high", exploitability="medium")
def pii_file_in_repo(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.files:
        suffix = PurePosixPath(entry.rel).suffix.lower()
        if suffix not in (".csv", ".json") or CONFIG_JSON.search(entry.rel):
            continue
        text = ctx.index.text(entry.rel)
        keys = _csv_keys(text) if suffix == ".csv" else _json_keys(text)
        personal = [k for k in keys if classify(k) and classify(k).key in DATA_CATEGORIES]
        if len(personal) >= 2 and any(STRONG_KEYS.search(k) for k in personal):
            rows = text.count("\n") if suffix == ".csv" else None
            size = f" about {rows} rows," if rows else ""
            where = _where(ctx, entry.rel)
            fmt = {"file": entry.rel, "columns": ", ".join(personal[:8]), "size": size}
            template = where.pop("detail_text", None)
            yield make_finding(
                "INV-PII-FILE-IN-REPO",
                tag=Tag.CONFIRMED,
                locations=[Location(entry.rel, 1)],
                detail=Template(template).safe_substitute(fmt) if template else None,
                **where,
                **fmt,
            )
