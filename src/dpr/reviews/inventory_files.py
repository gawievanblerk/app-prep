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
from dpr.pii_values import ValueCounts, table_counts, text_counts
from dpr.reviews.leaks_logs import words
from dpr.reviews.paths import is_test
from dpr.reviews.personal import classify, personal_fields
from dpr.rules import Context, make_finding, rule
from dpr.vendored import is_vendored

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
    "${file} is in the working folder and ${what};${size} anyone who can read this machine, its "
    "backups or a copy of the folder can read the records."
)
LOCAL_FIX = (
    "Confirm whether the records are real. If they are, move them out of the project folder to "
    "storage approved for personal data, delete the local copy, and keep the path in .gitignore "
    "so it is never committed."
)
NO_GIT_DETAIL = (
    "${file} is in the scanned folder and ${what};${size} git is not available, so whether the "
    "file is committed is not known."
)
# Delimited data files (None: sniffed) and free-text data files, both judged by value.
TABLE_SUFFIXES = {".csv": ",", ".tsv": "\t", ".psv": "|", ".txt": None, ".dat": None}
TEXT_SUFFIXES = (".json", ".jsonl", ".ndjson", ".sql", ".xml", ".yaml", ".yml")
# Licence and project notes list their authors' addresses; they are not records.
NOTES = re.compile(
    r"(?i)(?:^|/)(?:licen[cs]e|copying|authors|contributors|notice|readme|changelog|history)"
    r"(?:[._-][^/]*)?$"
)


def _delimiter(text: str) -> str | None:
    """The delimiter every one of the first five non-empty lines uses the same number of times."""
    lines = [line for line in text[:8192].splitlines() if line.strip()][:5]
    for delimiter in (",", "\t", "|", ";"):
        found = {line.count(delimiter) for line in lines}
        if len(lines) >= 2 and len(found) == 1 and found != {0}:
            return delimiter
    return None


def value_counts(text: str, suffix: str) -> ValueCounts:
    if suffix in TABLE_SUFFIXES:
        delimiter = _delimiter(text) or TABLE_SUFFIXES[suffix]
        return table_counts(text, delimiter) if delimiter else text_counts(text)
    return text_counts(text)


def _personal_keys(text: str, suffix: str) -> list[str]:
    if suffix not in (".csv", ".json"):
        return []
    keys = _csv_keys(text) if suffix == ".csv" else _json_keys(text)
    personal = [k for k in keys if classify(k) and classify(k).key in DATA_CATEGORIES]
    return personal if len(personal) >= 2 and any(STRONG_KEYS.search(k) for k in personal) else []


def _what(personal: list[str], counts: ValueCounts) -> str:
    parts = []
    if personal:
        parts.append(f"its columns or keys look like personal data ({', '.join(personal[:8])})")
    if counts:
        header = " (no header row)" if counts.headerless else ""
        parts.append(f"its values include {counts.describe()}{header}")
    return ", and ".join(parts)


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
    """A data file with personal column names or keys, or with personal values: several ID
    numbers or IBANs that pass their checks, account numbers next to a branch code, or bulk
    mobile numbers and email addresses. Counts only; no value is kept or reported."""
    for entry in ctx.index.files:
        suffix = PurePosixPath(entry.rel).suffix.lower()
        if suffix not in TABLE_SUFFIXES and suffix not in TEXT_SUFFIXES:
            continue
        if CONFIG_JSON.search(entry.rel) or NOTES.search(entry.rel):
            continue
        if is_vendored(ctx.index, entry.rel):
            continue
        text = ctx.index.text(entry.rel)
        counts = value_counts(text, suffix)
        personal = [] if counts.headerless else _personal_keys(text, suffix)
        if not personal and not counts:
            continue
        rows = text.count("\n") if suffix in TABLE_SUFFIXES else None
        where = _where(ctx, entry.rel)
        if not personal and is_test(entry.rel):
            where["severity"] = "low"
        fmt = {"file": entry.rel, "what": _what(personal, counts)}
        fmt["size"] = f" about {rows} rows," if rows else ""
        template = where.pop("detail_text", None)
        yield make_finding(
            "INV-PII-FILE-IN-REPO",
            tag=Tag.CONFIRMED if personal or counts.confirmed else Tag.INFERRED,
            locations=[Location(entry.rel, 1)],
            detail=Template(template).safe_substitute(fmt) if template else None,
            **where,
            **fmt,
        )
