"""Review 6, leaks: committed documents, databases and real-looking email addresses."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import PurePosixPath

from dpr.gitutil import tracked_files
from dpr.model import Finding, Location, Tag
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule

DATABASE = re.compile(r"(?i)\.(?:sqlite3?|db|bak|bacpac|dump|mdf|ldf)$|\.sql\.gz$")
SPREADSHEET = re.compile(r"(?i)\.(?:xlsx|xlsm|xls|ods|csv)$")
DOCUMENT = re.compile(r"(?i)\.(?:pdf|docx?|odt|pptx?)$")
IMAGE = re.compile(r"(?i)\.(?:png|jpe?g|heic|webp)$")
SCREENSHOT_WORDS = re.compile(r"(?i)uat|screenshot|screen[ _-]?shot|capture|export|report")
RECORD_WORDS = re.compile(
    r"(?i)report|statement|invoice|export|uat|screenshot|screen[ _-]?shot|sample|client|customer"
    r"|producer|patient|member|payroll|backup|dump|test[ _-]?data|record|letter|contract"
)
ASSET_WORDS = re.compile(r"(?i)logo|brand|icon|favicon|style[ _-]?guide|avatar|banner|hero")
SKIPPED_DIRS = re.compile(r"(?:^|/)(?:node_modules|vendor|\.venv|venv|site-packages)/")
EMAIL = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})"
)
RESERVED_TLDS = ("test", "invalid", "localhost", "example", "local", "internal")
PLACEHOLDER_LABELS = frozenset(
    {
        "example",
        "domain",
        "email",
        "company",
        "yourcompany",
        "mycompany",
        "acme",
        "foo",
        "bar",
        "baz",
        "sample",
        "demo",
        "fake",
        "dummy",
        "else",
        "somewhere",
        "website",
        "test",
        "testing",
    }
)
HOSTING_WORDS = re.compile(
    r"(?i)database|postgres|mysql|redis|amazonaws|azure|windows\.net|cloudapp|herokuapp|supabase"
    r"|neon\.tech|render\.com|github|gitlab|sentry|googleusercontent|users\.noreply"
)
TEXT_SUFFIXES = (
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".md",
    ".json",
    ".yaml",
    ".yml",
    ".sql",
    ".txt",
)
CONFIG_FILE = re.compile(
    r"(?i)(?:^|/)(?:config|settings|constants|env)[\w.-]*\.(?:py|ts|js|json)$|\.tf$"
    r"|\.env\.(?:example|sample|template)$|(?:^|/)[\w.-]*\.ya?ml$|(?:^|/)index\.html$"
)
URL_HOST = re.compile(r"https?://([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")


def data_files(ctx: Context) -> list[str]:
    """Tracked files whose contents dpr cannot read and that look like records about people."""
    tracked = tracked_files(ctx.index.root) or []
    readable = {f.rel for f in ctx.index.files}
    found = []
    for rel in tracked:
        if SKIPPED_DIRS.search(rel) or ASSET_WORDS.search(rel):
            continue
        if DATABASE.search(rel) or (SPREADSHEET.search(rel) and rel not in readable):
            found.append(rel)
        elif DOCUMENT.search(rel) and RECORD_WORDS.search(rel):
            found.append(rel)
        elif IMAGE.search(rel) and SCREENSHOT_WORDS.search(rel):
            found.append(rel)
    return found


def registrable(domain: str) -> str:
    return ".".join(domain.lower().split(".")[-2:])


def own_domains(ctx: Context) -> set[str]:
    """Domains the project's own configuration names: its sites, senders and services."""
    domains = set()
    for entry in ctx.index.files:
        if is_test(entry.rel) or "docs/" in entry.rel or not CONFIG_FILE.search(entry.rel):
            continue
        text = ctx.index.text(entry.rel)
        domains |= {registrable(d) for d in EMAIL.findall(text)}
        domains |= {registrable(d) for d in URL_HOST.findall(text)}
    return domains


def real_looking(domain: str, own: set[str]) -> bool:
    labels = domain.lower().split(".")
    if labels[-1] in RESERVED_TLDS or HOSTING_WORDS.search(domain):
        return False
    name = labels[-2]
    return len(name) > 2 and name not in PLACEHOLDER_LABELS and registrable(domain) not in own


def email_sites(ctx: Context) -> list[tuple[str, int, int]]:
    """(file, first line, count) for test and documentation files with real-looking addresses."""
    own = own_domains(ctx)
    sites = []
    for entry in ctx.index.files:
        docs = entry.rel.startswith("docs/") or "/docs/" in entry.rel
        if not (is_test(entry.rel) or docs) or not entry.rel.endswith(TEXT_SUFFIXES):
            continue
        text = ctx.index.text(entry.rel)
        hits = [m for m in EMAIL.finditer(text) if real_looking(m.group(1), own)]
        if hits:
            sites.append((entry.rel, text.count("\n", 0, hits[0].start()) + 1, len(hits)))
    return sites


def _folders(paths: list[str]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for rel in paths:
        grouped.setdefault(str(PurePosixPath(rel).parent), []).append(rel)
    return grouped


@rule("LEAK-COMMITTED-DATA-FILE", review="leaks", severity="medium", exploitability="medium")
def committed_data(ctx: Context) -> Iterator[Finding]:
    files = data_files(ctx)
    if files:
        grouped = _folders(files)
        yield make_finding(
            "LEAK-COMMITTED-DATA-FILE",
            tag=Tag.INFERRED,
            locations=[Location(paths[0], 1) for paths in grouped.values()][:10],
            what=f"{len(files)} document, spreadsheet or database file(s)",
            detail_text=(
                "These tracked files cannot be read by this review and their names suggest records "
                "about people: "
                + "; ".join(f"{folder} ({len(paths)})" for folder, paths in grouped.items())
                + "."
            ),
        )
    sites = email_sites(ctx)
    if sites:
        total = sum(count for _, _, count in sites)
        yield make_finding(
            "LEAK-COMMITTED-DATA-FILE",
            tag=Tag.INFERRED,
            locations=[Location(rel, line) for rel, line, _ in sites][:10],
            what="email addresses in tests and documentation",
            detail_text=(
                f"{total} email addresses in {len(sites)} test or documentation files use domains "
                "that are not reserved for examples (example.com, .test, .invalid) and are not "
                "named by the project's own configuration. The addresses are not printed here."
            ),
        )
