"""Schema state from a pasted psql dump of pg_tables and pg_policies (aligned or CSV output)."""

from __future__ import annotations

import csv
import re

from dpr.model import Location
from dpr.parsing.sql import clean_predicate, qualify
from dpr.parsing.sqlobjects import TRUE_WORDS, Policy
from dpr.parsing.sqlschema import SchemaState


def _dump_rows(text: str) -> list[tuple[int, dict[str, str]]]:
    """Rows from psql aligned or CSV output, each with its 1-based line number."""
    rows: list[tuple[int, dict[str, str]]] = []
    header: list[str] | None = None
    delimiter = "|"
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or re.fullmatch(r"[-+]+", line) or re.fullmatch(r"\(\d+ rows?\)", line):
            if not line:
                header = None
            continue
        if "tablename" in line and ("rowsecurity" in line or "policyname" in line):
            delimiter = "|" if "|" in line else ","
            header = [h.strip() for h in line.split(delimiter)]
            continue
        if header is None:
            continue
        cells = next(csv.reader([line])) if delimiter == "," else line.split("|")
        cells = [c.strip() for c in cells]
        if len(cells) != len(header):
            rows.append((number, {}))
            continue
        rows.append((number, dict(zip(header, cells, strict=True))))
    return rows


def apply_dump(state: SchemaState, text: str, file: str) -> list[str]:
    problems: list[str] = []
    replaced: set[str] = set()
    for number, row in _dump_rows(text):
        loc = Location(file, number)
        if not row or not row.get("tablename"):
            problems.append(f"{file}:{number}: row skipped, unexpected column count")
            continue
        key = qualify(f'"{row.get("schemaname") or "public"}"."{row["tablename"]}"')
        if "rowsecurity" in row:
            table = state.table(key, loc)
            table.rls = row["rowsecurity"].lower() in TRUE_WORDS
            table.rls_location = loc
            continue
        if key not in replaced:
            state.policies = {k: v for k, v in state.policies.items() if k[0] != key}
            replaced.add(key)
        roles = tuple(r.strip() for r in row.get("roles", "").strip("{}").split(",") if r.strip())
        qual = re.sub(r"\s+", " ", row.get("qual", "")).strip().lower()
        check = re.sub(r"\s+", " ", row.get("with_check", "")).strip().lower()
        state.policies[(key, row["policyname"])] = Policy(
            name=row["policyname"],
            table=key,
            command=row.get("cmd", "ALL").lower(),
            roles=roles or ("public",),
            roles_explicit=bool(roles) and roles != ("public",),
            using=clean_predicate(qual) if qual else None,
            with_check=clean_predicate(check) if check else None,
            permissive=row.get("permissive", "PERMISSIVE").upper() == "PERMISSIVE",
            location=loc,
        )
    return problems
