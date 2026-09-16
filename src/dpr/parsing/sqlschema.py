"""Schema state built from SQL migrations or a pasted psql dump."""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field, replace

from dpr.model import Location
from dpr.parsing.sql import (
    IDENT,
    QNAME,
    Statement,
    balanced,
    clean_predicate,
    find_top_level,
    qualify,
    split_sql,
    split_top_level,
)
from dpr.walk import RepoIndex

MIGRATION_GLOBS = ("*migrations/*.sql", "*db/*.sql", "schema.sql", "*/schema.sql")
TRUE_WORDS = ("true", "t", "1", "yes", "on")


@dataclass(frozen=True)
class Column:
    name: str
    type: str
    unique: bool = False
    autoincrement: bool = False


@dataclass
class TableDef:
    key: str
    columns: list[Column]
    location: Location
    rls: bool = False
    rls_location: Location | None = None

    @property
    def schema(self) -> str:
        return self.key.split(".")[0]

    @property
    def name(self) -> str:
        return self.key.split(".", 1)[1]

    def column_names(self) -> list[str]:
        return [c.name for c in self.columns]


@dataclass(frozen=True)
class Policy:
    name: str
    table: str
    command: str
    roles: tuple[str, ...]
    roles_explicit: bool
    using: str | None
    with_check: str | None
    permissive: bool
    location: Location


@dataclass(frozen=True)
class View:
    key: str
    security_invoker: bool
    sources: tuple[str, ...]
    location: Location


@dataclass(frozen=True)
class Function:
    key: str
    security_definer: bool
    sets_search_path: bool
    tables: tuple[str, ...]
    location: Location


@dataclass(frozen=True)
class Bucket:
    id: str
    public: bool
    location: Location


CREATE_TABLE = re.compile(
    rf"^create\s+(?:(?:global|local)\s+)?(?:temporary\s+|temp\s+|unlogged\s+)?table\s+"
    rf"(?:if\s+not\s+exists\s+)?({QNAME})\s*(.*)$", re.S)
ALTER_TABLE = re.compile(
    rf"^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?({QNAME})\s+(.*)$", re.S)
RLS_ACTION = re.compile(r"^(enable|disable|force|no\s+force)\s+row\s+level\s+security")
CREATE_POLICY = re.compile(rf"^create\s+policy\s+({IDENT})\s+on\s+({QNAME})\s*(.*)$", re.S)
ALTER_POLICY = re.compile(rf"^alter\s+policy\s+({IDENT})\s+on\s+({QNAME})\s*(.*)$", re.S)
DROP_POLICY = re.compile(rf"^drop\s+policy\s+(?:if\s+exists\s+)?({IDENT})\s+on\s+({QNAME})")
CREATE_VIEW = re.compile(
    rf"^create\s+(?:or\s+replace\s+)?(?:(?:temp|temporary)\s+)?(?:recursive\s+)?view\s+"
    rf"({QNAME})\s*(.*)$", re.S)
ALTER_VIEW = re.compile(rf"^alter\s+view\s+(?:if\s+exists\s+)?({QNAME})\s+set\s*(\(.*\))", re.S)
CREATE_FUNCTION = re.compile(rf"^create\s+(?:or\s+replace\s+)?function\s+({QNAME})\s*(.*)$", re.S)
INSERT_BUCKET = re.compile(
    r"^insert\s+into\s+storage\s*\.\s*buckets\s*\(([^)]*)\)\s*values\s*(.*)$", re.S)
DROP_OBJECT = re.compile(rf"^drop\s+(table|view|function)\s+(?:if\s+exists\s+)?({QNAME})")
CONSTRAINT_START = re.compile(
    r"^(constraint|primary\s+key|unique|foreign\s+key|check|exclude|like)\b")
TABLE_KEY_CONSTRAINT = re.compile(
    rf"^(?:constraint\s+{IDENT}\s+)?(?:primary\s+key|unique)\s*\(([^)]*)\)")
SOURCE_TABLE = re.compile(rf"\b(?:from|join)\s+({QNAME})")
BODY_TABLE = re.compile(rf"\b(?:from|join|into|update)\s+({QNAME})")


def _strip_quotes(name: str) -> str:
    return name[1:-1] if name.startswith('"') else name


def _column(item: str) -> Column | None:
    if CONSTRAINT_START.match(item):
        return None
    match = re.match(rf"^({IDENT})\s+(.*)$", item, re.S)
    if not match:
        return None
    rest = match.group(2)
    col_type = rest.split(" ")[0]
    unique = bool(re.search(r"\b(unique|primary\s+key)\b", rest))
    autoinc = col_type in ("serial", "bigserial", "smallserial", "serial4", "serial8") or bool(
        re.search(r"\bgenerated\b.*\bidentity\b", rest))
    return Column(_strip_quotes(match.group(1)), col_type, unique, autoinc)


def _policy_clauses(rest: str) -> dict[str, object]:
    out: dict[str, object] = {"permissive": True, "command": "all", "roles": ("public",),
                              "roles_explicit": False, "using": None, "with_check": None}
    match = re.match(r"^as\s+(permissive|restrictive)\s*", rest)
    if match:
        out["permissive"] = match.group(1) == "permissive"
        rest = rest[match.end():]
    match = re.match(r"^for\s+(all|select|insert|update|delete)\s*", rest)
    if match:
        out["command"] = match.group(1)
        rest = rest[match.end():]
    match = re.match(r"^to\s+", rest)
    if match:
        starts = (find_top_level(rest, r"using\b"), find_top_level(rest, r"with\s+check\b"))
        ends = [i for i in starts if i != -1]
        end = min(ends) if ends else len(rest)
        roles = [_strip_quotes(r.strip()) for r in split_top_level(rest[match.end():end])]
        out["roles"] = tuple(r for r in roles if r)
        out["roles_explicit"] = True
        rest = rest[end:]
    for key, keyword in (("using", r"using\s*\("), ("with_check", r"with\s+check\s*\(")):
        start = find_top_level(rest, keyword)
        if start != -1:
            inner, _ = balanced(rest, rest.index("(", start))
            out[key] = clean_predicate(inner)
    return out


@dataclass
class SchemaState:
    tables: dict[str, TableDef] = field(default_factory=dict)
    policies: dict[tuple[str, str], Policy] = field(default_factory=dict)
    views: dict[str, View] = field(default_factory=dict)
    functions: dict[str, Function] = field(default_factory=dict)
    buckets: dict[str, Bucket] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)

    def policies_for(self, table_key: str) -> list[Policy]:
        found = [p for (t, _), p in self.policies.items() if t == table_key]
        return sorted(found, key=lambda p: (p.location.file, p.location.line, p.name))

    def table(self, key: str, loc: Location) -> TableDef:
        if key not in self.tables:
            self.tables[key] = TableDef(key, [], loc)
        return self.tables[key]

    def apply(self, stmt: Statement, file: str) -> None:
        loc = Location(file, stmt.line)
        s = stmt.norm
        for handler in (self._create_table, self._alter_table, self._create_policy,
                        self._alter_policy, self._drop_policy, self._create_view,
                        self._alter_view, self._create_function, self._insert_bucket,
                        self._drop_object):
            if handler(s, loc):
                return

    def _create_table(self, s: str, loc: Location) -> bool:
        match = CREATE_TABLE.match(s)
        if not match:
            return False
        key = qualify(match.group(1))
        if key in self.tables:
            return True
        columns: list[Column] = []
        keyed: set[str] = set()
        rest = match.group(2)
        if rest.startswith("("):
            body, _ = balanced(rest, 0)
            for item in split_top_level(body):
                constraint = TABLE_KEY_CONSTRAINT.match(item)
                if constraint:
                    keyed.update(_strip_quotes(c.strip()) for c in constraint.group(1).split(","))
                column = _column(item)
                if column:
                    columns.append(column)
        columns = [replace(c, unique=True) if c.name in keyed else c for c in columns]
        self.tables[key] = TableDef(key, columns, loc)
        return True

    def _alter_table(self, s: str, loc: Location) -> bool:
        match = ALTER_TABLE.match(s)
        if not match:
            return False
        table = self.table(qualify(match.group(1)), loc)
        rest = match.group(2)
        action = RLS_ACTION.match(rest)
        if action:
            if action.group(1) in ("enable", "disable"):
                table.rls = action.group(1) == "enable"
                table.rls_location = loc
            return True
        for item in split_top_level(rest):
            added = re.match(r"^add\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?(.*)$", item, re.S)
            column = _column(added.group(1)) if added else None
            if column and column.name not in table.column_names():
                table.columns.append(column)
        return True

    def _create_policy(self, s: str, loc: Location) -> bool:
        match = CREATE_POLICY.match(s)
        if not match:
            return False
        name, table = _strip_quotes(match.group(1)), qualify(match.group(2))
        clauses = _policy_clauses(match.group(3))
        self.policies[(table, name)] = Policy(name=name, table=table, location=loc, **clauses)
        return True

    def _alter_policy(self, s: str, loc: Location) -> bool:
        match = ALTER_POLICY.match(s)
        if not match:
            return False
        name, table = _strip_quotes(match.group(1)), qualify(match.group(2))
        current = self.policies.get((table, name))
        rest = match.group(3)
        rename = re.match(rf"^rename\s+to\s+({IDENT})", rest)
        if current is None:
            return True
        if rename:
            del self.policies[(table, name)]
            new_name = _strip_quotes(rename.group(1))
            self.policies[(table, new_name)] = replace(current, name=new_name)
            return True
        clauses = _policy_clauses(rest)
        updated = current
        if clauses["roles_explicit"]:
            updated = replace(updated, roles=clauses["roles"], roles_explicit=True)
        if clauses["using"] is not None:
            updated = replace(updated, using=clauses["using"])
        if clauses["with_check"] is not None:
            updated = replace(updated, with_check=clauses["with_check"])
        self.policies[(table, name)] = updated
        return True

    def _drop_policy(self, s: str, loc: Location) -> bool:
        match = DROP_POLICY.match(s)
        if not match:
            return False
        self.policies.pop((qualify(match.group(2)), _strip_quotes(match.group(1))), None)
        return True

    def _create_view(self, s: str, loc: Location) -> bool:
        match = CREATE_VIEW.match(s)
        if not match:
            return False
        rest = match.group(2)
        if rest.startswith("("):
            _, end = balanced(rest, 0)
            rest = rest[end:].lstrip()
        invoker = False
        if rest.startswith("with"):
            options, end = balanced(rest, rest.index("("))
            invoker = _invoker(options)
            rest = rest[end:]
        sources = tuple(sorted({qualify(t) for t in SOURCE_TABLE.findall(rest)}))
        key = qualify(match.group(1))
        self.views[key] = View(key, invoker, sources, loc)
        return True

    def _alter_view(self, s: str, loc: Location) -> bool:
        match = ALTER_VIEW.match(s)
        if not match:
            return False
        key = qualify(match.group(1))
        if key in self.views:
            options, _ = balanced(match.group(2), 0)
            if "security_invoker" in options:
                self.views[key] = replace(self.views[key], security_invoker=_invoker(options))
        return True

    def _create_function(self, s: str, loc: Location) -> bool:
        match = CREATE_FUNCTION.match(s)
        if not match:
            return False
        rest = match.group(2)
        body = re.search(r"(\$[a-z0-9_]*\$)(.*?)\1", rest, re.S)
        inside = body.group(2) if body else rest
        outside = rest.replace(body.group(0), " ") if body else rest
        key = qualify(match.group(1))
        self.functions[key] = Function(
            key=key,
            security_definer=bool(re.search(r"\bsecurity\s+definer\b", outside)),
            sets_search_path=bool(re.search(r"\bset\s+search_path\b", outside)),
            tables=tuple(sorted({qualify(t) for t in BODY_TABLE.findall(inside)})),
            location=loc,
        )
        return True

    def _insert_bucket(self, s: str, loc: Location) -> bool:
        match = INSERT_BUCKET.match(s)
        if not match:
            return False
        columns = [_strip_quotes(c.strip()) for c in match.group(1).split(",")]
        rest = match.group(2).lstrip()
        while rest.startswith("("):
            inner, end = balanced(rest, 0)
            row = dict(zip(columns, (v.strip().strip("'") for v in split_top_level(inner)),
                           strict=False))
            if row.get("id"):
                public = row.get("public", "false").lower() in TRUE_WORDS
                self.buckets[row["id"]] = Bucket(row["id"], public, loc)
            rest = rest[end:].lstrip().lstrip(",").lstrip()
        return True

    def _drop_object(self, s: str, loc: Location) -> bool:
        match = DROP_OBJECT.match(s)
        if not match:
            return False
        kind, key = match.group(1), qualify(match.group(2))
        if kind == "table":
            self.tables.pop(key, None)
            self.policies = {k: v for k, v in self.policies.items() if k[0] != key}
        elif kind == "view":
            self.views.pop(key, None)
        else:
            self.functions.pop(key, None)
        return True


def _invoker(options: str) -> bool:
    match = re.search(r"security_invoker(?:\s*=\s*'?(\w+)'?)?", options)
    return bool(match) and (match.group(1) is None or match.group(1) in TRUE_WORDS)


def load_schema(index: RepoIndex) -> SchemaState:
    state = SchemaState()
    for rel in sorted({f.rel for f in index.glob(*MIGRATION_GLOBS)}):
        state.sources.append(rel)
        for stmt in split_sql(index.text(rel)):
            state.apply(stmt, rel)
    return state


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
            name=row["policyname"], table=key, command=row.get("cmd", "ALL").lower(),
            roles=roles or ("public",), roles_explicit=bool(roles) and roles != ("public",),
            using=clean_predicate(qual) if qual else None,
            with_check=clean_predicate(check) if check else None,
            permissive=row.get("permissive", "PERMISSIVE").upper() == "PERMISSIVE",
            location=loc,
        )
    return problems
