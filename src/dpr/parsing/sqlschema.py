"""Schema state built from SQL migrations (a pasted psql dump is read by `sqldump`)."""

from __future__ import annotations

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
from dpr.parsing.sqlgrants import Grant, parse_grant
from dpr.parsing.sqlobjects import (
    TRUE_WORDS,
    Bucket,
    Column,
    Function,
    Policy,
    TableDef,
    View,
)
from dpr.walk import RepoIndex

MIGRATION_GLOBS = (
    "*migrations/*.sql",
    "*db/*.sql",
    "schema.sql",
    "*/schema.sql",
    "*drizzle/*.sql",
)
DOWN_MARKER = re.compile(
    r"^--\s*(?:migrate:down|\+goose\s+down)\b.*$", re.IGNORECASE | re.MULTILINE
)


def up_section(text: str) -> str:
    """The part of a dbmate or goose migration that runs on up; blanked lines keep numbering."""
    down = DOWN_MARKER.search(text)
    if down is None:
        return text
    kept = text[: down.start()]
    return kept + "\n" * text[down.start() :].count("\n")


CREATE_TABLE = re.compile(
    rf"^create\s+(?:(?:global|local)\s+)?(?:temporary\s+|temp\s+|unlogged\s+)?table\s+"
    rf"(?:if\s+not\s+exists\s+)?({QNAME})\s*(.*)$",
    re.S,
)
ALTER_TABLE = re.compile(
    rf"^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?({QNAME})\s+(.*)$", re.S
)
RLS_ACTION = re.compile(r"^(enable|disable|force|no\s+force)\s+row\s+level\s+security")
CREATE_POLICY = re.compile(rf"^create\s+policy\s+({IDENT})\s+on\s+({QNAME})\s*(.*)$", re.S)
ALTER_POLICY = re.compile(rf"^alter\s+policy\s+({IDENT})\s+on\s+({QNAME})\s*(.*)$", re.S)
DROP_POLICY = re.compile(rf"^drop\s+policy\s+(?:if\s+exists\s+)?({IDENT})\s+on\s+({QNAME})")
CREATE_VIEW = re.compile(
    rf"^create\s+(?:or\s+replace\s+)?(?:(?:temp|temporary)\s+)?(?:recursive\s+)?view\s+"
    rf"({QNAME})\s*(.*)$",
    re.S,
)
ALTER_VIEW = re.compile(rf"^alter\s+view\s+(?:if\s+exists\s+)?({QNAME})\s+set\s*(\(.*\))", re.S)
CREATE_FUNCTION = re.compile(rf"^create\s+(?:or\s+replace\s+)?function\s+({QNAME})\s*(.*)$", re.S)
INSERT_BUCKET = re.compile(
    r"^insert\s+into\s+storage\s*\.\s*buckets\s*\(([^)]*)\)\s*values\s*(.*)$", re.S
)
DROP_OBJECT = re.compile(rf"^drop\s+(table|view|function)\s+(?:if\s+exists\s+)?({QNAME})")
CONSTRAINT_START = re.compile(
    r"^(constraint|primary\s+key|unique|foreign\s+key|check|exclude|like)\b"
)
TABLE_KEY_CONSTRAINT = re.compile(
    rf"^(?:constraint\s+{IDENT}\s+)?(?:primary\s+key|unique)\s*\(([^)]*)\)"
)
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
        re.search(r"\bgenerated\b.*\bidentity\b", rest)
    )
    return Column(_strip_quotes(match.group(1)), col_type, unique, autoinc)


def _policy_clauses(rest: str) -> dict[str, object]:
    out: dict[str, object] = {
        "permissive": True,
        "command": "all",
        "roles": ("public",),
        "roles_explicit": False,
        "using": None,
        "with_check": None,
    }
    match = re.match(r"^as\s+(permissive|restrictive)\s*", rest)
    if match:
        out["permissive"] = match.group(1) == "permissive"
        rest = rest[match.end() :]
    match = re.match(r"^for\s+(all|select|insert|update|delete)\s*", rest)
    if match:
        out["command"] = match.group(1)
        rest = rest[match.end() :]
    match = re.match(r"^to\s+", rest)
    if match:
        starts = (find_top_level(rest, r"using\b"), find_top_level(rest, r"with\s+check\b"))
        ends = [i for i in starts if i != -1]
        end = min(ends) if ends else len(rest)
        roles = [_strip_quotes(r.strip()) for r in split_top_level(rest[match.end() : end])]
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
    grants: list[Grant] = field(default_factory=list)

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
        for handler in (
            self._create_table,
            self._alter_table,
            self._create_policy,
            self._alter_policy,
            self._drop_policy,
            self._create_view,
            self._alter_view,
            self._create_function,
            self._insert_bucket,
            self._drop_object,
            self._grant,
        ):
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
        key, rest = qualify(match.group(1)), match.group(2)
        renamed = re.match(rf"^rename\s+to\s+({IDENT})\s*$", rest)
        if renamed:
            self._rename_table(key, qualify(f"{key.split('.')[0]}.{renamed.group(1)}"))
            return True
        table = self.table(key, loc)
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

    def _rename_table(self, old: str, new: str) -> None:
        table = self.tables.pop(old, None)
        if table is None:
            return
        table.key = new
        self.tables[new] = table
        moved = {}
        for (key, name), policy in self.policies.items():
            if key == old:
                moved[(new, name)] = replace(policy, table=new)
            else:
                moved[(key, name)] = policy
        self.policies = moved

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
            row = dict(
                zip(columns, (v.strip().strip("'") for v in split_top_level(inner)), strict=False)
            )
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

    def _grant(self, s: str, loc: Location) -> bool:
        grant = parse_grant(s, loc)
        if grant is not None:
            self.grants.append(grant)
        return grant is not None


def _invoker(options: str) -> bool:
    match = re.search(r"security_invoker(?:\s*=\s*'?(\w+)'?)?", options)
    return bool(match) and (match.group(1) is None or match.group(1) in TRUE_WORDS)


def load_schema(index: RepoIndex) -> SchemaState:
    state = SchemaState()
    for rel in sorted({f.rel for f in index.glob(*MIGRATION_GLOBS)}):
        state.sources.append(rel)
        for stmt in split_sql(up_section(index.text(rel))):
            state.apply(stmt, rel)
    return state
