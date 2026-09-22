"""Database migrations written in Python (Alembic, Django) and migration folders of any tool."""

from __future__ import annotations

import ast
import re
from dataclasses import replace
from pathlib import PurePosixPath

from dpr.parsing import pyast
from dpr.parsing.sql import split_sql
from dpr.parsing.sqlschema import SchemaState
from dpr.walk import RepoIndex

SQL_CALL = r"(?:\w+\.)*(?:execute|RunSQL|run_sql)"
TEXT_CALL = ("text", "sa.text", "sqlalchemy.text")
FOLDER_SIGNS = (
    (re.compile(r"(?:^|/)alembic/versions/[^/]+\.py$"), "alembic"),
    (re.compile(r"(?:^|/)migrations/\d{4}_[^/]+\.py$"), "django"),
    (re.compile(r"(?:^|/)prisma/migrations/[^/]+/migration\.sql$"), "prisma"),
    (re.compile(r"(?:^|/)drizzle/[^/]+\.sql$"), "drizzle"),
    (re.compile(r"(?:^|/)supabase/migrations/[^/]+\.sql$"), "supabase"),
    (re.compile(r"(?:^|/)migrations/[^/]+\.sql$"), "sql"),
)


def migration_folders(index: RepoIndex) -> list[tuple[str, str]]:
    """(folder, tool) for every folder that holds migration files."""
    found: dict[str, str] = {}
    for entry in index.files:
        for pattern, tool in FOLDER_SIGNS:
            if pattern.search(entry.rel):
                folder = str(PurePosixPath(entry.rel).parent)
                if tool == "prisma":
                    folder = str(PurePosixPath(folder).parent)
                found.setdefault(folder, tool)
                break
    return sorted(found.items())


def _sql_text(node: ast.AST | None) -> str | None:
    value = pyast.constant(node, None)
    if isinstance(value, str):
        return value
    if isinstance(node, ast.Call) and pyast.dotted(node.func) in TEXT_CALL and node.args:
        return _sql_text(node.args[0])
    return None


def python_migration_state(index: RepoIndex) -> SchemaState:
    """RLS, policy and grant statements run from Python migrations, applied in path order."""
    state = SchemaState()
    python_folders = {f for f, tool in migration_folders(index) if tool in ("alembic", "django")}
    for entry in sorted(index.py_files, key=lambda f: f.rel):
        if str(PurePosixPath(entry.rel).parent) not in python_folders:
            continue
        tree = pyast.parse_file(index, entry.rel)
        for call in pyast.calls(tree, SQL_CALL) if tree else []:
            sql = _sql_text(call.args[0] if call.args else pyast.kwarg(call, "sql"))
            if not sql:
                continue
            state.sources.append(entry.rel)
            for stmt in split_sql(sql):
                state.apply(replace(stmt, line=call.lineno), entry.rel)
    return state
