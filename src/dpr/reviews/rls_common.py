"""Shared RLS helpers: schema state, owner detection and policy SQL."""

from __future__ import annotations

import copy
import re
from pathlib import Path

from dpr.model import Location
from dpr.parsing.sqlschema import Policy, SchemaState, TableDef, apply_dump
from dpr.rules import Context

OWNER_COLUMNS = ("user_id", "owner_id", "created_by", "author_id", "profile_id")
TENANT_COLUMNS = ("org_id", "organization_id", "tenant_id", "workspace_id", "team_id")
MEMBERSHIP_WORDS = ("member", "membership", "org_users", "team_users")
AUTH_REF = re.compile(r"auth\.uid\s*\(|auth\.jwt\s*\(")
DASHBOARD_QUERIES = """```sql
select schemaname, tablename, rowsecurity
from pg_tables
where schemaname not in ('pg_catalog','information_schema')
order by rowsecurity, tablename;

select schemaname, tablename, policyname, permissive, roles, cmd, qual, with_check
from pg_policies
order by tablename, policyname;
```"""


def owner_column(table: TableDef) -> str | None:
    names = table.column_names()
    return next((c for c in OWNER_COLUMNS if c in names), None)


def tenant_column(table: TableDef) -> str | None:
    names = table.column_names()
    return next((c for c in TENANT_COLUMNS if c in names), None)


def has_owner_or_unknown(table: TableDef) -> bool:
    return not table.columns or bool(owner_column(table) or tenant_column(table))


def membership_table(state: SchemaState, tenant: str) -> str | None:
    for key, table in sorted(state.tables.items()):
        names = table.column_names()
        is_membership = any(w in table.name for w in MEMBERSHIP_WORDS)
        if is_membership and "user_id" in names and tenant in names:
            return key
    return None


def predicate(state: SchemaState, table: TableDef) -> str | None:
    owner = owner_column(table)
    if owner:
        return f"auth.uid() = {owner}"
    tenant = tenant_column(table)
    members = membership_table(state, tenant) if tenant else None
    if tenant and members:
        return f"{tenant} in (select {tenant} from {members} where user_id = auth.uid())"
    return None


def predicate_text(policy: Policy) -> str:
    return " ".join(p for p in (policy.using, policy.with_check) if p)


def qualified(key: str) -> str:
    return ".".join(p if re.fullmatch(r"[a-z_][a-z0-9_]*", p) else f'"{p}"'
                    for p in key.split(".", 1))


def sql_block(sql: str) -> str:
    return f"```sql\n{sql}\n```"


NO_PREDICATE = "-- No owner or tenant column was found. Choose the predicate for this table first."


def policies_sql(state: SchemaState, table: TableDef) -> str:
    name, target = table.name, qualified(table.key)
    lines = [f"alter table {target} enable row level security;"]
    pred = predicate(state, table)
    if pred is None:
        return "\n".join([*lines, NO_PREDICATE])
    return "\n".join([
        *lines, "",
        f'create policy "{name}_select_own" on {target}\n  for select using ({pred});', "",
        f'create policy "{name}_insert_own" on {target}\n  for insert with check ({pred});', "",
        f'create policy "{name}_update_own" on {target}\n'
        f"  for update using ({pred}) with check ({pred});", "",
        f'create policy "{name}_delete_own" on {target}\n  for delete using ({pred});',
    ])


def replacement_sql(state: SchemaState, policy: Policy) -> str:
    target = qualified(policy.table)
    drop = f'drop policy "{policy.name}" on {target};'
    table = state.tables.get(policy.table)
    pred = predicate(state, table) if table else None
    if pred is None:
        return f"{drop}\n{NO_PREDICATE}"
    if policy.command == "insert":
        clause = f"with check ({pred})"
    elif policy.command in ("update", "all"):
        clause = f"using ({pred}) with check ({pred})"
    else:
        clause = f"using ({pred})"
    create = f'create policy "{policy.name}" on {target}'
    return f"{drop}\n{create}\n  for {policy.command} to authenticated {clause};"


def confirm_commands(table_name: str) -> str:
    return (
        "Run this against your own project with your own anon key while signed out. "
        "A pass returns `[]` or a permission error. A fail returns any row you did not create. "
        "dpr never runs this command.\n\n"
        "```bash\n"
        f'curl -s "https://<project>.supabase.co/rest/v1/{table_name}?select=*" \\\n'
        '  -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY"\n'
        "```\n\n"
        "Then sign in as user A and request a row owned by user B with A's access token. "
        "It must return nothing."
    )


def state_for(ctx: Context) -> SchemaState:
    if "rls.state" not in ctx.facts:
        base = ctx.detection.schema if isinstance(ctx.detection.schema, SchemaState) else None
        state = copy.deepcopy(base) if base is not None else SchemaState()
        if ctx.options.db_dump:
            text = Path(ctx.options.db_dump).read_text(encoding="utf-8", errors="replace")
            ctx.not_covered.extend(apply_dump(state, text, ctx.options.db_dump))
        ctx.facts["rls.state"] = state
    return ctx.facts["rls.state"]


def client_facing(ctx: Context) -> bool:
    d = ctx.detection
    return d.public_supabase_key or "supabase" in d.databases or bool(ctx.options.db_dump)


def public_tables(ctx: Context) -> list[TableDef]:
    if not client_facing(ctx):
        return []
    return [t for _, t in sorted(state_for(ctx).tables.items()) if t.schema == "public"]


def table_location(table: TableDef) -> Location:
    return table.rls_location or table.location
