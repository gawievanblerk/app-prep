"""Review 2, database lock check: tables, views, functions, buckets and the section."""

from __future__ import annotations

import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Part, ReviewSection, Tag
from dpr.parsing import jsts
from dpr.parsing.sqlschema import TableDef
from dpr.reviews.rls_common import (
    DASHBOARD_QUERIES,
    client_facing,
    confirm_commands,
    policies_sql,
    public_tables,
    qualified,
    sql_block,
    state_for,
    table_location,
)
from dpr.rules import Context, make_finding, rule
from dpr.walk import line_of

SUPABASE_FROM = re.compile(r"\.from\(\s*['\"`](\w+)['\"`]\s*\)")
CONFIRM_IN_DATABASE = (
    "Run these queries in the database SQL editor and compare the result with the table "
    "above. Save the output to a file and pass it with `--db-dump` to make it the source "
    "of truth.\n\n"
)
SERVER_ONLY = (
    "No public database key or Supabase client was found. The database appears to be "
    "reachable only from the server, so row level security matters less here. "
    "No RLS findings are reported."
)


def _rls_tables(ctx: Context) -> set[str]:
    return {key for key, table in state_for(ctx).tables.items() if table.rls}


@rule("RLS-TABLE-OFF", review="rls", severity="critical", exploitability="high")
def table_off(ctx: Context) -> Iterator[Finding]:
    state = state_for(ctx)
    exposed = ctx.detection.public_supabase_key
    reach = ("A public Supabase key is configured, so anyone holding it can read the table."
             if exposed else "No public key was found, which reduces how reachable it is.")
    for table in public_tables(ctx):
        if not table.rls:
            yield make_finding(
                "RLS-TABLE-OFF", tag=Tag.CONFIRMED, locations=[table_location(table)],
                severity="critical" if exposed else "high",
                fix=sql_block(policies_sql(state, table)), verify=confirm_commands(table.name),
                table=table.key, reach=reach)


@rule("RLS-NO-POLICIES", review="rls", severity="low", exploitability="low")
def no_policies(ctx: Context) -> Iterator[Finding]:
    state = state_for(ctx)
    for table in public_tables(ctx):
        if table.rls and not state.policies_for(table.key):
            yield make_finding("RLS-NO-POLICIES", tag=Tag.CONFIRMED,
                               locations=[table_location(table)],
                               fix=sql_block(policies_sql(state, table)), table=table.key)


@rule("RLS-SELECT-ONLY", review="rls", severity="low", exploitability="low")
def select_only(ctx: Context) -> Iterator[Finding]:
    state = state_for(ctx)
    for table in public_tables(ctx):
        policies = state.policies_for(table.key)
        if table.rls and policies and all(p.command == "select" for p in policies):
            yield make_finding("RLS-SELECT-ONLY", tag=Tag.CONFIRMED,
                               locations=[policies[0].location], table=table.key)


@rule("RLS-VIEW-BYPASS", review="rls", severity="high", exploitability="high")
def view_bypass(ctx: Context) -> Iterator[Finding]:
    if not client_facing(ctx):
        return
    protected_tables = _rls_tables(ctx)
    for key, view in sorted(state_for(ctx).views.items()):
        protected = [s for s in view.sources if s in protected_tables]
        if key.startswith("public.") and not view.security_invoker and protected:
            fix = sql_block(f"alter view {qualified(key)} set (security_invoker = true);")
            yield make_finding("RLS-VIEW-BYPASS", tag=Tag.CONFIRMED, locations=[view.location],
                               fix=fix, view=key, tables=", ".join(protected))


@rule("RLS-DEFINER-FUNCTION", review="rls", severity="medium", exploitability="medium")
def definer_function(ctx: Context) -> Iterator[Finding]:
    if not client_facing(ctx):
        return
    protected_tables = _rls_tables(ctx)
    for key, fn in sorted(state_for(ctx).functions.items()):
        if not key.startswith("public.") or not fn.security_definer:
            continue
        protected = [t for t in fn.tables if t in protected_tables]
        what = "It runs with the owner's rights and can be called from the client."
        if protected:
            what += f" It reads {', '.join(protected)}, which have row level security."
        if not fn.sets_search_path:
            what += " It does not set search_path."
        yield make_finding("RLS-DEFINER-FUNCTION", tag=Tag.CONFIRMED, locations=[fn.location],
                           severity="high" if protected else "medium", function=key, what=what)


@rule("RLS-PUBLIC-BUCKET", review="rls", severity="medium", exploitability="medium")
def public_bucket(ctx: Context) -> Iterator[Finding]:
    for bucket in sorted(state_for(ctx).buckets.values(), key=lambda b: b.id):
        if bucket.public:
            yield make_finding("RLS-PUBLIC-BUCKET", tag=Tag.CONFIRMED,
                               locations=[bucket.location], bucket=bucket.id)
    for entry in ctx.index.js_files:
        if "createBucket" not in ctx.index.text(entry.rel):
            continue
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for call in jsts.calls(tree, r"(?:\w+\.)*createBucket"):
                args = jsts.arguments(call)
                public = jsts.object_pairs(args[1]).get("public") if len(args) > 1 else None
                if public is not None and jsts.node_text(public) == "true":
                    yield make_finding(
                        "RLS-PUBLIC-BUCKET", tag=Tag.CONFIRMED,
                        locations=[Location(entry.rel, jsts.line(tree, call))],
                        bucket=jsts.string_value(args[0]) or "(dynamic name)")


def _breakage(ctx: Context, tables: list[TableDef]) -> list[Location]:
    names = {t.name for t in tables}
    found = []
    for entry in ctx.index.js_files:
        text = ctx.index.text(entry.rel)
        for match in SUPABASE_FROM.finditer(text):
            if match.group(1) in names:
                found.append(Location(entry.rel, line_of(text, match.start())))
    return found


def _status_row(ctx: Context, table: TableDef) -> tuple[str, ...]:
    count = len(state_for(ctx).policies_for(table.key))
    if not table.rls:
        reach = ("yes, every row" if ctx.detection.public_supabase_key
                 else "yes, if a public key reaches the browser")
        verdict = "exposed"
    elif count == 0:
        reach, verdict = "no, all client access denied", "locked, probably read with a service key"
    else:
        reach, verdict = "only rows the policies allow", "check policy defects"
    return (table.key, "yes" if table.rls else "no", str(count), reach, verdict,
            str(table_location(table)))


def run(ctx: Context) -> ReviewSection | None:
    state = state_for(ctx)
    if not state.tables and not client_facing(ctx):
        ctx.not_covered.append(
            "Review 2 (rls): not applicable, no SQL tables, Supabase client or database dump found")
        return None
    if not client_facing(ctx):
        return ReviewSection("rls", [Part("text", "Relevance", body=SERVER_ONLY)])
    tables = public_tables(ctx)
    parts = [
        Part("table", "Table protection status",
             columns=("Table", "RLS enabled", "Policies", "Reachable by anon key", "Verdict",
                      "Evidence"),
             rows=tuple(_status_row(ctx, t) for t in tables)),
        Part("findings", "Policy defects"),
    ]
    gaps = [t for t in tables if not t.rls or not state.policies_for(t.key)]
    if gaps:
        body = "\n\n".join(sql_block(policies_sql(state, t)) for t in gaps)
        breakage = _breakage(ctx, gaps)
        if breakage:
            body += ("\n\nAdding these policies can make these queries return nothing for rows "
                     "the caller does not own:\n" + "\n".join(f"- `{loc}`" for loc in breakage))
        parts.append(Part("text", "Missing policies (runnable SQL)", body=body))
    example = gaps[0].name if gaps else (tables[0].name if tables else "<table>")
    confirm = confirm_commands(example)
    parts.append(Part("text", "How to confirm from outside the app", body=confirm))
    database = CONFIRM_IN_DATABASE + DASHBOARD_QUERIES
    parts.append(Part("text", "Confirm in the database", body=database))
    return ReviewSection("rls", parts)
