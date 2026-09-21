"""Review 2 at reduced relevance: the database is reached only by the server."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from dpr.discovery.approots import root_of, same_root
from dpr.model import Location, Part, ReviewSection
from dpr.parsing import hcl
from dpr.parsing.pymigrations import migration_folders, python_migration_state
from dpr.reviews.baseline_accounts import START_FILES
from dpr.reviews.rls_common import state_for
from dpr.rules import Context
from dpr.walk import line_of

RELEVANCE = (
    "Reduced relevance. No public database key and no Supabase, PostgREST or Firebase client was "
    "found, so the browser cannot query tables directly and the attack this review is built "
    "around (a stranger reading tables with the public key) does not apply. What remains is "
    "defence in depth inside the database and the database's own network exposure. No row "
    "level security findings are reported."
)
EXPOSURE_RULES = ("BASE-DB-NETWORK-OPEN", "BASE-DB-ADMIN-LOGIN")
NO_EXPOSURE = "No database firewall, public access or admin connection string finding was reported."
POSTGRES_SQL = """```sql
-- Run as the database owner, once per database. Adapt the names.
create role app_runtime login password '<from your secret store>';
grant connect on database <database> to app_runtime;
grant usage on schema public to app_runtime;
grant select, insert, update, delete on all tables in schema public to app_runtime;
grant usage, select on all sequences in schema public to app_runtime;
alter default privileges in schema public
  grant select, insert, update, delete on tables to app_runtime;
alter default privileges in schema public grant usage, select on sequences to app_runtime;
revoke create on schema public from public;
-- Keep the owner login for migrations only.
-- Then point the app's connection string at app_runtime.
```"""
MYSQL_SQL = """```sql
-- Run as an administrator. Adapt the names.
create user 'app_runtime'@'%' identified by '<from your secret store>';
grant select, insert, update, delete on <database>.* to 'app_runtime'@'%';
-- Keep the administrator login for migrations only, then point the app at app_runtime.
```"""
LEAST_PRIVILEGE = (
    "Row level security is not the first control to add when the server is the only client. "
    "The highest-value database change is a least-privilege login for the running app, so a "
    "SQL injection or leaked connection string does not carry owner rights and DDL."
)
POSTGRES_CONFIRM = """```sql
select schemaname, tablename, rowsecurity from pg_tables
where schemaname not in ('pg_catalog','information_schema') order by rowsecurity, tablename;

select current_user;  -- run through the app's own connection string
select rolname, rolsuper, rolcreaterole, rolcreatedb from pg_roles where rolcanlogin;
```
"""
POSTGRES_PASS = (
    "Pass: the app's `current_user` is not the owner or an administrator, and has no create "
    "rights. Fail: `current_user` is the owner or administrator login."
)
CLOUD_COMMANDS = {
    "azurerm_postgresql_flexible_server": (
        "az postgres flexible-server firewall-rule list -g <resource-group> -n <server> -o table"
    ),
    "azurerm_mysql_flexible_server": (
        "az mysql flexible-server firewall-rule list -g <resource-group> -n <server> -o table"
    ),
    "aws_db_instance": (
        "aws rds describe-db-instances "
        '--query "DBInstances[].[DBInstanceIdentifier,PubliclyAccessible]"'
    ),
    "google_sql_database_instance": (
        'gcloud sql instances describe <instance> --format="value(settings.ipConfiguration)"'
    ),
}
MIGRATE_AT_START = re.compile(
    r"alembic\s+upgrade|manage\.py\s+migrate|prisma\s+migrate\s+deploy|drizzle-kit\s+(?:migrate|push)"
    r"|knex\s+migrate|sequelize\s+db:migrate"
)


def _engine(ctx: Context) -> str:
    databases = set(ctx.detection.databases)
    prisma = " ".join(ctx.index.text(f.rel) for f in ctx.index.glob("*.prisma"))
    if "postgres" in databases or 'provider = "postgresql"' in prisma:
        return "postgres"
    if "mysql" in databases or 'provider = "mysql"' in prisma:
        return "mysql"
    return "other"


def _status_rows(ctx: Context) -> tuple[tuple[str, ...], ...]:
    scanned = python_migration_state(ctx.index)
    sql = state_for(ctx)
    folders = migration_folders(ctx.index)
    groups: dict[tuple[str, bool], list[tuple[str, Location]]] = {}
    seen = set()
    tables = [(m.table.split(".")[-1], m.location) for m in ctx.detection.models]
    tables += [(t.name, t.location) for t in sql.tables.values()]
    for name, location in tables:
        home = root_of(ctx.detection.app_roots, location.file)
        root = home.path if home is not None else ""
        if (root, name) in seen:
            continue
        seen.add((root, name))
        key = f"public.{name}"
        rls = any(s.tables.get(key) is not None and s.tables[key].rls for s in (scanned, sql))
        groups.setdefault((root, rls), []).append((name, location))
    rows = []
    for (root, rls), items in sorted(groups.items()):
        names = ", ".join(sorted({n for n, _ in items}))
        label = f"{root or 'repository root'}: {names}"
        policies = sum(len(s.policies_for(f"public.{n}")) for n, _ in items for s in (scanned, sql))
        where = sorted({str(PurePosixPath(loc.file).parent) for _, loc in items})
        local = [f for f, _ in folders if same_root(ctx.detection.app_roots, f, items[0][1].file)]
        statements = (
            "RLS or policy statements found" if rls or policies else "no RLS or policy statements"
        )
        places = ", ".join(local) or "any migration"
        evidence = f"models in {', '.join(where[:3])}; {statements} in {places}"
        verdict = (
            "row level security on; enforced for every database login without BYPASSRLS"
            if rls
            else "protected only by application code and database credentials"
        )
        rows.append(
            (
                label,
                "yes" if rls else "no",
                str(policies),
                "no, no client-side key",
                verdict,
                evidence,
            )
        )
    return tuple(rows)


def _grants_text(ctx: Context) -> str:
    grants = [*state_for(ctx).grants, *python_migration_state(ctx.index).grants]
    if not grants:
        return "No GRANT or REVOKE statements were found in migrations."
    lines = [
        f"- `{g.location}`: {g.action} {', '.join(g.privileges)} on {g.kind} "
        f"{', '.join(g.objects)} {'to' if g.action == 'grant' else 'from'} {', '.join(g.roles)}"
        for g in grants[:10]
    ]
    return "Grants and revokes found in migrations:\n\n" + "\n".join(lines)


def _migrations_at_start(ctx: Context) -> list[Location]:
    found = []
    for entry in ctx.index.named(*START_FILES):
        text = ctx.index.text(entry.rel)
        found += [
            Location(entry.rel, line_of(text, m.start())) for m in MIGRATE_AT_START.finditer(text)
        ]
    return found


def _cloud_commands(ctx: Context) -> list[str]:
    kinds = set()
    for entry in ctx.index.with_suffix(".tf"):
        for block in hcl.blocks(ctx.index.text(entry.rel)):
            if block.kind == "resource" and block.labels and block.labels[0] in CLOUD_COMMANDS:
                kinds.add(block.labels[0])
    return [CLOUD_COMMANDS[k] for k in sorted(kinds)]


def reduced_section(ctx: Context) -> ReviewSection:
    engine = _engine(ctx)
    sql = {"postgres": POSTGRES_SQL, "mysql": MYSQL_SQL}.get(
        engine, "No SQL is given because the database engine was not recognised."
    )
    body = f"{LEAST_PRIVILEGE}\n\n{sql}\n\n{_grants_text(ctx)}"
    starts = _migrations_at_start(ctx)
    if starts:
        body += (
            "\n\nThese start commands run migrations with the app's own credentials, which "
            "breaks once the runtime login loses DDL rights. Move migrations to a deploy step "
            "first: " + ", ".join(f"`{loc}`" for loc in starts[:5]) + "."
        )
    confirm = (
        POSTGRES_CONFIRM + "\n" + POSTGRES_PASS
        if engine == "postgres"
        else "Ask the database which login the app connects as and confirm it is not an "
        "administrator."
    )
    commands = _cloud_commands(ctx)
    if commands:
        confirm += (
            "\n\nNetwork exposure, run by the owner:\n\n```bash\n" + "\n".join(commands) + "\n```"
        )
    defects = (
        "No database policies are defined, so none can be defective. Access control is enforced "
        "in application code; review 5 lists routes that load records without an owner check."
    )
    return ReviewSection(
        "rls",
        [
            Part("text", "Relevance", body=RELEVANCE),
            Part(
                "table",
                "Table protection status",
                (
                    "Table(s)",
                    "RLS enabled",
                    "Policy count",
                    "Reachable by anon key",
                    "Verdict",
                    "Evidence",
                ),
                _status_rows(ctx),
            ),
            Part("text", "Policy defects", body=defects),
            Part(
                "refs", "Database exposure and privilege", columns=EXPOSURE_RULES, body=NO_EXPOSURE
            ),
            Part("text", "Missing policies (runnable SQL)", body=body),
            Part("text", "How to confirm from outside the app", body=confirm),
        ],
    )
