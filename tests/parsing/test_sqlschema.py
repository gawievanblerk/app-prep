from dpr.parsing.sql import split_sql
from dpr.parsing.sqlschema import SchemaState, apply_dump, load_schema
from dpr.walk import RepoIndex

MIGRATION = """
create table public.profiles (
  id uuid primary key,
  user_id uuid not null references auth.users,
  email text,
  constraint profiles_email_key unique (email)
);
create table if not exists invoices (id bigserial primary key, org_id uuid, amount int);
alter table public.profiles enable row level security;
create policy "profiles_update" on public.profiles as permissive for update to authenticated
  using ((select auth.uid()) = user_id) with check (true);
create policy read_all on profiles for select using (true);
alter policy read_all on public.profiles to anon, authenticated;
create policy temp on profiles for delete using (false);
drop policy if exists temp on public.profiles;
alter table invoices add column user_id uuid, add column note text;
create view public.invoice_list as select i.id from public.invoices i join profiles p on true;
create view public.safe_list with (security_invoker = true) as select id from invoices;
alter view public.invoice_list set (security_invoker = on);
create or replace function public.all_docs() returns setof documents language sql
  security definer as $$ select * from public.documents $$;
create function public.ok() returns int language sql security definer set search_path = ''
  as $fn$ select count(*) from invoices $fn$;
insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true), ('private', 'private', false);
create table public.tmp (id int);
drop table public.tmp;
"""


def state():
    s = SchemaState()
    for stmt in split_sql(MIGRATION):
        s.apply(stmt, "m.sql")
    return s


def test_tables_columns_and_rls():
    s = state()
    assert sorted(s.tables) == ["public.invoices", "public.profiles"]
    profiles = s.tables["public.profiles"]
    assert profiles.column_names() == ["id", "user_id", "email"]
    assert [c.unique for c in profiles.columns] == [True, False, True]
    assert profiles.rls is True and profiles.rls_location.line == 9
    invoices = s.tables["public.invoices"]
    assert invoices.column_names() == ["id", "org_id", "amount", "user_id", "note"]
    assert invoices.columns[0].autoincrement is True
    assert invoices.rls is False
    assert profiles.location.line == 2


def test_policies():
    s = state()
    policies = {p.name: p for p in s.policies_for("public.profiles")}
    assert sorted(policies) == ["profiles_update", "read_all"]
    update = policies["profiles_update"]
    assert (update.command, update.roles, update.roles_explicit) == ("update", ("authenticated",), True)
    assert update.using == "(select auth.uid()) = user_id"
    assert update.with_check == "true"
    assert update.location.line == 10
    read_all = policies["read_all"]
    assert (read_all.command, read_all.using, read_all.with_check) == ("select", "true", None)
    assert read_all.roles == ("anon", "authenticated")


def test_views_functions_buckets():
    s = state()
    assert s.views["public.invoice_list"].security_invoker is True
    assert s.views["public.invoice_list"].sources == ("public.invoices", "public.profiles")
    assert s.views["public.safe_list"].security_invoker is True
    all_docs = s.functions["public.all_docs"]
    assert (all_docs.security_definer, all_docs.sets_search_path) == (True, False)
    assert all_docs.tables == ("public.documents",)
    assert s.functions["public.ok"].sets_search_path is True
    assert {b.id: b.public for b in s.buckets.values()} == {"avatars": True, "private": False}


def test_load_schema_applies_files_in_path_order(tmp_path):
    mig = tmp_path / "supabase" / "migrations"
    mig.mkdir(parents=True)
    (mig / "002_rls.sql").write_text("alter table docs enable row level security;")
    (mig / "001_init.sql").write_text("create table docs (id int, user_id uuid);")
    (tmp_path / "app.ts").write_text("x")
    s = load_schema(RepoIndex(tmp_path))
    assert s.sources == ["supabase/migrations/001_init.sql", "supabase/migrations/002_rls.sql"]
    assert s.tables["public.docs"].rls is True
    assert s.tables["public.docs"].location.file == "supabase/migrations/001_init.sql"


ALIGNED = """
 schemaname | tablename | rowsecurity
------------+-----------+-------------
 public     | profiles  | f
 public     | invoices  | t
(2 rows)

 schemaname | tablename | policyname | permissive | roles | cmd | qual | with_check
------------+-----------+------------+------------+-------+-----+------+------------
 public | invoices | inv_read | PERMISSIVE | {authenticated} | SELECT | (auth.role() = 'authenticated'::text) |
(1 row)
"""

CSV = """schemaname,tablename,policyname,permissive,roles,cmd,qual,with_check
public,profiles,p_all,PERMISSIVE,{public},ALL,(auth.uid() = user_id),
"""


def test_apply_dump_aligned_overrides_migrations():
    s = state()
    problems = apply_dump(s, ALIGNED, "dump.txt")
    assert problems == []
    assert s.tables["public.profiles"].rls is False
    assert s.tables["public.profiles"].rls_location.file == "dump.txt"
    assert s.tables["public.invoices"].rls is True
    [policy] = s.policies_for("public.invoices")
    assert policy.using == "auth.role() = 'authenticated'::text"
    assert policy.with_check is None
    assert policy.location.line == 10


def test_apply_dump_csv_replaces_table_policies():
    s = state()
    apply_dump(s, CSV, "dump.csv")
    [policy] = s.policies_for("public.profiles")
    assert (policy.name, policy.command, policy.roles_explicit) == ("p_all", "all", False)
    assert policy.using == "auth.uid() = user_id"


def test_apply_dump_reports_bad_rows():
    problems = apply_dump(SchemaState(), " schemaname | tablename | rowsecurity\n public | x\n", "d")
    assert problems == ["d:2: row skipped, unexpected column count"]
