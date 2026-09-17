from tests.reviews.helpers import findings_for, write

MIG = """create table public.profiles (id uuid primary key, user_id uuid not null, full_name text);
alter table public.profiles enable row level security;
create policy "profiles_update" on public.profiles for update using (auth.uid() = user_id) with check (true);
create policy "profiles_admin" on public.profiles for select using (auth.jwt() -> 'user_metadata' ->> 'role' = 'admin');
create policy "profiles_select_own" on public.profiles for select using (auth.uid() = user_id);
create table public.documents (id bigserial primary key, user_id uuid not null, body text);
alter table public.documents enable row level security;
create policy "documents_read" on public.documents for select using (true);
create policy "docs_auth" on public.documents for select to authenticated using (auth.role() = 'authenticated');
create policy "documents_delete" on public.documents for delete to anon using (body is not null);
create policy "documents_insert" on public.documents for insert with check (true);
create policy "documents_update_own" on public.documents for update using (auth.uid() = user_id) with check (true);
create table public.projects (id uuid primary key, org_id uuid not null, name text);
alter table public.projects enable row level security;
create policy "projects_read" on public.projects for select to authenticated using (exists (select 1 from public.members where members.user_id = auth.uid()));
create policy "projects_scoped" on public.projects for select to authenticated using (org_id in (select org_id from public.members where user_id = auth.uid()));
create table public.members (org_id uuid, user_id uuid);
create table public.posts (id int, published boolean);
alter table public.posts enable row level security;
create policy posts_read on public.posts for select to authenticated using (published);
"""


def app(tmp_path):
    write(tmp_path, "supabase/migrations/001.sql", MIG)
    write(tmp_path, ".env.example", "NEXT_PUBLIC_SUPABASE_ANON_KEY=\n")
    return tmp_path


def by_line(root, rule_id, **options):
    return {f.locations[0].line: f for f in findings_for(root, "rls", rule_id, **options)}


def test_policy_true_and_authenticated_not_owner(tmp_path):
    root = app(tmp_path)
    assert sorted(by_line(root, "RLS-POLICY-TRUE")) == [8]
    assert sorted(by_line(root, "RLS-AUTHENTICATED-NOT-OWNER")) == [9]
    assert 'drop policy "documents_read" on public.documents;' in by_line(root, "RLS-POLICY-TRUE")[8].fix


def test_weak_with_check_severity(tmp_path):
    found = by_line(app(tmp_path), "RLS-WEAK-WITH-CHECK")
    assert {line: f.severity.value for line, f in found.items()} == {3: "low", 11: "high", 12: "high"}


def test_wrong_role_client_owner_tenant_unbound(tmp_path):
    root = app(tmp_path)
    assert sorted(by_line(root, "RLS-WRONG-ROLE")) == [10]
    assert sorted(by_line(root, "RLS-CLIENT-OWNER")) == [4]
    unbound = by_line(root, "RLS-TENANT-UNBOUND")
    assert sorted(unbound) == [15]
    assert unbound[15].tag.value == "INFERRED" and unbound[15].proof_needed


def test_dump_only_table_is_checked(tmp_path):
    root = app(tmp_path)
    dump = write(tmp_path, "pol.csv",
                 "schemaname,tablename,policyname,permissive,roles,cmd,qual,with_check\n"
                 "public,secrets,secrets_read,PERMISSIVE,{authenticated},SELECT,(auth.role() = 'authenticated'::text),\n")
    found = findings_for(root, "rls", "RLS-AUTHENTICATED-NOT-OWNER", db_dump=str(dump))
    assert sorted((f.locations[0].file.endswith("pol.csv"), f.locations[0].line) for f in found) == [
        (False, 9), (True, 2),
    ]
