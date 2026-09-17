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
    assert (
        'drop policy "documents_read" on public.documents;'
        in by_line(root, "RLS-POLICY-TRUE")[8].fix
    )


def test_weak_with_check_severity(tmp_path):
    found = by_line(app(tmp_path), "RLS-WEAK-WITH-CHECK")
    # profiles_admin is a select policy that is not scoped to the owner, so line 3 stays high.
    assert {line: f.severity.value for line, f in found.items()} == {
        3: "high",
        11: "high",
        12: "high",
    }


def test_wrong_role_client_owner_tenant_unbound(tmp_path):
    root = app(tmp_path)
    assert sorted(by_line(root, "RLS-WRONG-ROLE")) == [10]
    assert sorted(by_line(root, "RLS-CLIENT-OWNER")) == [4]
    unbound = by_line(root, "RLS-TENANT-UNBOUND")
    assert sorted(unbound) == [15]
    assert unbound[15].tag.value == "INFERRED" and unbound[15].proof_needed


def test_dump_only_table_is_checked(tmp_path):
    root = app(tmp_path)
    dump = write(
        tmp_path,
        "pol.csv",
        "schemaname,tablename,policyname,permissive,roles,cmd,qual,with_check\n"
        "public,secrets,secrets_read,PERMISSIVE,{authenticated},SELECT,(auth.role() = 'authenticated'::text),\n",
    )
    found = findings_for(root, "rls", "RLS-AUTHENTICATED-NOT-OWNER", db_dump=str(dump))
    assert sorted(
        (f.locations[0].file.endswith("pol.csv"), f.locations[0].line) for f in found
    ) == [
        (False, 9),
        (True, 2),
    ]


SERVER_AND_RESTRICTIVE = """create table public.notes (id uuid primary key, user_id uuid not null, body text);
alter table public.notes enable row level security;
create policy "notes_service" on public.notes for all to service_role using (true) with check (true);
create policy "notes_admin" on public.notes for select to postgres, supabase_admin using (true);
create policy "notes_restrict" on public.notes as restrictive for select to authenticated using (true);
create policy "notes_restrict_auth" on public.notes as restrictive for select to authenticated using (auth.role() = 'authenticated');
create policy "notes_restrict_write" on public.notes as restrictive for update to anon using (body is not null) with check (true);
create policy "notes_mixed" on public.notes for select to service_role, anon using (true);
"""


def test_server_roles_and_restrictive_policies_do_not_grant(tmp_path):
    write(tmp_path, "supabase/migrations/001.sql", SERVER_AND_RESTRICTIVE)
    write(tmp_path, ".env.example", "NEXT_PUBLIC_SUPABASE_ANON_KEY=\n")
    assert sorted(by_line(tmp_path, "RLS-POLICY-TRUE")) == [8]
    for rule_id in (
        "RLS-AUTHENTICATED-NOT-OWNER",
        "RLS-WRONG-ROLE",
        "RLS-WEAK-WITH-CHECK",
        "RLS-TENANT-UNBOUND",
    ):
        assert by_line(tmp_path, rule_id) == {}, rule_id


HELPERS = """create table public.projects (id uuid primary key, org_id uuid not null, user_id uuid, name text);
alter table public.projects enable row level security;
create policy "projects_member" on public.projects for select to authenticated using (public.is_org_member(org_id));
create policy "projects_signed_in" on public.projects for select to authenticated using (auth.role() = 'authenticated');
create policy "projects_write" on public.projects for update to anon using (private.can_edit(id)) with check (private.can_edit(id));
create policy "projects_rows" on public.projects for insert with check (public.can_insert(id));
create policy "projects_tenant" on public.projects for select to authenticated using (exists (select 1 from public.members m where m.user_id = (select auth.uid()) and public.active(m.id)));
create policy "projects_tenant_plain" on public.projects for select to authenticated using (exists (select 1 from public.members m where m.user_id = auth.uid() and m.role in ('a', 'b(c)')));
create policy "projects_insert_plain" on public.projects for insert with check (true);
create table public.members (id uuid, org_id uuid, user_id uuid, role text);
"""


def test_helper_functions_make_policy_findings_inferred(tmp_path):
    write(tmp_path, "supabase/migrations/001.sql", HELPERS)
    write(tmp_path, ".env.example", "NEXT_PUBLIC_SUPABASE_ANON_KEY=\n")
    helper = "Read the called function to confirm it checks the row owner or tenant."

    def tags(rule_id):
        return {
            line: (f.tag.value, f.proof_needed) for line, f in by_line(tmp_path, rule_id).items()
        }

    assert tags("RLS-AUTHENTICATED-NOT-OWNER") == {
        3: ("INFERRED", helper),
        4: ("CONFIRMED", None),
    }
    assert tags("RLS-WRONG-ROLE") == {5: ("INFERRED", helper)}
    assert tags("RLS-WEAK-WITH-CHECK") == {
        5: ("INFERRED", helper),
        6: ("INFERRED", helper),
        9: ("CONFIRMED", None),
    }
    unbound = tags("RLS-TENANT-UNBOUND")
    assert unbound[7] == ("INFERRED", helper)
    assert unbound[8][0] == "INFERRED" and unbound[8][1].startswith("Sign in as a member")


EVERY_SELECT = """create table public.a (id int, user_id uuid);
alter table public.a enable row level security;
create policy a_own on public.a for select using (auth.uid() = user_id);
create policy a_admin on public.a for select using (auth.jwt() ->> 'role' = 'admin');
create policy a_update on public.a for update using (auth.uid() = user_id) with check (true);
create table public.b (id int, user_id uuid);
alter table public.b enable row level security;
create policy b_own on public.b for select using ((select auth.uid()) = user_id);
create policy b_all on public.b for all to authenticated using (user_id = auth.uid()) with check (true);
create policy b_service on public.b for select to service_role using (true);
create policy b_restrict on public.b as restrictive for select using (true);
create table public.c (id int, user_id uuid);
alter table public.c enable row level security;
create policy c_update on public.c for update using (auth.uid() = user_id) with check (true);
"""


def test_weak_with_check_is_low_only_when_every_select_policy_is_owner_scoped(tmp_path):
    write(tmp_path, "supabase/migrations/001.sql", EVERY_SELECT)
    write(tmp_path, ".env.example", "NEXT_PUBLIC_SUPABASE_ANON_KEY=\n")
    found = by_line(tmp_path, "RLS-WEAK-WITH-CHECK")
    assert {line: f.severity.value for line, f in found.items()} == {
        5: "high",
        9: "low",
        14: "high",
    }
    assert "Not every select policy is scoped to the owner" in found[5].detail
    assert "Every select policy is scoped to the owner" in found[9].detail


def test_renamed_table_leaves_no_ghost(tmp_path):
    write(
        tmp_path,
        "supabase/migrations/001.sql",
        "create table public.notes (id int, user_id uuid);\n"
        "alter table public.notes rename to memos;\n"
        "alter table public.memos enable row level security;\n"
        "create policy memos_own on public.memos for select using (auth.uid() = user_id);\n",
    )
    write(tmp_path, ".env.example", "NEXT_PUBLIC_SUPABASE_ANON_KEY=\n")
    assert findings_for(tmp_path, "rls", "RLS-TABLE-OFF") == []
