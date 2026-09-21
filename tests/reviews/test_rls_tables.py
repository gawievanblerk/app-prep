from dpr import reviews, rules
from dpr.discovery.detect import detect
from dpr.walk import RepoIndex
from tests.reviews.helpers import findings_for, write

MIG = """create table public.invoices (id bigserial primary key, user_id uuid not null, amount int);
create table public.documents (id bigserial primary key, user_id uuid, body text);
alter table public.documents enable row level security;
create policy "documents_read" on public.documents for select using (auth.uid() = user_id);
create table public.members (org_id uuid, user_id uuid);
alter table public.members enable row level security;
create table public.lookup (code text primary key);
alter table public.lookup enable row level security;
create policy lookup_read on public.lookup for select using (true);
create view public.document_list as select id, body from public.documents;
create view public.safe_list with (security_invoker = true) as select id from public.documents;
create function public.all_docs() returns setof public.documents language sql security definer as $$ select * from public.documents $$;
create function public.util() returns int language sql security definer set search_path = '' as $$ select 1 $$;
insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true), ('private', 'private', false);
create table audit.events (id int);
"""


def app(tmp_path, public_key=True):
    write(tmp_path, "supabase/migrations/001_init.sql", MIG)
    if public_key:
        write(tmp_path, ".env.example", "NEXT_PUBLIC_SUPABASE_ANON_KEY=\n")
    write(
        tmp_path,
        "lib/q.ts",
        "export const q = () => supabase.from('invoices').select('id')\n"
        "export const b = () => supabase.storage.createBucket('uploads', { public: true })\n",
    )
    return tmp_path


def lines(found):
    return sorted((f.locations[0].file, f.locations[0].line) for f in found)


def test_table_off(tmp_path):
    [f] = findings_for(app(tmp_path), "rls", "RLS-TABLE-OFF")
    assert (str(f.locations[0]), f.severity.value, f.tag.value) == (
        "supabase/migrations/001_init.sql:1",
        "critical",
        "CONFIRMED",
    )
    assert "alter table public.invoices enable row level security;" in f.fix
    assert "for select using (auth.uid() = user_id);" in f.fix
    assert "rest/v1/invoices" in f.verify


def test_table_level_rules(tmp_path):
    root = app(tmp_path)
    mig = "supabase/migrations/001_init.sql"
    assert lines(findings_for(root, "rls", "RLS-NO-POLICIES")) == [(mig, 6)]
    assert lines(findings_for(root, "rls", "RLS-SELECT-ONLY")) == [(mig, 4), (mig, 9)]
    assert lines(findings_for(root, "rls", "RLS-VIEW-BYPASS")) == [(mig, 10)]
    definer = {f.locations[0].line: f for f in findings_for(root, "rls", "RLS-DEFINER-FUNCTION")}
    assert (definer[12].severity.value, definer[13].severity.value) == ("high", "medium")
    assert "does not set search_path" in definer[12].detail
    assert lines(findings_for(root, "rls", "RLS-PUBLIC-BUCKET")) == [("lib/q.ts", 2), (mig, 14)]


def test_server_only_data_layer_reports_nothing(tmp_path):
    root = app(tmp_path, public_key=False)
    assert findings_for(root, "rls", "RLS-TABLE-OFF") == []
    reviews.available()
    index = RepoIndex(root)
    ctx = rules.Context(index=index, detection=detect(index))
    section = reviews.available()["rls"].run(ctx)
    assert [p.title for p in section.parts] == [
        "Relevance",
        "Table protection status",
        "Policy defects",
        "Database exposure and privilege",
        "Missing policies (runnable SQL)",
        "How to confirm from outside the app",
    ]


def test_not_applicable(tmp_path):
    write(tmp_path, "a.py", "x = 1\n")
    index = RepoIndex(tmp_path)
    ctx = rules.Context(index=index, detection=detect(index))
    assert reviews.available()["rls"].run(ctx) is None
    assert ctx.not_covered == [
        "Review 2 (rls): not applicable, no SQL tables, ORM models, migrations, Supabase "
        "client or database dump found"
    ]


def test_section_parts_and_breakage_note(tmp_path):
    index = RepoIndex(app(tmp_path))
    ctx = rules.Context(index=index, detection=detect(index))
    section = reviews.available()["rls"].run(ctx)
    assert [p.title for p in section.parts] == [
        "Table protection status",
        "Policy defects",
        "Missing policies (runnable SQL)",
        "How to confirm from outside the app",
        "Confirm in the database",
    ]
    table = section.parts[0]
    assert [r[0] for r in table.rows] == [
        "public.documents",
        "public.invoices",
        "public.lookup",
        "public.members",
    ]
    invoices = next(r for r in table.rows if r[0] == "public.invoices")
    assert invoices[1:5] == ("no", "0", "yes, every row", "exposed")
    missing = section.parts[2].body
    assert "public.invoices" in missing and "public.members" in missing
    assert "`lib/q.ts:1`" in missing
    assert "pg_policies" in section.parts[4].body


def test_db_dump_is_source_of_truth(tmp_path):
    root = app(tmp_path)
    dump = write(
        tmp_path,
        "dump.csv",
        "schemaname,tablename,rowsecurity\npublic,invoices,t\n\n"
        "schemaname,tablename,policyname,permissive,roles,cmd,qual,with_check\n"
        "public,invoices,inv_own,PERMISSIVE,{authenticated},SELECT,(auth.uid() = user_id),\n",
    )
    assert findings_for(root, "rls", "RLS-TABLE-OFF", db_dump=str(dump)) == []
