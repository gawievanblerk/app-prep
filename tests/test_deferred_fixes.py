import subprocess

from dpr import gitutil
from dpr.parsing.sqlschema import load_schema
from dpr.redact import is_secret_name, redact
from dpr.walk import RepoIndex
from tests.reviews.helpers import findings_for, write


def test_secret_words_match_whole_tokens():
    assert not is_secret_name("NEXT_PUBLIC_ADMIN_EMAIL")
    assert not is_secret_name("NEXT_PUBLIC_SMTP_HOST")
    assert not is_secret_name("VITE_PASSWORDLESS_ENABLED")
    assert is_secret_name("NEXT_PUBLIC_SMTP_PASSWORD")
    assert is_secret_name("VITE_ADMIN_KEY")
    assert is_secret_name("NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY")


def test_public_admin_email_is_not_a_leaked_secret(tmp_path):
    write(tmp_path, ".env.example", "NEXT_PUBLIC_ADMIN_EMAIL=\nNEXT_PUBLIC_WEBHOOK_SECRET=\n")
    write(tmp_path, "app/page.tsx", "export default function P() { return null }\n")
    found = findings_for(tmp_path, "leaks", "LEAK-PUBLIC-SECRET")
    assert [f.title for f in found] == [found[0].title]
    assert "NEXT_PUBLIC_WEBHOOK_SECRET" in found[0].title + found[0].detail


def test_sensitive_columns_match_whole_words(tmp_path):
    route = (
        "import { prisma } from '@/lib/db'\n"
        "export async function GET(req, { params }) {\n"
        "  const row = await prisma.{model}.findUnique({ where: { id: params.id } })\n"
        "  return Response.json(row)\n}\n"
    )
    write(
        tmp_path,
        "prisma/schema.prisma",
        "model Course {\n  id Int @id\n  enrolled Int\n  hashtag String\n}\n"
        "model Member {\n  id Int @id\n  passwordHash String\n}\n",
    )
    write(tmp_path, "app/api/courses/[id]/route.ts", route.replace("{model}", "course"))
    write(tmp_path, "app/api/members/[id]/route.ts", route.replace("{model}", "member"))
    severities = {
        f.locations[0].file.split("/")[2]: f.severity.value
        for f in findings_for(tmp_path, "leaks", "LEAK-BROAD-RESPONSE")
    }
    assert severities == {"courses": "medium", "members": "high"}


def test_url_password_containing_at_sign_is_fully_masked():
    secret = "p" + "@ss" + "w0rd"
    out = redact(f"DATABASE_URL=postgres://app:{secret}@db.internal:5432/app")
    assert "ss" + "w0rd" not in out
    assert out == "DATABASE_URL=postgres://app:<redacted:password>@db.internal:5432/app"


def test_git_timeout_is_recorded(tmp_path, monkeypatch):
    def slow(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="git", timeout=30)

    monkeypatch.setattr(gitutil.subprocess, "run", slow)
    notes = []
    assert gitutil.tracked_files(tmp_path, notes=notes) is None
    assert notes == [
        "git ls-files timed out after 30 s, so the git-based checks that use it are incomplete"
    ]


def test_down_sections_are_not_applied(tmp_path):
    write(
        tmp_path,
        "db/migrations/20240101_notes.sql",
        "-- migrate:up\ncreate table notes (id int);\n\n-- migrate:down\ndrop table notes;\n",
    )
    write(
        tmp_path,
        "db/migrations/20240102_tags.sql",
        "-- +goose Up\ncreate table tags (id int);\n-- +goose Down\ndrop table tags;\n",
    )
    state = load_schema(RepoIndex(tmp_path))
    assert {"public.notes", "public.tags"} <= set(state.tables)
    assert state.tables["public.tags"].location.line == 2


def test_drizzle_output_folder_is_a_migration_source(tmp_path):
    write(tmp_path, "drizzle/0000_init.sql", 'CREATE TABLE "accounts" ("id" serial PRIMARY KEY);\n')
    assert "public.accounts" in load_schema(RepoIndex(tmp_path)).tables
