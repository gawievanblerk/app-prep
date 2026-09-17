import subprocess

from dpr.discovery.detect import detect
from dpr.walk import RepoIndex


def write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_detect_next_supabase_app(tmp_path):
    write(
        tmp_path,
        "package.json",
        '{"dependencies": {"next": "14", "@supabase/supabase-js": "2", "@prisma/client": "5",'
        ' "@sentry/nextjs": "8", "openai": "4", "@upstash/ratelimit": "1"},'
        ' "devDependencies": {"vitest": "1"}}',
    )
    write(
        tmp_path,
        "next.config.js",
        "module.exports = { async headers() { return [{ source: '/(.*)', headers: "
        "[{ key: 'X-Frame-Options', value: 'DENY' }] }] } }\n",
    )
    write(tmp_path, "vercel.json", "{}")
    write(tmp_path, ".github/workflows/ci.yml", "on: push")
    write(tmp_path, ".env.example", "NEXT_PUBLIC_SUPABASE_ANON_KEY=\n")
    write(tmp_path, "prisma/schema.prisma", "model User {\n  id Int @id\n}\n")
    write(tmp_path, "supabase/migrations/1.sql", "create table docs (id int);")
    write(tmp_path, "lib/ai.ts", "import OpenAI from 'openai'\nconst s = supabase.auth.getUser()\n")
    write(tmp_path, "app/api/chat/route.ts", "export async function POST() {}\n")
    subprocess.run(["git", "-C", str(tmp_path), "init", "-q"], check=True)

    d = detect(RepoIndex(tmp_path))
    assert d.languages == {"javascript/typescript": 3}
    assert d.frameworks == ["next"]
    assert d.databases == ["supabase"]
    assert d.orms == ["prisma"]
    assert d.auth_providers == ["supabase-auth"]
    assert d.hosting == ["vercel"]
    assert d.ci == [".github/workflows/ci.yml"]
    assert d.logging == ["sentry"]
    assert d.header_config == ["next.config.js"]
    assert d.rate_limiters == ["upstash-ratelimit"]
    assert d.test_frameworks == ["vitest"]
    assert [s.name for s in d.sdks] == ["openai", "sentry"]
    openai = d.sdks[0]
    assert (openai.category, openai.paid, openai.recipient) == ("llm", True, True)
    assert [str(loc) for loc in openai.locations] == ["lib/ai.ts:1"]
    assert [(r.method, r.path) for r in d.routes] == [("POST", "/api/chat")]
    assert [m.name for m in d.models] == ["User", "docs"]
    assert "public.docs" in d.schema.tables
    assert d.serverless is True
    assert d.public_supabase_key is True
    assert d.git.is_repo is True
    assert "next" in d.packages


def test_detect_django_app(tmp_path):
    write(tmp_path, "requirements.txt", "Django==5.0\ndjangorestframework\nsentry-sdk\n")
    write(tmp_path, "manage.py", "import django\n")
    write(
        tmp_path,
        "shop/settings.py",
        "SECURE_HSTS_SECONDS = 3600\nfrom django.contrib.auth import x\n",
    )
    write(tmp_path, "Dockerfile", "FROM python")
    d = detect(RepoIndex(tmp_path))
    assert d.frameworks == ["django", "djangorestframework"]
    assert d.orms == ["django-orm"]
    assert d.auth_providers == ["django-auth"]
    assert d.hosting == ["docker"]
    assert d.header_config == ["shop/settings.py"]
    assert d.serverless is False
    assert d.public_supabase_key is False
    assert d.git.is_repo is False
