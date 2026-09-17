from dpr.discovery.packages import collect_env_vars, collect_packages, normalise
from dpr.walk import RepoIndex


def write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_collect_packages(tmp_path):
    write(
        tmp_path,
        "package.json",
        '{"dependencies": {"next": "14"}, "devDependencies": {"vitest": "1"}}',
    )
    write(tmp_path, "web/broken/package.json", "{not json")
    write(
        tmp_path,
        "pyproject.toml",
        '[project]\ndependencies = ["Django>=5", "psycopg[binary]"]\n'
        '[dependency-groups]\ndev = ["pytest"]\n'
        '[tool.poetry.dependencies]\nsentry_sdk = "^2"\n',
    )
    write(
        tmp_path,
        "requirements-dev.txt",
        "# tools\nslowapi==0.1 ; python_version > '3'\n-r base.txt\n",
    )
    write(
        tmp_path,
        "src/a.ts",
        "import { createClient } from '@supabase/supabase-js'\n"
        "import './styles.css'\nconst x = require(\"stripe\")\nimport 'server-only'\n",
    )
    write(tmp_path, "svc/b.py", "import os\nfrom openai import OpenAI\n")
    packages, sites = collect_packages(RepoIndex(tmp_path))
    for name in [
        "next",
        "vitest",
        "django",
        "psycopg",
        "pytest",
        "sentry-sdk",
        "slowapi",
        "@supabase/supabase-js",
        "stripe",
        "server-only",
        "openai",
        "os",
    ]:
        assert name in packages, name
    assert [str(loc) for loc in sites["stripe"]] == ["src/a.ts:3"]
    assert [str(loc) for loc in sites["openai"]] == ["svc/b.py:2"]
    assert normalise("Flask_Login") == "flask-login"


def test_collect_env_vars_names_only(tmp_path):
    write(
        tmp_path,
        ".env.local",
        "NEXT_PUBLIC_SUPABASE_URL=https://x\nSECRET_VALUE_HOLDER=do-not-read\n",
    )
    write(
        tmp_path,
        "lib/a.ts",
        "const u = process.env.NEXT_PUBLIC_SUPABASE_URL\nconst k = process.env['STRIPE_SECRET_KEY']\n"
        "const v = import.meta.env.VITE_API\n",
    )
    write(
        tmp_path,
        "src/routes/+page.svelte",
        "<script>\nimport { PUBLIC_MAP_TOKEN } from '$env/static/public'\n</script>\n",
    )
    write(
        tmp_path,
        "svc/settings.py",
        "import os\nA = os.environ['DATABASE_URL']\nB = os.environ.get('DEBUG')\n"
        "C = os.getenv('REDIS_URL')\nD = env.bool('USE_TLS')\n",
    )
    env = {e.name: e for e in collect_env_vars(RepoIndex(tmp_path))}
    assert sorted(env) == [
        "DATABASE_URL",
        "DEBUG",
        "NEXT_PUBLIC_SUPABASE_URL",
        "PUBLIC_MAP_TOKEN",
        "REDIS_URL",
        "SECRET_VALUE_HOLDER",
        "STRIPE_SECRET_KEY",
        "USE_TLS",
        "VITE_API",
    ]
    assert [str(loc) for loc in env["NEXT_PUBLIC_SUPABASE_URL"].locations] == [
        ".env.local:1",
        "lib/a.ts:1",
    ]
    assert env["NEXT_PUBLIC_SUPABASE_URL"].public and env["VITE_API"].public
    assert not env["STRIPE_SECRET_KEY"].public
    assert "do-not-read" not in repr(env)
