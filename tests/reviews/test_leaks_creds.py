from dpr.api import review
from dpr.report.json_out import render_json
from dpr.report.markdown import render_markdown
from tests.reviews.helpers import findings_for, write

BYPASS_VALUE = "rollout" + "-gate-" + "2031"
DB_DEFAULT = "localdev" + "pw" + "31"


def repo(root):
    write(
        root,
        "web/src/Gate.tsx",
        "export const ok = (k) => k === import.meta.env.VITE_PREVIEW_UNLOCK_KEY\n",
    )
    write(root, "web/src/api.ts", "export const base = import.meta.env.VITE_API_URL\n")
    write(
        root,
        "azure-pipelines.yml",
        f"variables:\n  VITE_PREVIEW_UNLOCK_KEY: '{BYPASS_VALUE}'\n  VITE_API_URL: $(API_URL)\n",
    )
    write(
        root,
        "docker-compose.yml",
        "services:\n  db:\n    environment:\n"
        f"      POSTGRES_PASSWORD: ${{DB_PASSWORD:-{DB_DEFAULT}}}\n"
        "      POSTGRES_USER: app\n"
        "      JWT_SECRET: ${JWT_SECRET}\n"
        f"      DATABASE_URL: postgresql://app:{DB_DEFAULT}@db:5432/app\n"
        "      API_TOKEN: changeme\n",
    )
    write(
        root,
        "scripts/restore.sh",
        f'STORE_PASSWORD="${{STORE_PASSWORD:-{DB_DEFAULT}}}"\nUSER="${{STORE_USER:-admin}}"\n',
    )
    write(
        root,
        "scripts/migrate.py",
        f'"""Usage: migrate.py --from-password {DB_DEFAULT} --from-server localhost"""\n',
    )
    write(
        root,
        "docs/setup.md",
        "Run with --password <your-password> and postgresql://user:password@host/db\n",
    )
    write(
        root,
        "app/config.py",
        f"database_url = 'postgresql://app:{DB_DEFAULT}@localhost:5432/app'\n",
    )
    return root


def test_public_gate_key(tmp_path):
    [f] = findings_for(repo(tmp_path), "leaks", "LEAK-PUBLIC-GATE-KEY")
    assert [str(loc) for loc in f.locations] == ["azure-pipelines.yml:2", "web/src/Gate.tsx:1"]
    assert "committed at azure-pipelines.yml:2" in f.detail


def test_default_credentials(tmp_path):
    found = {
        f.locations[0].file: f
        for f in findings_for(repo(tmp_path), "leaks", "LEAK-DEFAULT-CREDENTIAL")
    }
    assert set(found) == {"docker-compose.yml", "scripts/restore.sh", "scripts/migrate.py"}
    assert [str(loc) for loc in found["docker-compose.yml"].locations] == [
        "docker-compose.yml:4",
        "docker-compose.yml:7",
    ]
    assert "a default value for DB_PASSWORD" in found["docker-compose.yml"].detail


def test_values_never_printed(tmp_path):
    report = review(repo(tmp_path))
    text = render_markdown(report) + render_json(report)
    assert BYPASS_VALUE not in text and DB_DEFAULT not in text
