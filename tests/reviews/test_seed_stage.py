import pytest

from dpr.api import review
from tests.reviews.helpers import findings_for, write

PW = "Seed" + "Stage" + "#4410"


def seeds(root):
    write(root, "api/requirements.txt", "fastapi\n")
    write(
        root,
        "api/app/db/seed.py",
        "from app.core.security import get_password_hash\n"
        f"ADMIN_PASSWORD = '{PW}'\n"
        "def seed(db):\n    db.add(User(password_hash=get_password_hash(ADMIN_PASSWORD)))\n",
    )
    write(
        root,
        "api/app/db/admin_seed.py",
        "import os\nfrom app.core.security import get_password_hash\n"
        f"DEFAULT_PW = '{PW}x'\n"
        "def seed(db):\n"
        "    pw = os.environ.get('SEED_ADMIN_PASSWORD', DEFAULT_PW)\n"
        "    db.add(User(password_hash=get_password_hash(pw)))\n",
    )
    return root


def by_location(root):
    return {str(f.locations[0]): f for f in findings_for(root, "baseline", "BASE-SEED-ON-START")}


def test_staging_service_seed_with_committed_password_is_high(tmp_path):
    seeds(tmp_path)
    write(
        tmp_path,
        "render.yaml",
        "services:\n  - type: web\n    rootDir: api\n"
        "    startCommand: python -m app.db.seed && uvicorn app.main:app\n"
        '    envVars:\n      - key: ENVIRONMENT\n        value: "staging"\n',
    )
    finding = by_location(tmp_path)["render.yaml:4"]
    assert finding.severity.value == "high"
    assert "staging environment setting" in finding.detail
    assert finding.refs == ("BASE-LITERAL-PASSWORD-HASH",)


def test_unknown_stage_with_committed_password_stays_critical(tmp_path):
    seeds(tmp_path)
    write(tmp_path, "api/startup.sh", "python -m app.db.seed\ngunicorn app.main:app\n")
    assert by_location(tmp_path)["api/startup.sh:1"].severity.value == "critical"


def test_env_password_from_a_secret_store_is_medium(tmp_path):
    seeds(tmp_path)
    write(tmp_path, "api/startup.sh", "python -m app.db.admin_seed\n")
    write(
        tmp_path,
        "infra/main.tf",
        'resource "azurerm_linux_web_app" "api" {\n  app_settings = {\n'
        '    SEED_ADMIN_PASSWORD = "@Microsoft.KeyVault(SecretUri=${azurerm_key_vault_secret.x.id})"\n'
        "  }\n}\n",
    )
    finding = by_location(tmp_path)["api/startup.sh:1"]
    assert (finding.severity.value, finding.tag.value) == ("medium", "INFERRED")
    assert [str(loc) for loc in finding.locations] == [
        "api/startup.sh:1",
        "api/app/db/admin_seed.py:6",
        "infra/main.tf:3",
    ]
    assert (
        finding.proof_needed == "Check that the secret reference for SEED_ADMIN_PASSWORD resolves."
    )


def test_env_password_without_a_secret_store_stays_high(tmp_path):
    seeds(tmp_path)
    write(tmp_path, "api/startup.sh", "python -m app.db.admin_seed\n")
    write(tmp_path, "infra/main.tf", "app_settings = {\n  SEED_ADMIN_PASSWORD = var.seed\n}\n")
    assert by_location(tmp_path)["api/startup.sh:1"].severity.value == "high"


def _worker_app(root):
    write(root, "worker/requirements.txt", "flask\n")
    write(
        root,
        "worker/app.py",
        "from flask import Flask\napp = Flask(__name__)\n\n\n@app.route('/x')\ndef x():\n"
        "    return 'ok'\n",
    )


def test_deploy_setting_in_a_different_app_root_does_not_lower_severity(tmp_path):
    seeds(tmp_path)
    write(tmp_path, "api/startup.sh", "python -m app.db.admin_seed\n")
    _worker_app(tmp_path)
    write(
        tmp_path,
        "worker/infra/main.tf",
        'resource "azurerm_linux_web_app" "worker" {\n  app_settings = {\n'
        '    SEED_ADMIN_PASSWORD = "@Microsoft.KeyVault(SecretUri=${azurerm_key_vault_secret.x.id})"\n'
        "  }\n}\n",
    )
    assert by_location(tmp_path)["api/startup.sh:1"].severity.value == "high"


def test_shared_repository_level_secret_reference_still_lowers_severity(tmp_path):
    seeds(tmp_path)
    write(tmp_path, "api/startup.sh", "python -m app.db.admin_seed\n")
    _worker_app(tmp_path)
    write(
        tmp_path,
        "infra/main.tf",
        'resource "azurerm_linux_web_app" "api" {\n  app_settings = {\n'
        '    SEED_ADMIN_PASSWORD = "@Microsoft.KeyVault(SecretUri=${azurerm_key_vault_secret.x.id})"\n'
        "  }\n}\n",
    )
    finding = by_location(tmp_path)["api/startup.sh:1"]
    assert (finding.severity.value, finding.tag.value) == ("medium", "INFERRED")


SEED_LITERAL = (
    "from app.core.security import get_password_hash\n\n"
    "def seed():\n"
    "    return get_password_hash('placeholder-demo-value')\n"
)
SEED_ENV = (
    "import os\n"
    "from app.core.security import get_password_hash\n\n"
    "def seed():\n"
    "    return get_password_hash(os.environ['ADMIN_PASSWORD'])\n"
)


ROUTE = "from fastapi import FastAPI\napp = FastAPI()\n\n\n@app.get('/health')\ndef health():\n    return 1\n"


def two_seed_roots(root):
    write(root, "a/requirements.txt", "fastapi\n")
    write(root, "a/app/db/seed.py", SEED_LITERAL)
    write(root, "b/requirements.txt", "fastapi\n")
    write(root, "b/app/db/seed.py", SEED_ENV)


def test_render_service_resolves_the_seed_module_under_its_root_dir(tmp_path):
    two_seed_roots(tmp_path)
    write(
        tmp_path,
        "render.yaml",
        "services:\n  - type: web\n    name: b-api\n    rootDir: b\n"
        "    startCommand: python -m app.db.seed && uvicorn app.main:app\n",
    )
    finding = by_location(tmp_path)["render.yaml:5"]
    assert finding.severity.value == "high"
    assert [loc.file for loc in finding.locations] == ["render.yaml"]
    assert finding.refs == ()


def test_seed_module_found_only_in_another_root_is_not_given_its_severity(tmp_path):
    two_seed_roots(tmp_path)
    write(tmp_path, "c/requirements.txt", "fastapi\n")
    write(tmp_path, "c/app/main.py", ROUTE)
    write(tmp_path, "c/start.sh", "python -m app.db.seed\nuvicorn app.main:app\n")
    finding = by_location(tmp_path)["c/start.sh:1"]
    assert (finding.severity.value, finding.tag.value) == ("high", "INFERRED")
    assert [loc.file for loc in finding.locations] == ["c/start.sh"]
    assert "a/app/db/seed.py" in finding.proof_needed
    write(tmp_path, "a/start.sh", "python -m app.db.seed\nuvicorn app.main:app\n")
    local = by_location(tmp_path)["a/start.sh:1"]
    assert local.severity.value == "critical"
    assert [str(loc) for loc in local.locations] == ["a/start.sh:1", "a/app/db/seed.py:4"]


SHARED_STARTS = {
    "compose build": (
        "docker-compose.yml",
        "services:\n  api:\n    build: ./backend\n"
        '    command: sh -c "python -m app.db.seed && uvicorn app.main:app"\n',
        4,
    ),
    "compose context": (
        "docker-compose.yml",
        "services:\n  api:\n    build:\n      context: ./backend\n"
        '    command: sh -c "python -m app.db.seed && uvicorn app.main:app"\n',
        5,
    ),
    "procfile cd": ("Procfile", "release: cd backend && python -m app.db.seed\n", 1),
    "render cd": (
        "render.yaml",
        "services:\n  - type: web\n    name: api\n"
        "    startCommand: cd backend && python -m app.db.seed && uvicorn app.main:app\n",
        4,
    ),
    "render script path": (
        "render.yaml",
        "services:\n  - type: web\n    name: api\n"
        "    startCommand: python backend/app/db/seed.py && uvicorn app.main:app\n",
        4,
    ),
    "module under one root": ("Procfile", "release: python -m app.db.seed\n", 1),
}


def backend(root):
    write(root, "backend/requirements.txt", "fastapi\npasslib\n")
    write(root, "backend/app/main.py", ROUTE)
    write(root, "backend/app/db/seed.py", SEED_LITERAL)
    return root


@pytest.mark.parametrize("shape", sorted(SHARED_STARTS))
def test_shared_start_file_resolves_the_seed_in_the_app_root_it_names(tmp_path, shape):
    rel, text, line = SHARED_STARTS[shape]
    write(backend(tmp_path), rel, text)
    finding = by_location(tmp_path)[f"{rel}:{line}"]
    assert finding.severity.value == "critical"
    assert "another app root" not in finding.proof_needed
    assert [str(loc) for loc in finding.locations] == [f"{rel}:{line}", "backend/app/db/seed.py:4"]
    assert finding.refs == ("BASE-LITERAL-PASSWORD-HASH",)
    [issue] = [i for i in review(tmp_path).register if "BASE-SEED-ON-START" in i.findings]
    assert issue.title == (
        "Account passwords are written in backend/app/db/seed.py, and a start command runs it"
    )


def test_shared_start_file_with_seeds_in_two_app_roots_stays_unresolved(tmp_path):
    backend(tmp_path)
    write(tmp_path, "worker/requirements.txt", "fastapi\n")
    write(tmp_path, "worker/app/main.py", ROUTE)
    write(tmp_path, "worker/app/db/seed.py", SEED_LITERAL.replace("demo", "other"))
    write(tmp_path, "Procfile", "release: python -m app.db.seed\n")
    finding = by_location(tmp_path)["Procfile:1"]
    assert (finding.severity.value, [loc.file for loc in finding.locations]) == (
        "high",
        ["Procfile"],
    )
    assert "backend/app/db/seed.py" in finding.proof_needed
