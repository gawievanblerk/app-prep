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
