from dpr.discovery.detect import detect
from dpr.reviews import deploy_env
from dpr.rules import Context
from dpr.walk import RepoIndex
from tests.reviews.helpers import findings_for, write

SETTINGS = (
    "from pydantic_settings import BaseSettings\n\n\n"
    "class Settings(BaseSettings):\n    debug: bool = True\n    environment: str = 'dev'\n"
)
GUARDED = SETTINGS + (
    "\n    def check(self):\n        if self.environment == 'production':\n"
    "            if self.debug:\n                raise ValueError('DEBUG must be False')\n"
)


def api(root, settings=SETTINGS, main="from fastapi import FastAPI\napp = FastAPI()\n"):
    write(root, "api/requirements.txt", "fastapi\n")
    write(root, "api/app/config.py", settings)
    write(root, "api/app/main.py", main)
    return root


def locs(found):
    return sorted((str(f.locations[0]), f.severity.value) for f in found)


def test_settings_flag_passed_to_the_app_is_reported(tmp_path):
    api(tmp_path, main="from fastapi import FastAPI\napp = FastAPI(debug=settings.debug)\n")
    found = findings_for(tmp_path, "baseline", "BASE-DEBUG-ON")
    assert locs(found) == [("api/app/config.py:5", "high")]
    assert "passed to the app" in found[0].detail


def test_flag_assigned_to_app_debug_is_a_sink(tmp_path):
    api(
        tmp_path,
        main="from flask import Flask\napp = Flask(__name__)\napp.debug = settings.debug\n",
    )
    assert locs(findings_for(tmp_path, "baseline", "BASE-DEBUG-ON")) == [
        ("api/app/config.py:5", "high")
    ]


def test_flag_that_only_gates_docs_is_low(tmp_path):
    main = (
        "from fastapi import FastAPI\napp = FastAPI(docs_url='/docs' if settings.debug else None)\n"
    )
    api(tmp_path, main=main)
    found = findings_for(tmp_path, "baseline", "BASE-DEBUG-ON")
    assert locs(found) == [("api/app/config.py:5", "low")]
    assert "API docs" in found[0].detail


def test_unused_flag_is_not_reported(tmp_path):
    api(tmp_path)
    assert findings_for(tmp_path, "baseline", "BASE-DEBUG-ON") == []


def test_production_validator_suppresses(tmp_path):
    api(
        tmp_path,
        settings=GUARDED,
        main="from fastapi import FastAPI\napp = FastAPI(debug=settings.debug)\n",
    )
    assert findings_for(tmp_path, "baseline", "BASE-DEBUG-ON") == []


def test_every_deploy_config_setting_debug_false_suppresses(tmp_path):
    api(tmp_path, main="from fastapi import FastAPI\napp = FastAPI(debug=settings.debug)\n")
    write(
        tmp_path,
        "infra/main.tf",
        'resource "azurerm_linux_web_app" "api" {\n  app_settings = {\n    DEBUG = "false"\n  }\n}\n',
    )
    write(
        tmp_path,
        "render.yaml",
        'services:\n  - type: web\n    envVars:\n      - key: DEBUG\n        value: "false"\n',
    )
    write(tmp_path, ".gitlab-ci.yml", 'test:\n  variables:\n    DEBUG: "true"\n')
    assert findings_for(tmp_path, "baseline", "BASE-DEBUG-ON") == []


def test_one_deploy_config_turning_debug_on_keeps_the_finding(tmp_path):
    api(tmp_path, main="from fastapi import FastAPI\napp = FastAPI(debug=settings.debug)\n")
    write(tmp_path, "infra/main.tf", 'app_settings = {\n  DEBUG = "false"\n}\n')
    write(tmp_path, "api/Dockerfile", "FROM python\nENV DEBUG=true\n")
    assert len(findings_for(tmp_path, "baseline", "BASE-DEBUG-ON")) == 1


def _worker_app(root):
    write(root, "worker/requirements.txt", "flask\n")
    write(
        root,
        "worker/app.py",
        "from flask import Flask\napp = Flask(__name__)\n\n\n@app.route('/x')\ndef x():\n"
        "    return 'ok'\n",
    )


def test_deploy_setting_in_a_different_app_root_does_not_suppress(tmp_path):
    api(tmp_path, main="from fastapi import FastAPI\napp = FastAPI(debug=settings.debug)\n")
    _worker_app(tmp_path)
    write(tmp_path, "worker/infra/main.tf", 'app_settings = {\n  DEBUG = "false"\n}\n')
    assert len(findings_for(tmp_path, "baseline", "BASE-DEBUG-ON")) == 1


def test_shared_repository_level_deploy_setting_still_suppresses(tmp_path):
    api(tmp_path, main="from fastapi import FastAPI\napp = FastAPI(debug=settings.debug)\n")
    _worker_app(tmp_path)
    write(tmp_path, "infra/main.tf", 'app_settings = {\n  DEBUG = "false"\n}\n')
    assert findings_for(tmp_path, "baseline", "BASE-DEBUG-ON") == []


def test_sink_in_another_app_root_does_not_count(tmp_path):
    api(tmp_path)
    write(tmp_path, "worker/requirements.txt", "flask\n")
    write(tmp_path, "worker/app.py", "app = Flask(__name__)\napp.run(debug=config.debug)\n")
    assert findings_for(tmp_path, "baseline", "BASE-DEBUG-ON") == []


def test_sink_in_a_sibling_root_does_not_count_for_a_repository_root_app(tmp_path):
    """A repository-root app ("" app root) must not pick up a sink from a sibling root through
    a string-prefix test that matches every path, which would wrongly upgrade a docs-only,
    low-severity finding into a high-severity one."""
    write(tmp_path, "requirements.txt", "fastapi\n")
    write(tmp_path, "app/config.py", SETTINGS)
    write(
        tmp_path,
        "app/main.py",
        "from fastapi import FastAPI\napp = FastAPI(docs_url='/docs' if settings.debug else None)\n",
    )
    write(tmp_path, "worker/requirements.txt", "flask\n")
    write(tmp_path, "worker/app.py", "app = Flask(__name__)\napp.run(debug=config.debug)\n")
    found = findings_for(tmp_path, "baseline", "BASE-DEBUG-ON")
    assert locs(found) == [("app/config.py:5", "low")]
    assert "API docs" in found[0].detail


def ctx_for(root):
    index = RepoIndex(root)
    return Context(index=index, detection=detect(index))


def test_secret_reference_and_stage(tmp_path):
    write(
        tmp_path,
        "infra/main.tf",
        "app_settings = {\n"
        '  SEED_ADMIN_PASSWORD = "@Microsoft.KeyVault(SecretUri=${azurerm_key_vault_secret.s.id})"\n'
        '  PLAIN = "value"\n}\n',
    )
    write(
        tmp_path,
        "render.yaml",
        "services:\n  - type: web\n    startCommand: python -m app.db.seed\n    envVars:\n"
        '      - key: ENVIRONMENT\n        value: "staging"\n'
        "      - key: TOKEN\n        sync: false\n"
        "  - type: worker\n    startCommand: python worker.py\n",
    )
    ctx = ctx_for(tmp_path)
    assert str(deploy_env.secret_reference(ctx, "SEED_ADMIN_PASSWORD")) == "infra/main.tf:2"
    assert str(deploy_env.secret_reference(ctx, "TOKEN")) == "render.yaml:7"
    assert deploy_env.secret_reference(ctx, "PLAIN") is None
    assert deploy_env.start_stage(ctx, "render.yaml", 3) == "staging"
    assert deploy_env.start_stage(ctx, "render.yaml", 10) is None
    assert deploy_env.non_production("staging") and not deploy_env.non_production("production")


def test_django_debug_skips_test_ci_and_vendored_settings(tmp_path):
    apps = "INSTALLED_APPS = ['shop']\nDEBUG = True\n"
    write(tmp_path, "site/site/settings.py", "INSTALLED_APPS = ['shop']\nDEBUG = False\n")
    for name in ("tests_settings", "ci_settings", "settings_test", "testing", "local"):
        write(tmp_path, f"site/site/{name}.py", apps)
    write(tmp_path, "site/tests/settings.py", apps)
    write(tmp_path, "site/jsapp/settings.py", apps)
    write(tmp_path, "site/jsapp/LICENSE", "MIT\n")
    write(tmp_path, "site/jsapp/views.py", "def view(request):\n    return None\n")
    assert findings_for(tmp_path, "baseline", "BASE-DEBUG-ON") == []


def test_django_debug_in_a_local_module_counts_when_it_is_the_only_one(tmp_path):
    write(tmp_path, "site/settings/local.py", "INSTALLED_APPS = ['shop']\nDEBUG = True\n")
    found = findings_for(tmp_path, "baseline", "BASE-DEBUG-ON")
    assert locs(found) == [("site/settings/local.py:2", "high")]
