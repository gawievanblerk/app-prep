from dpr.discovery.detect import detect
from dpr.walk import RepoIndex
from tests.reviews.helpers import write


def test_ci_from_azure_gitlab_and_github(tmp_path):
    write(tmp_path, "azure-pipelines.yml", "trigger: [main]\n")
    write(tmp_path, ".gitlab-ci.yml", "stages: [test]\n")
    write(tmp_path, ".github/workflows/ci.yml", "on: push\n")
    write(tmp_path, "docs/azure-pipelines.yml", "copied example\n")
    d = detect(RepoIndex(tmp_path))
    assert d.ci == [".github/workflows/ci.yml", ".gitlab-ci.yml", "azure-pipelines.yml"]


def test_no_ci_files(tmp_path):
    write(tmp_path, "app.py", "x = 1\n")
    assert detect(RepoIndex(tmp_path)).ci == []


def test_hosting_from_terraform_resource_types(tmp_path):
    write(
        tmp_path,
        "infra/main.tf",
        'resource "azurerm_linux_web_app" "api" {\n}\n'
        'resource "azurerm_static_web_app" "web" {\n}\n'
        'resource "aws_lambda_function" "job" {\n}\n',
    )
    d = detect(RepoIndex(tmp_path))
    assert d.hosting == ["azure-app-service", "azure-static-web-apps", "aws-lambda", "terraform"]
    assert d.serverless is True


def test_resource_names_in_comments_or_data_blocks_do_not_count(tmp_path):
    write(
        tmp_path,
        "infra/main.tf",
        '# resource "azurerm_linux_web_app" was removed\ndata "aws_lambda_function" "x" {\n}\n',
    )
    assert detect(RepoIndex(tmp_path)).hosting == ["terraform"]


def test_static_web_app_config_means_azure_static_web_apps(tmp_path):
    write(tmp_path, "web/staticwebapp.config.json", "{}")
    assert detect(RepoIndex(tmp_path)).hosting == ["azure-static-web-apps"]


def test_procfile_is_not_heroku_when_another_platform_is_configured(tmp_path):
    write(tmp_path, "api/Procfile", "web: gunicorn app:app\n")
    write(tmp_path, "render.yaml", "services: []\n")
    write(tmp_path, "api/Dockerfile", "FROM python\n")
    assert detect(RepoIndex(tmp_path)).hosting == ["render", "docker"]


def test_lone_procfile_still_means_heroku(tmp_path):
    write(tmp_path, "Procfile", "web: gunicorn app:app\n")
    write(tmp_path, "Dockerfile", "FROM python\n")
    assert detect(RepoIndex(tmp_path)).hosting == ["heroku", "docker"]


def test_custom_jwt_needs_a_token_library_and_a_password_hasher(tmp_path):
    write(tmp_path, "requirements.txt", "fastapi\npython-jose[cryptography]\npasslib[bcrypt]\n")
    write(tmp_path, "app/main.py", "x = 1\n")
    assert detect(RepoIndex(tmp_path)).auth_providers == ["custom-jwt"]


def test_token_library_alone_is_not_custom_jwt(tmp_path):
    write(tmp_path, "requirements.txt", "fastapi\npyjwt\n")
    write(tmp_path, "app/main.py", "x = 1\n")
    assert detect(RepoIndex(tmp_path)).auth_providers == []


def test_managed_provider_wins_over_custom_jwt(tmp_path):
    write(
        tmp_path,
        "package.json",
        '{"dependencies": {"@clerk/nextjs": "5", "jsonwebtoken": "9", "bcryptjs": "2"}}',
    )
    write(tmp_path, "app/page.tsx", "export default function P() { return null }\n")
    assert detect(RepoIndex(tmp_path)).auth_providers == ["clerk"]


def test_python_azure_sdks_are_catalogued_with_import_sites(tmp_path):
    write(
        tmp_path,
        "requirements.txt",
        "azure-communication-email>=1\nazure-storage-blob\nazure-monitor-opentelemetry\n"
        "chromadb\nweasyprint\n",
    )
    write(
        tmp_path,
        "app/email.py",
        "import logging\n\n\ndef client(conn):\n"
        "    from azure.communication.email import EmailClient\n"
        "    return EmailClient.from_connection_string(conn)\n",
    )
    write(
        tmp_path, "app/main.py", "from azure.monitor.opentelemetry import configure_azure_monitor\n"
    )
    d = detect(RepoIndex(tmp_path))
    by_name = {s.name: s for s in d.sdks}
    assert set(by_name) == {
        "azure-communication-email",
        "azure-storage-blob",
        "azure-monitor",
        "chromadb",
        "weasyprint",
    }
    email = by_name["azure-communication-email"]
    assert (email.category, email.recipient, email.paid) == ("email", True, True)
    assert [str(loc) for loc in email.locations] == ["app/email.py:5"]
    assert [str(loc) for loc in by_name["azure-monitor"].locations] == ["app/main.py:1"]
    assert by_name["weasyprint"].paid is False


def test_google_fonts_link_in_html_is_a_browser_recipient(tmp_path):
    write(
        tmp_path,
        "web/index.html",
        "<html><head>\n"
        '<link href="https://fonts.googleapis.com/css2?family=Inter" rel="stylesheet">\n'
        "</head></html>\n",
    )
    write(tmp_path, "web/src/main.ts", "export {}\n")
    [fonts] = detect(RepoIndex(tmp_path)).sdks
    assert (fonts.name, fonts.recipient) == ("google-fonts", True)
    assert [str(loc) for loc in fonts.locations] == ["web/index.html:2"]


def test_self_hosted_fonts_are_not_google_fonts(tmp_path):
    write(tmp_path, "web/index.html", '<link href="/fonts/inter.css" rel="stylesheet">\n')
    assert detect(RepoIndex(tmp_path)).sdks == []
