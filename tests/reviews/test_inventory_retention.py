from dpr import reviews, rules
from dpr.api import review
from dpr.cli import main
from dpr.discovery.detect import detect
from dpr.report.json_out import render_json
from dpr.report.markdown import render_markdown
from dpr.report.sarif import render_sarif
from dpr.reviews.inventory_retention import iac_retention, readers, retention_text
from dpr.walk import RepoIndex
from tests.reviews.helpers import findings_for, write

PERSONAL_VALUES = (
    "Ada",
    "Example",
    "ada@example.invalid",
    "Ben",
    "ben@example.invalid",
    "000-000-0000",
    "000-000-0001",
)

MODELS = (
    "class Client(Base):\n    __tablename__ = 'clients'\n"
    "    email = Column(String)\n    phone = Column(String)\n\n"
    "class Note(SoftDeleteMixin, Base):\n    __tablename__ = 'notes'\n"
    "    client_id = Column(String)\n    content = Column(Text)\n\n"
    "class Lead(Base):\n    __tablename__ = 'leads'\n"
    "    email = Column(String)\n    deleted = Column(Boolean)\n"
)
SERVICE = (
    "class ClientService:\n"
    "    async def delete_client(self, client_id):\n"
    "        result = await self.db.execute(select(Client).where(Client.id == client_id))\n"
    "        client = result.scalar_one_or_none()\n"
    "        await self.db.delete(client)\n\n"
    "    async def delete_lead_note(self, lead_id, note):\n"
    "        lead = await self.db.get(Lead, lead_id)\n"
    "        await self.db.delete(note)\n"
)


def app(root):
    write(root, "api/requirements.txt", "fastapi\n")
    write(root, "api/app/models.py", MODELS)
    write(root, "api/app/services/clients.py", SERVICE)
    write(
        root,
        "api/app/routes.py",
        "from fastapi import APIRouter\nrouter = APIRouter()\n"
        "ManagerOrAdmin = Annotated[User, Depends(require_manager)]\n"
        "@router.get('/clients/{client_id}')\n"
        "async def read_client(client_id: str, user: ManagerOrAdmin):\n"
        "    return await db.get(Client, client_id)\n",
    )
    return root


def context(root):
    reviews.available()
    index = RepoIndex(root)
    return rules.Context(index=index, detection=detect(index))


def test_retention_text_per_model(tmp_path):
    ctx = context(app(tmp_path))
    models = {m.name: m for m in ctx.detection.models}
    assert retention_text(ctx, models["Client"]) == (
        "hard delete available (`api/app/services/clients.py:5`)"
    )
    assert retention_text(ctx, models["Note"]).startswith("soft delete flag only")
    assert retention_text(ctx, models["Lead"]).startswith("soft delete flag only")


def test_no_deletion_path_groups_models_per_app(tmp_path):
    app(tmp_path)
    [finding] = findings_for(tmp_path, "inventory", "INV-NO-DELETION-PATH")
    assert finding.tag.value == "INFERRED"
    assert finding.title == "Personal data in api has no deletion path"
    assert [str(loc) for loc in finding.locations] == [
        "api/app/models.py:11",
        "api/app/models.py:6",
    ]
    assert "Lead, Note only set a soft delete flag" in finding.detail


def test_deletion_evidence_does_not_cross_app_roots(tmp_path):
    write(tmp_path, "root_a/requirements.txt", "fastapi\n")
    write(
        tmp_path,
        "root_a/app/models.py",
        "class User(Base):\n    __tablename__ = 'users'\n    email = Column(String)\n",
    )
    write(tmp_path, "root_b/requirements.txt", "fastapi\n")
    write(
        tmp_path,
        "root_b/app/models.py",
        "class User(Base):\n    __tablename__ = 'users'\n    email = Column(String)\n",
    )
    write(
        tmp_path,
        "root_b/app/services.py",
        "class UserService:\n"
        "    async def delete_user(self, user_id):\n"
        "        user = await self.db.get(User, user_id)\n"
        "        await self.db.delete(user)\n",
    )
    titles = {f.title for f in findings_for(tmp_path, "inventory", "INV-NO-DELETION-PATH")}
    assert "Personal data in root_a has no deletion path" in titles
    assert "Personal data in root_b has no deletion path" not in titles


def test_no_deletion_path_puts_person_models_before_the_location_cap(tmp_path):
    notes = "".join(
        f"class Note{i}(Base):\n    __tablename__ = 'notes{i}'\n"
        "    user_id = Column(String)\n    ip = Column(String)\n\n"
        for i in range(1, 11)
    )
    write(tmp_path, "requirements.txt", "fastapi\n")
    write(tmp_path, "app/notes.py", notes)
    write(
        tmp_path,
        "app/user.py",
        "class User(Base):\n    __tablename__ = 'users'\n    email = Column(String)\n",
    )
    [finding] = findings_for(tmp_path, "inventory", "INV-NO-DELETION-PATH")
    assert len(finding.locations) == 10
    assert str(finding.locations[0]) == "app/user.py:1"
    assert "User" in finding.detail


def test_readers_from_route_access(tmp_path):
    ctx = context(app(tmp_path))
    client = next(m for m in ctx.detection.models if m.name == "Client")
    assert readers(ctx, client).startswith("authenticated: Depends(require_manager)")
    lead = next(m for m in ctx.detection.models if m.name == "Lead")
    assert readers(ctx, lead).startswith("no read route names this model")


def test_terraform_backup_and_log_retention(tmp_path):
    write(
        tmp_path,
        "infra/main.tf",
        'resource "azurerm_postgresql_flexible_server" "db" {\n'
        "  backup_retention_days        = 7\n  geo_redundant_backup_enabled = false\n}\n"
        'resource "azurerm_log_analytics_workspace" "logs" {\n  retention_in_days = 30\n}\n'
        'resource "azurerm_linux_web_app" "api" {\n  logs {\n    http_logs {\n'
        "      file_system {\n        retention_in_days = 7\n      }\n    }\n  }\n}\n",
    )
    found = [(r, s, str(loc)) for r, s, loc in iac_retention(context(tmp_path))]
    assert found == [
        ("azurerm_postgresql_flexible_server db", "backup_retention_days = 7", "infra/main.tf:2"),
        (
            "azurerm_postgresql_flexible_server db",
            "geo_redundant_backup_enabled = false",
            "infra/main.tf:3",
        ),
        ("azurerm_log_analytics_workspace logs", "retention_in_days = 30", "infra/main.tf:6"),
        ("azurerm_linux_web_app api", "retention_in_days = 7", "infra/main.tf:12"),
    ]


def test_unused_personal_fields(tmp_path):
    write(
        tmp_path,
        "app/models.py",
        "class Insured(Base):\n    __tablename__ = 'insureds'\n"
        "    email = Column(String)\n    status_note = Column(String)\n    home_phone = Column(String)\n",
    )
    write(
        tmp_path,
        "app/importer.py",
        "def apply(insured, row):\n    insured.status_note = row['note']\n"
        "    insured.home_phone = row['phone']\n",
    )
    write(
        tmp_path, "app/views.py", "def show(insured):\n    return {'phone': insured.home_phone}\n"
    )
    [finding] = findings_for(tmp_path, "inventory", "INV-UNUSED-FIELD")
    assert finding.title == "Personal fields of Insured that no code reads"
    assert [str(loc) for loc in finding.locations] == ["app/models.py:4"]


def test_personal_data_files_committed(tmp_path):
    write(tmp_path, "exports/customers.csv", "first_name,email,plan\nA,a@example.invalid,x\n")
    write(tmp_path, "data/leads.json", '[{"full_name": "A", "phone": "0", "source": "web"}]')
    write(tmp_path, "data/products.csv", "sku,price\n1,2\n")
    write(tmp_path, "web/package.json", '{"name": "web", "author": "x", "email": "y"}')
    found = sorted(
        str(f.locations[0]) for f in findings_for(tmp_path, "inventory", "INV-PII-FILE-IN-REPO")
    )
    assert found == ["data/leads.json:1", "exports/customers.csv:1"]


def test_personal_values_in_a_data_file_never_reach_any_output(tmp_path, capsys):
    root = tmp_path / "repo"
    write(
        root,
        "exports/customers.csv",
        "first_name,last_name,email,phone\n"
        "Ada,Example,ada@example.invalid,000-000-0000\n"
        "Ben,Example,ben@example.invalid,000-000-0001\n",
    )
    write(root, "app/requirements.txt", "fastapi\n")
    write(root, "app/main.py", "app = None\n")
    report = review(root)
    [finding] = [f for f in report.findings if f.rule_id == "INV-PII-FILE-IN-REPO"]
    assert [str(loc) for loc in finding.locations] == ["exports/customers.csv:1"]
    outputs = [
        render_markdown(report),
        render_json(report),
        render_sarif(report),
        repr(report.findings),
    ]
    out_dir = tmp_path / "out"
    assert main(["scan", str(root), "--format", "md,json,sarif", "--out", str(out_dir)]) == 0
    outputs += [p.read_text() for p in out_dir.iterdir()]
    captured = capsys.readouterr()
    outputs += [captured.out, captured.err]
    for value in PERSONAL_VALUES:
        for text in outputs:
            assert value not in text
