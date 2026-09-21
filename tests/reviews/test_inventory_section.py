from dpr.api import review
from dpr.report.markdown import render_markdown
from tests.reviews.helpers import write


def app(root):
    write(root, "api/requirements.txt", "fastapi\nsqlalchemy\nasyncpg\nazure-communication-email\n")
    write(root, ".env.example", "SENDGRID_API_KEY=\n")
    write(
        root,
        "api/app/models.py",
        "class Client(Base):\n    __tablename__ = 'clients'\n"
        "    name = Column(String)\n    email = Column(String)\n    notes = Column(Text)\n"
        "    visit_count = Column(Integer)\n    deleted = Column(Boolean)\n",
    )
    write(
        root,
        "api/app/schemas.py",
        "class ClientCreate(BaseModel):\n    name: str\n    email: str\n    notes: str\n",
    )
    write(
        root,
        "api/app/mail.py",
        "from azure.communication.email import EmailClient\n\nclass Mailer:\n"
        "    def __init__(self):\n        self.client = EmailClient.from_connection_string('x')\n\n"
        "    def welcome(self, to_email):\n"
        "        return self.client.begin_send({'recipients': {'to': [{'address': to_email}]}})\n",
    )
    write(
        root,
        "api/app/routes.py",
        "from fastapi import APIRouter\nfrom app.mail import Mailer\nrouter = APIRouter()\n"
        "ManagerOrAdmin = Annotated[User, Depends(require_manager)]\n\n"
        "@router.post('/clients')\n"
        "async def create_client(data: ClientCreate, user: ManagerOrAdmin, request: Request):\n"
        "    Mailer().welcome(data.email)\n"
        "    logger.info('created for %s from %s', data.email, request.client.host)\n"
        "    return await save(Client(**data.model_dump()))\n\n"
        "@router.get('/clients/{client_id}')\n"
        "async def read_client(client_id: str, user: ManagerOrAdmin):\n"
        "    return await db.get(Client, client_id)\n",
    )
    write(
        root,
        "infra/main.tf",
        'variable "location" {\n  default = "westeurope"\n}\n'
        'resource "azurerm_postgresql_flexible_server" "db" {\n  backup_retention_days = 14\n}\n',
    )
    return root


def parts(report):
    return {p.title: p for p in report.sections["inventory"].parts}


def test_inventory_section_parts_and_map_row(tmp_path):
    report = review(app(tmp_path))
    found = parts(report)
    assert list(found) == [
        "How to read this inventory",
        "Personal data map",
        "Categories checked",
        "Data flows",
        "Collected with no clear reason",
        "Not covered by this repo",
        "Findings",
    ]
    [row] = [r for r in found["Personal data map"].rows if r[0].startswith("clients:")]
    assert row[0] == "clients: `name`, `email`, `notes`"
    assert row[1] == "Contact and identity, Free text and content"
    assert row[2] == "POST /clients (`api/app/routes.py:7`)"
    assert row[3].startswith(
        "table clients (postgres); backups per Terraform: backup_retention_days = 14"
    )
    assert row[4] == "azure-communication-email (INFERRED, reached from the collecting route)"
    assert row[5] == "soft delete flag only, rows kept; retained indefinitely"
    assert row[6] == "authenticated: Depends(require_manager); database administrators UNKNOWN"
    assert row[7] == "`api/app/models.py:1` CONFIRMED"
    runtime = [r for r in found["Personal data map"].rows if r[0] == "IP address"]
    assert runtime and runtime[0][2] == "captured from requests: `api/app/routes.py:9`"


def test_flows_reasons_and_outside_systems(tmp_path):
    found = parts(review(app(tmp_path)))
    assert (
        "- POST /clients (`api/app/routes.py:7`) -> clients -> azure-communication-email"
        in found["Data flows"].body
    )
    assert "Free-text fields that invite more than the product needs: clients.notes" in (
        found["Collected with no clear reason"].body
    )
    assert "- sendgrid is configured by SENDGRID_API_KEY, but no call site was found in code" in (
        found["Not covered by this repo"].body
    )
    assert "- Special category: none found by field name" in found["Categories checked"].body


def test_answered_by_this_review(tmp_path):
    report = review(app(tmp_path))
    questions = {a.question: a for a in report.answered}
    assert (
        "Contact and identity (clients)"
        in questions["What personal data does the code hold?"].answer
    )
    where = questions["Where does it live?"].answer
    assert "region per Terraform defaults: westeurope (`infra/main.tf:2`), not verified" in where
    assert questions["Is there a path for access or deletion requests?"].answer.startswith(
        "No export"
    )
    assert questions["Is access to personal data logged?"].answer.startswith("No audit")
    text = render_markdown(report)
    answered = text[text.index("### Answered by this review") : text.index("### Still open")]
    assert "- What retention does the code enforce? 0 of 1 personal data tables" in answered
