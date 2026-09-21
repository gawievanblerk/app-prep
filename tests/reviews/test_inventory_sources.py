from dpr import reviews, rules
from dpr.discovery.detect import detect
from dpr.reviews.inventory_sources import collection_points
from dpr.walk import RepoIndex
from tests.reviews.helpers import findings_for, write


def context(root):
    reviews.available()
    index = RepoIndex(root)
    return rules.Context(index=index, detection=detect(index))


def test_collection_points_from_request_schemas_and_body_reads(tmp_path):
    write(
        tmp_path,
        "api/schemas.py",
        "class ContactBase(BaseModel):\n    email: str\n    phone: str | None = None\n"
        "class ClientCreate(ContactBase):\n    name: str\n    crop_year: int\n",
    )
    write(
        tmp_path,
        "api/routes.py",
        "from fastapi import APIRouter\nrouter = APIRouter()\n"
        "@router.post('/clients')\nasync def create(data: ClientCreate, user: CurrentUser): ...\n"
        "@router.get('/clients')\nasync def listing(user: CurrentUser): ...\n",
    )
    write(
        tmp_path,
        "web/app.py",
        "from flask import Flask, request\napp = Flask(__name__)\n"
        "@app.route('/contact', methods=['POST'])\ndef contact():\n"
        "    return save(request.form['email'], request.form.get('message'))\n",
    )
    write(
        tmp_path,
        "server/signup.js",
        "router.post('/signup', async (req, res) => {\n"
        "  const { email, fullName } = req.body\n  res.json({ ip: req.ip })\n})\n",
    )
    points = {
        (c.route.method, c.route.path) if c.route else c.fields[0]: c
        for c in collection_points(context(tmp_path))
    }
    assert points[("POST", "/clients")].fields == ("name", "email", "phone")
    assert points[("POST", "/clients")].source == "ClientCreate"
    assert points[("POST", "/contact")].fields == ("email", "message")
    assert points[("POST", "/signup")].fields == ("email", "fullName")
    assert str(points["IP address"].location) == "server/signup.js:3"
    assert ("GET", "/clients") not in points


EMAIL_SERVICE = (
    "import logging\n\nclass EmailService:\n"
    "    def __init__(self, conn):\n"
    "        from azure.communication.email import EmailClient\n"
    "        self.client = EmailClient.from_connection_string(conn)\n\n"
    "    def send(self, to_email, to_name, html):\n"
    "        message = {\n"
    "            'senderAddress': 'noreply@example.invalid',\n"
    "            'recipients': {'to': [{'address': to_email, 'displayName': to_name}]},\n"
    "            'content': {'html': html},\n"
    "        }\n"
    "        return self.client.begin_send(message)\n"
)


def test_email_provider_receiving_recipient_fields_is_confirmed(tmp_path):
    write(tmp_path, "requirements.txt", "azure-communication-email\n")
    write(tmp_path, "app/email.py", EMAIL_SERVICE)
    [finding] = findings_for(tmp_path, "inventory", "INV-SDK-RECEIVES-PII")
    assert (finding.tag.value, str(finding.locations[0])) == ("CONFIRMED", "app/email.py:14")
    assert "identifying fields (recipients, to, address, displayName)" in finding.detail
    assert "senderAddress" not in finding.detail


def test_llm_prompts_are_inferred_and_constructor_keys_do_not_count(tmp_path):
    write(tmp_path, "requirements.txt", "anthropic\n")
    write(
        tmp_path,
        "app/chat.py",
        "import anthropic\n\ndef ask(messages, context):\n"
        "    client = anthropic.Anthropic(api_key=KEY)\n"
        "    return client.messages.create(model='m', system=context, messages=messages)\n",
    )
    [finding] = findings_for(tmp_path, "inventory", "INV-SDK-RECEIVES-PII")
    assert (finding.tag.value, finding.detail.split(". ")[0]) == (
        "INFERRED",
        "Calls to anthropic (llm) pass free text or prompts (system, messages)",
    )
    assert [str(loc) for loc in finding.locations] == ["app/chat.py:5"]


def test_javascript_mail_and_whole_user_objects(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"nodemailer": "6", "posthog-node": "4"}}')
    write(
        tmp_path,
        "lib/mail.ts",
        "import nodemailer from 'nodemailer'\nconst transport = nodemailer.createTransport({ host: 'x' })\n"
        "export const send = (to, text) => transport.sendMail({ to, subject: 'Hi', text })\n",
    )
    write(
        tmp_path,
        "lib/track.ts",
        "import { PostHog } from 'posthog-node'\nconst posthog = new PostHog('key')\n"
        "export const track = (user) => posthog.capture({ distinctId: 'x', properties: user })\n",
    )
    found = {f.title: f for f in findings_for(tmp_path, "inventory", "INV-SDK-RECEIVES-PII")}
    assert found["nodemailer receives personal data"].tag.value == "CONFIRMED"
    assert set(found) == {"nodemailer receives personal data"}


def test_sdk_imported_but_called_without_personal_keys_is_not_reported(tmp_path):
    write(tmp_path, "requirements.txt", "azure-monitor-opentelemetry\n")
    write(
        tmp_path,
        "app/main.py",
        "from azure.monitor.opentelemetry import configure_azure_monitor\n"
        "configure_azure_monitor(connection_string=CONN)\n",
    )
    assert findings_for(tmp_path, "inventory", "INV-SDK-RECEIVES-PII") == []
