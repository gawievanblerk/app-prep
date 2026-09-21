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


def test_sdk_recipient_findings_are_scoped_per_app_root(tmp_path):
    write(tmp_path, "app-a/requirements.txt", "openai\n")
    write(
        tmp_path,
        "app-a/app.py",
        "import openai\n\nclient = openai.OpenAI()\n\n\n"
        "def ask(prompt):\n"
        "    return client.chat.completions.create(\n"
        "        model='m', messages=[{'role': 'user', 'content': prompt}]\n    )\n",
    )
    write(tmp_path, "app-b/requirements.txt", "openai\n")
    write(
        tmp_path,
        "app-b/app.py",
        "import openai\n\nclient = openai.OpenAI()\n\n\n"
        "def notify(to_email):\n    return client.emails.send(to=to_email)\n",
    )
    findings = findings_for(tmp_path, "inventory", "INV-SDK-RECEIVES-PII")
    by_tag = {f.tag.value: f for f in findings}
    assert set(by_tag) == {"INFERRED", "CONFIRMED"}
    assert [str(loc) for loc in by_tag["INFERRED"].locations] == ["app-a/app.py:7"]
    assert [str(loc) for loc in by_tag["CONFIRMED"].locations] == ["app-b/app.py:7"]


EMAIL_SERVICE_INDIRECT = (
    "import logging\n\nclass EmailService:\n"
    "    def __init__(self, conn):\n"
    "        from azure.communication.email import EmailClient\n"
    "        self.client = EmailClient.from_connection_string(conn)\n\n"
    "    def _send(self, message):\n"
    "        return self.client.begin_send(message)\n\n"
    "    def send(self, to_email, to_name, html):\n"
    "        message = {\n"
    "            'senderAddress': 'noreply@example.invalid',\n"
    "            'recipients': {'to': [{'address': to_email, 'displayName': to_name}]},\n"
    "            'content': {'html': html},\n"
    "        }\n"
    "        return self._send(message)\n"
)


def test_dict_built_in_one_method_and_sent_from_another_is_confirmed(tmp_path):
    write(tmp_path, "requirements.txt", "azure-communication-email\n")
    write(tmp_path, "app/email.py", EMAIL_SERVICE_INDIRECT)
    [finding] = findings_for(tmp_path, "inventory", "INV-SDK-RECEIVES-PII")
    assert (finding.tag.value, str(finding.locations[0])) == ("CONFIRMED", "app/email.py:9")
    assert "identifying fields (recipients, to, address, displayName)" in finding.detail


def test_zod_schema_parsed_from_request_body_is_collected(tmp_path):
    write(
        tmp_path,
        "app/api/signup/route.ts",
        "import { z } from 'zod'\n\n"
        "const SignupSchema = z.object({\n  email: z.string().email(),\n  fullName: z.string(),\n})\n\n"
        "export async function POST(req: Request) {\n"
        "  const body = await req.json()\n"
        "  const data = SignupSchema.parse(body)\n"
        "  return Response.json({ ok: true })\n"
        "}\n",
    )
    write(
        tmp_path,
        "lib/internal.ts",
        "import { z } from 'zod'\n\nconst ConfigSchema = z.object({\n  region: z.string(),\n})\n"
        "export const config = ConfigSchema.parse(process.env)\n",
    )
    points = collection_points(context(tmp_path))
    zod = [c for c in points if c.source == "SignupSchema"]
    assert len(zod) == 1
    assert zod[0].fields == ("email", "fullName")
    assert not any(c.source == "ConfigSchema" for c in points)


THREAD_RUNNER_SERVICE = (
    "import logging\n\nclass EmailService:\n"
    "    def __init__(self, conn):\n"
    "        from azure.communication.email import EmailClient\n"
    "        self.client = EmailClient.from_connection_string(conn)\n\n"
    "    def _dispatch(self, message):\n"
    "        return self.client.begin_send(message).result()\n\n"
    "    async def send(self, to_email, to_name, html):\n"
    "        message = {\n"
    "            'senderAddress': 'noreply@example.invalid',\n"
    "            'recipients': {'to': [{'address': to_email, 'displayName': to_name}]},\n"
    "            'content': {'html': html},\n"
    "        }\n"
    "        return await to_thread.run_sync(self._dispatch, message)\n"
)


def test_method_passed_to_thread_runner_is_followed_for_sent_dicts(tmp_path):
    write(tmp_path, "requirements.txt", "azure-communication-email\n")
    write(tmp_path, "app/email.py", THREAD_RUNNER_SERVICE)
    [finding] = findings_for(tmp_path, "inventory", "INV-SDK-RECEIVES-PII")
    assert (finding.tag.value, str(finding.locations[0])) == ("CONFIRMED", "app/email.py:9")
    assert "identifying fields (recipients, to, address, displayName)" in finding.detail


EXECUTOR_SERVICE = (
    "import logging\n\nclass EmailService:\n"
    "    def __init__(self, conn):\n"
    "        from azure.communication.email import EmailClient\n"
    "        self.client = EmailClient.from_connection_string(conn)\n\n"
    "    def _dispatch(self, message):\n"
    "        return self.client.begin_send(message).result()\n\n"
    "    async def send(self, to_email, to_name, html):\n"
    "        message = {\n"
    "            'senderAddress': 'noreply@example.invalid',\n"
    "            'recipients': {'to': [{'address': to_email, 'displayName': to_name}]},\n"
    "            'content': {'html': html},\n"
    "        }\n"
    "        return await loop.run_in_executor(None, self._dispatch, message)\n"
)


def test_method_passed_to_run_in_executor_is_followed_for_sent_dicts(tmp_path):
    write(tmp_path, "requirements.txt", "azure-communication-email\n")
    write(tmp_path, "app/email.py", EXECUTOR_SERVICE)
    [finding] = findings_for(tmp_path, "inventory", "INV-SDK-RECEIVES-PII")
    assert (finding.tag.value, str(finding.locations[0])) == ("CONFIRMED", "app/email.py:9")
    assert "identifying fields (recipients, to, address, displayName)" in finding.detail
