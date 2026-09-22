from tests.reviews.helpers import findings_for, write


def next_app(root):
    write(root, "package.json", '{"dependencies": {"next": "14", "openai": "4"}}')
    write(
        root,
        "lib/ai.ts",
        "import OpenAI from 'openai'\nconst client = new OpenAI()\n"
        "export async function generate(prompt: string) {\n  return client.chat.completions.create({ messages: [] })\n}\n",
    )
    write(
        root,
        "app/api/generate/route.ts",
        "import { generate } from '@/lib/ai'\n"
        "export async function POST(req: Request) {\n  return Response.json(await generate('x'))\n}\n",
    )
    write(
        root,
        "app/api/chat/route.ts",
        "import OpenAI from 'openai'\nconst openai = new OpenAI()\n"
        "export async function POST(req: Request) {\n  const session = await auth()\n"
        "  if (process.env.CHAT_ENABLED !== 'true') return new Response(null, { status: 503 })\n"
        "  const { success } = await ratelimit.limit(session.user.id)\n"
        "  return Response.json(await openai.chat.completions.create({ messages: [] }))\n}\n",
    )
    write(
        root,
        "app/api/signup/route.ts",
        "export async function POST(req: Request) {\n  return Response.json({})\n}\n",
    )
    write(
        root,
        "app/api/contact/route.ts",
        "export async function POST(req: Request) {\n  await verifyTurnstile(req)\n  return Response.json({})\n}\n",
    )
    return root


def locs(found):
    return sorted(str(f.locations[0]) for f in found)


def test_paid_routes_auth_limits_and_kill_switch(tmp_path):
    root = next_app(tmp_path)
    [unauth] = findings_for(root, "abuse", "ABUSE-PAID-UNAUTH")
    assert str(unauth.locations[0]) == "app/api/generate/route.ts:2"
    assert unauth.title == "POST /api/generate calls openai with no sign-in"
    assert "through generate()" in unauth.detail and "tokens per call" in unauth.detail
    [unlimited] = findings_for(root, "abuse", "ABUSE-PAID-UNLIMITED")
    assert str(unlimited.locations[0]) == "app/api/generate/route.ts:2"
    assert "20 per user and 40 per IP per 1 h" in unlimited.fix
    [switch] = findings_for(root, "abuse", "ABUSE-NO-KILL-SWITCH")
    assert "API_GENERATE_ENABLED" in switch.fix


def test_python_paid_route_through_helper(tmp_path):
    write(tmp_path, "requirements.txt", "fastapi\nanthropic\nslowapi\n")
    write(
        tmp_path,
        "app/chat.py",
        "async def relay_chat(messages):\n    import anthropic\n"
        "    client = anthropic.Anthropic()\n    return client.messages.create(messages=messages)\n",
    )
    write(
        tmp_path,
        "app/routes.py",
        "from fastapi import APIRouter, Depends\nrouter = APIRouter()\n"
        "@router.post('/chat')\nasync def chat(user=Depends(get_current_user)):\n"
        "    from app.chat import relay_chat\n    return await relay_chat([])\n"
        "@router.post('/limited')\n@limiter.limit('5/minute')\nasync def limited(user=Depends(get_current_user)):\n"
        "    return await relay_chat([])\n",
    )
    assert findings_for(tmp_path, "abuse", "ABUSE-PAID-UNAUTH") == []
    assert locs(findings_for(tmp_path, "abuse", "ABUSE-PAID-UNLIMITED")) == ["app/routes.py:4"]
    write(
        tmp_path,
        "app/main.py",
        "from slowapi.middleware import SlowAPIMiddleware\napp.add_middleware(SlowAPIMiddleware)\n",
    )
    assert findings_for(tmp_path, "abuse", "ABUSE-PAID-UNLIMITED") == []


def test_public_forms_without_challenge(tmp_path):
    root = next_app(tmp_path)
    write(
        root,
        "api/auth.py",
        "from fastapi import APIRouter, Depends\nrouter = APIRouter(prefix='/auth')\n"
        "@router.post('/register')\nasync def register(data): ...\n"
        "@router.post('/forgot-password')\nasync def forgot(data): ...\n"
        "@router.post('/logout')\nasync def logout(): ...\n"
        "@router.post('/register/admin')\nasync def admin_register(boss=Depends(get_admin_user)): ...\n",
    )
    found = {f.locations[0].file: f for f in findings_for(root, "abuse", "ABUSE-FORM-NO-CHALLENGE")}
    assert set(found) == {"api/auth.py", "app/api/signup/route.ts"}
    assert [str(loc) for loc in found["api/auth.py"].locations] == [
        "api/auth.py:4",
        "api/auth.py:6",
    ]
    assert "POST /auth/register, POST /auth/forgot-password" in found["api/auth.py"].detail


def fastapi_paid(root, main_extra=""):
    write(root, "requirements.txt", "fastapi\nopenai\n")
    write(
        root,
        "app/main.py",
        "from fastapi import FastAPI\nfrom openai import OpenAI\nfrom app.middleware import AuthMiddleware\n"
        f"app = FastAPI()\nclient = OpenAI()\n{main_extra}"
        "@app.post('/generate')\ndef generate(prompt: str):\n"
        "    return client.responses.create(model='x', input=prompt)\n",
    )
    return root


def test_paid_unauth_is_inferred_when_a_global_auth_mechanism_cannot_be_read(tmp_path):
    plain = fastapi_paid(
        tmp_path / "plain", "app.add_middleware(CORSMiddleware, allow_origins=['x'])\n"
    )
    [confirmed] = findings_for(plain, "abuse", "ABUSE-PAID-UNAUTH")
    assert confirmed.tag.value == "CONFIRMED"

    guarded = fastapi_paid(tmp_path / "guarded", "app.add_middleware(AuthMiddleware)\n")
    [inferred] = findings_for(guarded, "abuse", "ABUSE-PAID-UNAUTH")
    assert inferred.tag.value == "INFERRED"
    assert "AuthMiddleware" in inferred.proof_needed

    hook = fastapi_paid(
        tmp_path / "hook",
        "@app.middleware('http')\nasync def check(request, call_next):\n"
        "    if not request.headers.get('authorization'):\n        return JSONResponse({}, status_code=401)\n"
        "    return await call_next(request)\n",
    )
    [hooked] = findings_for(hook, "abuse", "ABUSE-PAID-UNAUTH")
    assert hooked.tag.value == "INFERRED"


def test_express_unknown_app_middleware_makes_paid_unauth_inferred(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"express": "4", "openai": "4"}}')
    write(
        tmp_path,
        "server.js",
        "const express = require('express')\nconst OpenAI = require('openai')\n"
        "const { clerkMiddleware } = require('@clerk/express')\n"
        "const app = express()\nconst ai = new OpenAI()\n"
        "app.use(express.json())\napp.use(clerkMiddleware())\n"
        "app.post('/generate', async (req, res) => {\n"
        "  res.json(await ai.chat.completions.create({ model: 'x', messages: req.body.messages }))\n"
        "})\n",
    )
    [finding] = findings_for(tmp_path, "abuse", "ABUSE-PAID-UNAUTH")
    assert finding.tag.value == "INFERRED"
    assert "clerkMiddleware" in finding.proof_needed


def test_method_calls_on_objects_are_not_paid_helpers(tmp_path):
    write(tmp_path, "requirements.txt", "fastapi\nboto3\n")
    write(
        tmp_path,
        "app/storage.py",
        "import boto3\n\ns3 = boto3.client('s3')\n\nclass Storage:\n"
        "    def get(self, key):\n        return s3.get_object(Bucket='b', Key=key)\n",
    )
    write(
        tmp_path,
        "app/main.py",
        "from fastapi import FastAPI, Request\napp = FastAPI()\n\n"
        "@app.post('/contact-preferences')\nasync def prefs(request: Request):\n"
        "    data = await request.json()\n    return {'theme': data.get('theme', 'light')}\n",
    )
    assert findings_for(tmp_path, "abuse", "ABUSE-PAID-UNAUTH") == []


def test_helpers_are_followed_only_through_the_callers_imports(tmp_path):
    write(tmp_path, "requirements.txt", "fastapi\nresend\n")
    write(
        tmp_path,
        "app/mailer.py",
        "import resend\n\ndef send(to, body):\n    resend.Emails.send({'to': to, 'html': body})\n",
    )
    write(
        tmp_path,
        "app/ws.py",
        "class Manager:\n    async def send(self, text):\n        return text\nmanager = Manager()\n",
    )
    write(
        tmp_path,
        "app/main.py",
        "from fastapi import FastAPI\nfrom app.ws import manager\napp = FastAPI()\n\n"
        "@app.post('/echo')\nasync def echo(text: str):\n    await manager.send(text)\n    return {}\n",
    )
    assert findings_for(tmp_path, "abuse", "ABUSE-PAID-UNAUTH") == []
    write(
        tmp_path,
        "app/notify.py",
        "from fastapi import APIRouter\nfrom app import mailer\nfrom app.mailer import send\n"
        "router = APIRouter()\n"
        "@router.post('/announce')\nasync def announce(email: str):\n    send(email, 'hi')\n"
        "@router.post('/remind')\nasync def remind(email: str):\n    mailer.send(email, 'hi')\n",
    )
    found = findings_for(tmp_path, "abuse", "ABUSE-PAID-UNAUTH")
    assert sorted((str(f.locations[0]), f.tag.value) for f in found) == [
        ("app/notify.py:6", "CONFIRMED"),
        ("app/notify.py:9", "CONFIRMED"),
    ]


def test_sdk_names_are_read_per_file(tmp_path):
    write(tmp_path, "requirements.txt", "fastapi\ntwilio\nhttpx\n")
    write(
        tmp_path,
        "app/notify.py",
        "from twilio.rest import Client\n\ndef text_owner(body):\n"
        "    Client().messages.create(to='+1', from_='+2', body=body)\n",
    )
    write(
        tmp_path,
        "app/main.py",
        "import httpx\nfrom fastapi import FastAPI\napp = FastAPI()\n\n"
        "@app.get('/weather')\ndef weather():\n    with httpx.Client() as http:\n"
        "        return http.get('https://api.weather.example/today').json()\n",
    )
    assert findings_for(tmp_path, "abuse", "ABUSE-PAID-UNAUTH") == []
    write(
        tmp_path,
        "app/both.py",
        "import httpx\nfrom fastapi import APIRouter\nfrom twilio.rest import Client\n"
        "router = APIRouter()\n"
        "@router.get('/proxy')\ndef proxy():\n    return httpx.Client().get('https://example.invalid')\n",
    )
    assert findings_for(tmp_path, "abuse", "ABUSE-PAID-UNAUTH") == []


def test_paid_call_reached_by_name_only_is_inferred(tmp_path):
    write(tmp_path, "requirements.txt", "fastapi\nopenai\n")
    write(
        tmp_path,
        "packages/llm/complete.py",
        "from openai import OpenAI\nclient = OpenAI()\n"
        "def complete(prompt):\n    return client.responses.create(model='x', input=prompt)\n",
    )
    write(
        tmp_path,
        "app/main.py",
        "from fastapi import FastAPI\nfrom llm_tools import complete\napp = FastAPI()\n"
        "@app.post('/generate')\ndef generate(prompt: str):\n    return complete(prompt)\n",
    )
    [finding] = findings_for(tmp_path, "abuse", "ABUSE-PAID-UNAUTH")
    assert finding.tag.value == "INFERRED"
    assert "complete()" in finding.proof_needed


def test_js_helpers_resolve_through_imports(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"next": "14", "openai": "4"}}')
    write(
        tmp_path,
        "lib/ai.ts",
        "import OpenAI from 'openai'\nconst client = new OpenAI()\n"
        "export async function generate(prompt: string) {\n"
        "  return client.chat.completions.create({ messages: [] })\n}\n",
    )
    write(
        tmp_path,
        "lib/format.ts",
        "export function generate(value: string) {\n  return value.trim()\n}\n",
    )
    write(
        tmp_path,
        "app/api/relative/route.ts",
        "import { generate } from '../../../lib/ai'\n"
        "export async function POST() {\n  return Response.json(await generate('x'))\n}\n",
    )
    write(
        tmp_path,
        "app/api/format/route.ts",
        "import { generate } from '@/lib/format'\n"
        "export async function POST() {\n  return Response.json(generate(' x '))\n}\n",
    )
    write(
        tmp_path,
        "app/api/cache/route.ts",
        "export async function GET() {\n  const cache = new Map()\n"
        "  return Response.json(cache.get('generate'))\n}\n",
    )
    found = findings_for(tmp_path, "abuse", "ABUSE-PAID-UNAUTH")
    assert [(str(f.locations[0]), f.tag.value) for f in found] == [
        ("app/api/relative/route.ts:2", "CONFIRMED")
    ]


def test_next_and_django_global_guards_make_paid_unauth_inferred(tmp_path):
    nxt = tmp_path / "next"
    write(nxt, "package.json", '{"dependencies": {"next": "14", "openai": "4"}}')
    write(
        nxt,
        "app/api/generate/route.ts",
        "import OpenAI from 'openai'\nconst ai = new OpenAI()\n"
        "export async function POST() {\n  return Response.json(await ai.responses.create({}))\n}\n",
    )
    [plain] = findings_for(nxt, "abuse", "ABUSE-PAID-UNAUTH")
    assert plain.tag.value == "CONFIRMED"
    write(
        nxt,
        "middleware.ts",
        "export function middleware(req) { return gate(req) }\n"
        "export const config = { matcher: ['/api/:path*'] }\n",
    )
    [guarded] = findings_for(nxt, "abuse", "ABUSE-PAID-UNAUTH")
    assert guarded.tag.value == "INFERRED"
    assert "middleware.ts" in guarded.proof_needed

    django = tmp_path / "django"
    write(django, "requirements.txt", "django\nopenai\n")
    write(
        django,
        "config/settings.py",
        "INSTALLED_APPS = ['shop']\nMIDDLEWARE = ['django.middleware.security.SecurityMiddleware', "
        "'shop.middleware.TokenAuthMiddleware']\n",
    )
    write(
        django,
        "shop/urls.py",
        "from django.urls import path\nfrom . import views\nurlpatterns = [path('ask/', views.ask)]\n",
    )
    write(
        django,
        "shop/views.py",
        "from openai import OpenAI\nclient = OpenAI()\n"
        "def ask(request):\n    return client.responses.create(model='x', input='hi')\n",
    )
    [django_finding] = findings_for(django, "abuse", "ABUSE-PAID-UNAUTH")
    assert django_finding.tag.value == "INFERRED"
    assert "TokenAuthMiddleware" in django_finding.proof_needed


def test_paid_calls_through_imported_clients_and_service_instances(tmp_path):
    write(tmp_path, "requirements.txt", "fastapi\nopenai\n")
    write(tmp_path, "app/__init__.py", "")
    write(tmp_path, "app/services/__init__.py", "")
    write(
        tmp_path,
        "app/services/ai.py",
        "from openai import OpenAI\n_client = OpenAI()\n"
        "class AIService:\n    def complete(self, prompt):\n"
        "        return _client.chat.completions.create(model='x', messages=[])\n"
        "class Plain:\n    def complete(self, prompt):\n        return prompt\n"
        "ai_service = AIService()\nplain = Plain()\n",
    )
    write(
        tmp_path,
        "app/clients.py",
        "from openai import OpenAI\nclient = OpenAI()\nlabel = 'openai'\n",
    )
    write(
        tmp_path,
        "app/main.py",
        "from fastapi import FastAPI\nfrom app.services.ai import AIService, ai_service, plain\n"
        "from app.clients import client, label\nfrom app import clients\napp = FastAPI()\n"
        "@app.post('/service')\ndef service(prompt: str):\n    return ai_service.complete(prompt)\n"
        "@app.post('/client')\ndef direct(prompt: str):\n"
        "    return client.chat.completions.create(model='x', messages=[])\n"
        "@app.post('/module-client')\ndef module_client(prompt: str):\n"
        "    return clients.client.chat.completions.create(model='x', messages=[])\n"
        "@app.post('/constructed')\ndef constructed(prompt: str):\n"
        "    svc = AIService()\n    return svc.complete(prompt)\n"
        "@app.post('/plain')\ndef plain_route(prompt: str):\n    return plain.complete(label.upper())\n",
    )
    write(tmp_path, "package.json", '{"dependencies": {"next": "14", "openai": "4"}}')
    write(
        tmp_path,
        "lib/openai.ts",
        "import OpenAI from 'openai'\nexport const openai = new OpenAI()\nexport const cache = new Map()\n",
    )
    route = "{imports}\nexport async function POST(req: Request) {{\n  return Response.json(await {call})\n}}\n"
    write(
        tmp_path,
        "app/api/named/route.ts",
        route.format(
            imports="import { openai } from '@/lib/openai'",
            call="openai.chat.completions.create({ model: 'x', messages: [] })",
        ),
    )
    write(
        tmp_path,
        "app/api/alias/route.ts",
        route.format(
            imports="import { openai as ai } from '@/lib/openai'",
            call="ai.chat.completions.create({ model: 'x', messages: [] })",
        ),
    )
    write(
        tmp_path,
        "app/api/cache/route.ts",
        route.format(imports="import { cache } from '@/lib/openai'", call="cache.get('x')"),
    )
    found = findings_for(tmp_path, "abuse", "ABUSE-PAID-UNAUTH")
    assert sorted((str(f.locations[0]), f.tag.value) for f in found) == [
        ("app/api/alias/route.ts:2", "CONFIRMED"),
        ("app/api/named/route.ts:2", "CONFIRMED"),
        ("app/main.py:10", "CONFIRMED"),
        ("app/main.py:13", "CONFIRMED"),
        ("app/main.py:16", "CONFIRMED"),
        ("app/main.py:7", "CONFIRMED"),
    ]


def test_instances_resolve_only_from_the_handler_or_module_level(tmp_path):
    write(tmp_path, "requirements.txt", "fastapi\nopenai\n")
    write(tmp_path, "app/__init__.py", "")
    write(
        tmp_path,
        "app/deps.py",
        "def get_current_user():\n    return None\ndef get_mailer():\n    return None\n",
    )
    write(
        tmp_path,
        "app/main.py",
        "from fastapi import FastAPI, Depends\nfrom openai import OpenAI\n"
        "from app.deps import get_current_user, get_mailer\napp = FastAPI()\nclient = OpenAI()\n"
        "class WeatherTool:\n    def run(self, city):\n        return {'city': city}\n"
        "class LLMTool:\n    def run(self, prompt):\n"
        "        return client.chat.completions.create(model='x', messages=[])\n"
        "class Summariser:\n    def send(self, text):\n"
        "        return client.chat.completions.create(model='x', messages=[])\n"
        "@app.get('/weather')\ndef weather(city: str):\n    tool = WeatherTool()\n    return tool.run(city)\n"
        "@app.post('/generate')\ndef generate(prompt: str, user=Depends(get_current_user)):\n"
        "    tool = LLMTool()\n    return tool.run(prompt)\n"
        "def nightly_job():\n    service = Summariser()\n    return service.send('digest')\n"
        "@app.post('/contact')\ndef contact(text: str, service=Depends(get_mailer)):\n"
        "    return service.send(text)\n"
        "@app.post('/late')\ndef late(text: str):\n    helper.run(text)\n    helper = LLMTool()\n    return None\n",
    )
    assert findings_for(tmp_path, "abuse", "ABUSE-PAID-UNAUTH") == []
    unlimited = findings_for(tmp_path, "abuse", "ABUSE-PAID-UNLIMITED")
    assert [str(f.locations[0]) for f in unlimited] == ["app/main.py:20"]
