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
        "async def stream_chat(messages):\n    import anthropic\n"
        "    client = anthropic.Anthropic()\n    return client.messages.create(messages=messages)\n",
    )
    write(
        tmp_path,
        "app/routes.py",
        "from fastapi import APIRouter, Depends\nrouter = APIRouter()\n"
        "@router.post('/chat')\nasync def chat(user=Depends(get_current_user)):\n"
        "    from app.chat import stream_chat\n    return await stream_chat([])\n"
        "@router.post('/limited')\n@limiter.limit('5/minute')\nasync def limited(user=Depends(get_current_user)):\n"
        "    return await stream_chat([])\n",
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
        "@router.post('/invite')\nasync def invite(email: str):\n    send(email, 'hi')\n"
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
