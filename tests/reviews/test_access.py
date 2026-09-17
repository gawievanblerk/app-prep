from dpr import rules
from dpr.discovery.detect import detect
from dpr.reviews.access import Access, access, path_params
from dpr.walk import RepoIndex
from tests.reviews.helpers import findings_for, write


def classify(root):
    index = RepoIndex(root)
    ctx = rules.Context(index=index, detection=detect(index))
    return {(r.method, r.path): access(ctx, r) for r in ctx.detection.routes}


def test_fastapi_aliases_router_dependencies_and_admin(tmp_path):
    write(
        tmp_path,
        "app/deps.py",
        "from typing import Annotated\nfrom fastapi import Depends\n"
        "CurrentUser = Annotated[dict, Depends(get_current_user)]\n"
        "AdminUser = Annotated[dict, Depends(get_admin_user)]\n"
        "ManagerOrAdmin = Annotated[dict, Depends(get_manager_or_admin_user)]\n"
        "StaffOrAdmin = Annotated[dict, Depends(get_staff_or_admin_user)]\n",
    )
    write(
        tmp_path,
        "app/items.py",
        "from fastapi import APIRouter, Depends\nfrom app.deps import AdminUser, CurrentUser, ManagerOrAdmin\n"
        "router = APIRouter()\n"
        "@router.get('/items/{item_id}')\nasync def one(item_id: str, me: CurrentUser): ...\n"
        "@router.delete('/items/{item_id}')\nasync def drop(item_id: str, boss: AdminUser): ...\n"
        "@router.put('/items/{item_id}')\nasync def edit(item_id: str, who: ManagerOrAdmin): ...\n"
        "@router.patch('/items/{item_id}')\nasync def tune(item_id: str, who: StaffOrAdmin): ...\n"
        "@router.post('/login')\nasync def login(db=Depends(get_db)): ...\n"
        "@router.get('/me', dependencies=[Depends(verify_token)])\nasync def me(): ...\n"
        "@router.get('/old')\nasync def old(user=Depends(get_current_user)): ...\n",
    )
    write(
        tmp_path,
        "app/secure.py",
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter(dependencies=[Depends(require_auth)])\n"
        "@router.get('/reports')\nasync def reports(): ...\n",
    )
    found = classify(tmp_path)
    assert found[("GET", "/items/{item_id}")].level == "authenticated"
    assert found[("GET", "/items/{item_id}")].subjects == ("me",)
    assert found[("DELETE", "/items/{item_id}")].level == "admin"
    assert found[("PUT", "/items/{item_id}")].level == "authenticated"
    assert found[("PATCH", "/items/{item_id}")].level == "admin"
    assert found[("POST", "/login")].level == "public"
    assert found[("GET", "/me")].level == "authenticated"
    assert found[("GET", "/old")].subjects == ("user",)
    assert found[("GET", "/reports")].evidence == "Depends(require_auth)"


def test_flask_and_django(tmp_path):
    write(
        tmp_path,
        "web/app.py",
        "from flask import Flask\nfrom flask_login import login_required\napp = Flask(__name__)\n"
        "@app.route('/notes/<int:note_id>')\n@login_required\ndef note(note_id): ...\n"
        "@app.route('/admin/users')\n@roles_required('admin')\ndef users(): ...\n"
        "@app.route('/contact', methods=['POST'])\ndef contact(): ...\n",
    )
    write(
        tmp_path,
        "shop/urls.py",
        "from django.urls import path\nfrom . import views\nurlpatterns = [\n"
        "    path('invoices/<int:pk>/', views.invoice),\n    path('open/', views.open_view),\n"
        "    path('staff/', views.staff),\n    path('api/', views.InvoiceApi.as_view()),\n]\n",
    )
    write(
        tmp_path,
        "shop/views.py",
        "from django.contrib.auth.decorators import login_required\n"
        "@login_required\ndef invoice(request, pk): ...\n"
        "def open_view(request): ...\n"
        "@staff_member_required\ndef staff(request): ...\n"
        "class InvoiceApi(APIView):\n    permission_classes = [IsAuthenticated]\n",
    )
    found = classify(tmp_path)
    assert found[("GET", "/notes/<int:note_id>")].level == "authenticated"
    assert found[("GET", "/admin/users")].level == "admin"
    assert found[("POST", "/contact")].level == "public"
    assert found[("ANY", "/invoices/<int:pk>")].subjects == ("request.user", "self.request.user")
    assert found[("ANY", "/open")].level == "public"
    assert found[("ANY", "/staff")].level == "admin"
    assert found[("ANY", "/api")].level == "authenticated"


def test_next_handlers_and_middleware(tmp_path):
    write(
        tmp_path,
        "app/api/invoices/[id]/route.ts",
        "export async function GET(req: Request, { params }: any) {\n"
        "  const session = await auth()\n  return Response.json({})\n}\n"
        "export async function DELETE(req: Request) {\n  return Response.json({})\n}\n",
    )
    write(
        tmp_path,
        "app/api/admin/stats/route.ts",
        "export async function GET() {\n  const { data: { user } } = await supabase.auth.getUser()\n"
        "  if (user.role !== 'admin') return new Response(null, { status: 403 })\n}\n",
    )
    write(
        tmp_path,
        "app/api/account/route.ts",
        "export async function POST() {\n  return Response.json({})\n}\n",
    )
    write(
        tmp_path,
        "middleware.ts",
        "export default auth\nexport const config = { matcher: ['/api/account/:path*'] }\n",
    )
    found = classify(tmp_path)
    assert found[("GET", "/api/invoices/:id")].subjects == ("session",)
    assert found[("DELETE", "/api/invoices/:id")].level == "public"
    assert found[("GET", "/api/admin/stats")].level == "admin"
    assert found[("GET", "/api/admin/stats")].subjects == ("user",)
    assert found[("POST", "/api/account")].evidence == "middleware matcher"


def test_express_route_and_use_middleware(tmp_path):
    write(
        tmp_path,
        "server/routes.js",
        "const router = require('express').Router()\n"
        "router.get('/public', (req, res) => res.send('ok'))\n"
        "router.get('/orders/:orderId', requireAuth, (req, res) => res.send('ok'))\n"
        "router.use(authenticate)\n"
        "router.delete('/orders/:orderId', isAdmin, (req, res) => res.send('ok'))\n"
        "router.post('/orders', (req, res) => res.send('ok'))\n",
    )
    found = classify(tmp_path)
    assert found[("GET", "/public")].level == "public"
    assert found[("GET", "/orders/:orderId")].level == "authenticated"
    assert found[("DELETE", "/orders/:orderId")].level == "admin"
    assert found[("POST", "/orders")].level == "authenticated"
    assert found[("POST", "/orders")].subjects[0] == "req.user"


def test_next_wrapper_auth(tmp_path):
    write(
        tmp_path,
        "app/api/secret/route.ts",
        "export const GET = withAuth(async (req) => { return Response.json({ ok: true }) })\n",
    )
    write(
        tmp_path,
        "app/api/admin/users/route.ts",
        "export const GET = withAdmin(async () => Response.json([]))\n",
    )
    write(
        tmp_path,
        "app/api/log/route.ts",
        "export const POST = withLogging(async () => Response.json({}))\n",
    )
    write(
        tmp_path,
        "pages/api/auth/[...nextauth].ts",
        "export default NextAuth(authOptions)\n",
    )
    index = RepoIndex(tmp_path)
    ctx = rules.Context(index=index, detection=detect(index))
    found = {(r.method, r.path): r for r in ctx.detection.routes}

    secret = access(ctx, found[("GET", "/api/secret")])
    assert secret.level == "authenticated"
    assert "withAuth" in secret.evidence

    admin = access(ctx, found[("GET", "/api/admin/users")])
    assert admin.level == "admin"

    log = access(ctx, found[("POST", "/api/log")])
    assert log.level == "public"

    nextauth_route = found[("ANY", "/api/auth/*nextauth")]
    assert nextauth_route.handler.type == "call_expression"
    nextauth = access(ctx, nextauth_route)
    assert isinstance(nextauth, Access)


def test_express_wrapped_last_argument(tmp_path):
    write(
        tmp_path,
        "server/app.js",
        "const app = require('express')()\n"
        "app.get('/me', requireAuth((req, res) => res.send('ok')))\n",
    )
    found = classify(tmp_path)
    assert found[("GET", "/me")].level == "authenticated"


def test_path_params():
    from dpr.model import Route

    def params(path):
        return path_params(Route("GET", path, "a", 1, "x"))

    assert params("/items/{item_id}/files/{name:path}") == ["item_id", "name"]
    assert params("/invoices/<int:pk>/<slug>") == ["pk", "slug"]
    assert params("/orders/:orderId/lines/*rest") == ["orderId", "rest"]
    assert params("/plain") == []


def test_database_session_dependencies_are_not_authentication(tmp_path):
    write(tmp_path, "requirements.txt", "fastapi\nsqlmodel\nopenai\n")
    write(
        tmp_path,
        "app/deps.py",
        "from typing import Annotated\nfrom fastapi import Depends\nfrom sqlmodel import Session\n"
        "def get_session():\n    yield None\n"
        "SessionDep = Annotated[Session, Depends(get_session)]\n",
    )
    write(
        tmp_path,
        "app/main.py",
        "from fastapi import FastAPI, Depends\nfrom sqlmodel import Session\n"
        "from sqlalchemy.ext.asyncio import AsyncSession\n"
        "from app.deps import SessionDep, get_session\napp = FastAPI()\n"
        "@app.get('/invoices/{invoice_id}')\n"
        "def read_invoice(invoice_id: int, session: Session = Depends(get_session)):\n"
        "    return session.get(Invoice, invoice_id)\n"
        "@app.post('/generate')\ndef generate(prompt: str, session: SessionDep):\n    return None\n"
        "@app.get('/db')\nasync def db_route(db: AsyncSession = Depends(get_db_session)):\n    return None\n"
        "@app.get('/me')\nasync def me(session: Session = Depends(get_session), user=Depends(get_current_user)):\n"
        "    return user\n",
    )
    found = classify(tmp_path)
    assert found[("GET", "/invoices/{invoice_id}")].level == "public"
    assert found[("GET", "/invoices/{invoice_id}")].basis == "absence"
    assert found[("POST", "/generate")].level == "public"
    assert found[("GET", "/db")].level == "public"
    assert found[("GET", "/me")].level == "authenticated"
    assert found[("GET", "/me")].subjects == ("user",)


def test_auth_words_match_whole_name_tokens(tmp_path):
    write(
        tmp_path,
        "app/main.py",
        "from fastapi import FastAPI, Depends\napp = FastAPI()\n"
        "@app.get('/posts')\ndef posts(author=Depends(get_author), prefs=Depends(get_username_prefs)):\n"
        "    return []\n"
        "@app.get('/mine')\ndef mine(user=Depends(authenticated_user)):\n    return []\n",
    )
    found = classify(tmp_path)
    assert found[("GET", "/posts")].level == "public"
    assert found[("GET", "/mine")].level == "authenticated"


def test_fastapi_include_router_dependencies(tmp_path):
    write(tmp_path, "requirements.txt", "fastapi\nopenai\n")
    write(tmp_path, "app/deps.py", "def get_current_active_user(): ...\n")
    write(
        tmp_path,
        "app/main.py",
        "from fastapi import FastAPI, Depends\nfrom app.deps import get_current_active_user\n"
        "from app.routers import ai, public\napp = FastAPI()\n"
        "app.include_router(ai.router, prefix='/ai', dependencies=[Depends(get_current_active_user)])\n"
        "app.include_router(public.router, prefix='/public')\n",
    )
    write(tmp_path, "app/routers/__init__.py", "")
    write(
        tmp_path,
        "app/routers/ai.py",
        "from fastapi import APIRouter\nfrom openai import OpenAI\nrouter = APIRouter()\nclient = OpenAI()\n"
        "@router.post('/generate')\ndef generate(prompt: str):\n"
        "    return client.responses.create(model='x', input=prompt)\n",
    )
    write(
        tmp_path,
        "app/routers/public.py",
        "from fastapi import APIRouter\nrouter = APIRouter()\n@router.get('/status')\ndef status():\n    return {}\n",
    )
    found = classify(tmp_path)
    assert found[("POST", "/generate")].level == "authenticated"
    assert "get_current_active_user" in found[("POST", "/generate")].evidence
    assert found[("GET", "/status")].level == "public"
    assert findings_for(tmp_path, "abuse", "ABUSE-PAID-UNAUTH") == []


def test_express_session_and_router_mounts_are_not_authentication(tmp_path):
    write(
        tmp_path,
        "package.json",
        '{"dependencies": {"express": "4", "express-session": "1", "openai": "4"}}',
    )
    write(
        tmp_path,
        "src/server.js",
        "const express = require('express')\nconst session = require('express-session')\n"
        "const passport = require('passport')\nconst OpenAI = require('openai')\n"
        "const usersRouter = require('./routes/users')\n"
        "const app = express()\nconst ai = new OpenAI()\n"
        "app.use(express.json())\n"
        "app.use(session({ secret: process.env.SESSION_SECRET, resave: false }))\n"
        "app.use(passport.initialize())\n"
        "app.use('/api/users', usersRouter)\n"
        "app.use('/api/admin', requireAdmin)\n"
        "app.post('/api/generate', async (req, res) => {\n"
        "  res.json(await ai.chat.completions.create({ model: 'x', messages: req.body.messages }))\n"
        "})\n"
        "app.get('/api/admin/stats', (req, res) => res.json({}))\n"
        "app.listen(3000)\n",
    )
    write(
        tmp_path,
        "src/routes/users.js",
        "const router = require('express').Router()\nrouter.get('/', (req, res) => res.json([]))\n"
        "module.exports = router\n",
    )
    found = classify(tmp_path)
    generate = found[("POST", "/api/generate")]
    assert generate.level == "public"
    assert generate.basis == "absence"
    assert found[("GET", "/api/admin/stats")].level == "admin"
    [paid] = findings_for(tmp_path, "abuse", "ABUSE-PAID-UNAUTH")
    assert paid.tag.value == "CONFIRMED"


def test_express_auth_middleware_at_a_mount_in_another_file(tmp_path):
    write(
        tmp_path, "package.json", '{"dependencies": {"express": "4", "openai": "4", "helmet": "7"}}'
    )
    write(
        tmp_path,
        "src/server.js",
        "const express = require('express')\nconst helmet = require('helmet')\n"
        "const { requireAuth } = require('./auth')\nconst aiRouter = require('./routes/ai')\n"
        "const openRouter = require('./routes/open')\n"
        "const app = express()\napp.use(helmet())\n"
        "app.use('/api/ai', requireAuth, aiRouter)\n"
        "app.use('/api/open', openRouter)\n"
        "app.listen(3000)\n",
    )
    write(
        tmp_path,
        "src/routes/ai.js",
        "const express = require('express')\nconst OpenAI = require('openai')\n"
        "const router = express.Router()\nconst ai = new OpenAI()\n"
        "router.post('/generate', async (req, res) => {\n"
        "  res.json(await ai.chat.completions.create({ model: 'x', messages: req.body.messages }))\n"
        "})\nmodule.exports = router\n",
    )
    write(
        tmp_path,
        "src/routes/open.js",
        "const router = require('express').Router()\nrouter.get('/ping', (req, res) => res.send('ok'))\n"
        "module.exports = router\n",
    )
    found = classify(tmp_path)
    assert found[("POST", "/generate")].level == "authenticated"
    assert "requireAuth" in found[("POST", "/generate")].evidence
    assert found[("GET", "/ping")].level == "public"
    assert findings_for(tmp_path, "abuse", "ABUSE-PAID-UNAUTH") == []


def test_next_matcher_negative_lookahead_excludes_its_prefixes(tmp_path):
    write(
        tmp_path,
        "package.json",
        '{"dependencies": {"next": "14", "next-auth": "4", "openai": "4"}}',
    )
    write(
        tmp_path,
        "middleware.ts",
        'export { default } from "next-auth/middleware"\n'
        'export const config = { matcher: ["/((?!api|_next/static|_next/image|favicon.ico).*)"] }\n',
    )
    write(
        tmp_path,
        "app/api/generate/route.ts",
        "import OpenAI from 'openai'\nconst ai = new OpenAI()\n"
        "export async function POST(req: Request) {\n  const body = await req.json()\n"
        "  return Response.json(await ai.chat.completions.create({ model: 'x', messages: body.messages }))\n}\n",
    )
    write(
        tmp_path,
        "app/account/export/route.ts",
        "export async function GET() {\n  return Response.json({})\n}\n",
    )
    found = classify(tmp_path)
    assert found[("POST", "/api/generate")].level == "public"
    assert found[("GET", "/account/export")].level == "authenticated"
    assert [f.tag.value for f in findings_for(tmp_path, "abuse", "ABUSE-PAID-UNAUTH")] == [
        "CONFIRMED"
    ]


def test_django_login_required_middleware_and_drf_defaults_in_any_settings_module(tmp_path):
    write(tmp_path, "requirements.txt", "django==5.1\ndjangorestframework==3.15\nopenai==1.0.0\n")
    write(tmp_path, "manage.py", "import django\n")
    write(
        tmp_path,
        "config/settings/common.py",
        "INSTALLED_APPS = ['rest_framework']\n"
        "MIDDLEWARE = ['django.middleware.security.SecurityMiddleware', "
        "'django.contrib.auth.middleware.LoginRequiredMiddleware']\n",
    )
    write(
        tmp_path,
        "shop/urls.py",
        "from django.urls import path\nfrom . import views\nurlpatterns = [path('summarise/', views.summarise), "
        "path('health/', views.health), path('notes/<int:pk>/', views.NoteView.as_view())]\n",
    )
    write(
        tmp_path,
        "shop/views.py",
        "from django.contrib.auth.decorators import login_not_required\nfrom openai import OpenAI\n"
        "from rest_framework.views import APIView\nclient = OpenAI()\n"
        "def summarise(request):\n    return client.responses.create(model='x', input=request.POST['text'])\n"
        "@login_not_required\ndef health(request):\n    return None\n"
        "class NoteView(APIView):\n    def delete(self, request, pk):\n        return None\n",
    )
    found = classify(tmp_path)
    assert found[("ANY", "/summarise")].level == "authenticated"
    assert found[("ANY", "/summarise")].evidence == "LoginRequiredMiddleware"
    assert found[("ANY", "/health")].level == "public"
    assert found[("ANY", "/health")].basis == "explicit"
    assert findings_for(tmp_path, "abuse", "ABUSE-PAID-UNAUTH") == []

    write(
        tmp_path,
        "config/settings/common.py",
        "INSTALLED_APPS = ['rest_framework']\n"
        "REST_FRAMEWORK = {'DEFAULT_PERMISSION_CLASSES': ['rest_framework.permissions.IsAuthenticated']}\n",
    )
    found = classify(tmp_path)
    assert found[("ANY", "/notes/<int:pk>")].level == "authenticated"
    assert found[("ANY", "/notes/<int:pk>")].evidence == "DEFAULT_PERMISSION_CLASSES"
    assert found[("ANY", "/summarise")].level == "public"
