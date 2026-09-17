from dpr import rules
from dpr.discovery.detect import detect
from dpr.reviews.access import access, path_params
from dpr.walk import RepoIndex
from tests.reviews.helpers import write


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


def test_path_params():
    from dpr.model import Route

    def params(path):
        return path_params(Route("GET", path, "a", 1, "x"))

    assert params("/items/{item_id}/files/{name:path}") == ["item_id", "name"]
    assert params("/invoices/<int:pk>/<slug>") == ["pk", "slug"]
    assert params("/orders/:orderId/lines/*rest") == ["orderId", "rest"]
    assert params("/plain") == []
