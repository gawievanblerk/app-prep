from dpr.parsing.routes import extract_routes
from dpr.parsing.routes_py import decorator_routes, django_routes
from dpr.walk import RepoIndex


def write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def repo(tmp_path):
    write(tmp_path, "api/main.py",
          "from fastapi import APIRouter\nrouter = APIRouter()\n\n"
          "@router.get(\"/items/{item_id}\")\nasync def read_item(item_id: int):\n    return {}\n\n"
          "@router.api_route(\"/multi\", methods=[\"GET\", \"POST\"])\ndef multi():\n    pass\n")
    write(tmp_path, "web/app.py",
          "from flask import Flask\napp = Flask(__name__)\n\n"
          "@app.route(\"/contact\", methods=[\"GET\", \"POST\"])\ndef contact():\n    pass\n\n"
          "@app.route(\"/about\")\ndef about():\n    pass\n")
    write(tmp_path, "shop/urls.py",
          "from django.urls import path, include\nfrom . import views\n\n"
          "urlpatterns = [\n"
          "    path(\"invoices/<int:pk>/\", views.invoice_detail),\n"
          "    path(\"orders/\", views.OrderView.as_view()),\n"
          "    path(\"api/\", include(\"accounts.urls\")),\n"
          "    path(\"register/\", views.missing_view),\n"
          "]\n")
    write(tmp_path, "shop/views.py",
          "def invoice_detail(request, pk):\n    pass\n\n\nclass OrderView(View):\n    pass\n")
    write(tmp_path, "accounts/urls.py",
          "from rest_framework import routers\nfrom .views import AccountViewSet\n"
          "router = routers.DefaultRouter()\nrouter.register(r\"accounts\", AccountViewSet)\n")
    write(tmp_path, "accounts/views.py", "class AccountViewSet(ModelViewSet):\n    pass\n")
    write(tmp_path, "app/api/signup/route.ts", "export async function POST() {}\n")
    return RepoIndex(tmp_path)


def test_decorator_routes(tmp_path):
    got = sorted((r.method, r.path, r.file, r.line, r.framework) for r in decorator_routes(repo(tmp_path)))
    assert got == [
        ("GET", "/about", "web/app.py", 9, "flask"),
        ("GET", "/contact", "web/app.py", 5, "flask"),
        ("GET", "/items/{item_id}", "api/main.py", 5, "fastapi"),
        ("GET", "/multi", "api/main.py", 9, "fastapi"),
        ("POST", "/contact", "web/app.py", 5, "flask"),
        ("POST", "/multi", "api/main.py", 9, "fastapi"),
    ]


def test_django_routes_resolve_views(tmp_path):
    got = sorted((r.path, r.file, r.line, r.framework, type(r.handler).__name__)
                 for r in django_routes(repo(tmp_path)))
    assert got == [
        ("/accounts", "accounts/views.py", 1, "drf", "ClassDef"),
        ("/invoices/<int:pk>", "shop/views.py", 1, "django", "FunctionDef"),
        ("/orders", "shop/views.py", 5, "django", "ClassDef"),
        ("/register", "shop/urls.py", 8, "django", "NoneType"),
    ]


def test_extract_routes_sets_public_form_flag(tmp_path):
    routes = extract_routes(repo(tmp_path))
    public = sorted((r.method, r.path) for r in routes if r.is_public_form)
    assert public == [("ANY", "/register"), ("GET", "/contact"), ("POST", "/api/signup"), ("POST", "/contact")]
    assert routes == sorted(routes, key=lambda r: (r.file, r.line, r.method))
