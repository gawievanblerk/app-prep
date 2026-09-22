from dpr.discovery.detect import detect
from dpr.reviews import cost_trace
from dpr.rules import Context
from dpr.walk import RepoIndex
from tests.reviews.helpers import write

MAILER = (
    "from azure.communication.email import EmailClient\n\n\n"
    "class Mailer:\n    def __init__(self, conn):\n"
    "        self._client = EmailClient.from_connection_string(conn)\n\n"
    "    def _deliver(self, message):\n        return self._client.begin_send(message)\n\n"
    "    def send_invite(self, address):\n        return self._deliver({'to': address})\n"
)
ACCOUNTS = (
    "from app.services.mailer import Mailer\n\nmailer = Mailer('x')\n\n\n"
    "def invite_user(address):\n    return mailer.send_invite(address)\n"
)
ROUTES = (
    "import httpx\nimport openpyxl\nfrom fastapi import APIRouter, Depends\n"
    "from app.services.accounts import invite_user\n\nrouter = APIRouter()\n\n\n"
    "@router.post('/users')\nasync def create_user(body: dict, admin=Depends(get_admin_user)):\n"
    "    return invite_user(body['email'])\n\n\n"
    "@router.post('/imports')\nasync def import_rows(file, user=Depends(get_current_user)):\n"
    "    return openpyxl.load_workbook(file.file).sheetnames\n\n\n"
    "@router.get('/prices')\nasync def prices():\n"
    "    async with httpx.AsyncClient() as client:\n"
    "        return (await client.get(PRICES_URL)).json()\n\n\n"
    "@router.get('/orders')\nasync def orders(user=Depends(get_current_user)):\n"
    "    return await db.execute(select(Order))\n"
)


def api(root, prefix="api"):
    write(root, f"{prefix}/requirements.txt", "fastapi\nazure-communication-email\nopenpyxl\n")
    write(root, f"{prefix}/app/services/mailer.py", MAILER)
    write(root, f"{prefix}/app/services/accounts.py", ACCOUNTS)
    write(root, f"{prefix}/app/routes.py", ROUTES)
    return root


def ctx_for(root):
    index = RepoIndex(root)
    return Context(index=index, detection=detect(index))


def test_email_client_held_on_a_service_is_traced_three_calls_deep(tmp_path):
    ctx = ctx_for(api(tmp_path))
    rows = {f"{r.route.method} {r.route.path}": r for r in cost_trace.cost_rows(ctx)}
    assert rows["POST /users"].calls == ("azure-communication-email",)
    assert rows["POST /users"].app == "api"
    assert cost_trace.auth_label(ctx, rows["POST /users"].route) == "admin only"


def test_spreadsheet_parse_and_public_outbound_calls_are_listed(tmp_path):
    ctx = ctx_for(api(tmp_path))
    rows = {f"{r.route.method} {r.route.path}": r for r in cost_trace.cost_rows(ctx)}
    assert rows["POST /imports"].categories == ("spreadsheet",)
    assert rows["GET /prices"].calls == ("outbound HTTP",)
    assert cost_trace.auth_label(ctx, rows["GET /prices"].route) == "no"
    assert "GET /orders" not in rows


def test_shallow_trace_does_not_reach_the_client(tmp_path):
    ctx = ctx_for(api(tmp_path))
    route = next(r for r in ctx.detection.routes if r.path == "/users")
    codes = cost_trace.route_code(ctx, route, 1)
    assert not any(cost_trace.code_costs(ctx, code) for code in codes)


INVOICES_SERVICE = (
    "import weasyprint\nfrom azure.communication.email import EmailClient\n\n\n"
    "def render_invoice_pdf(html):\n    return weasyprint.HTML(string=html).write_pdf()\n\n\n"
    "def send_invoice_email(pdf, address):\n"
    "    client = EmailClient.from_connection_string('conn')\n"
    "    return client.begin_send({'to': address, 'attachment': pdf})\n"
)
INVOICES_ROUTES = (
    "from fastapi import APIRouter, Depends\n"
    "from app.services.invoices import render_invoice_pdf, send_invoice_email\n\n"
    "router = APIRouter()\n\n\n"
    "@router.post('/invoices')\n"
    "async def create_invoice(body: dict, user=Depends(get_current_user)):\n"
    "    pdf = render_invoice_pdf(body['html'])\n"
    "    return send_invoice_email(pdf, body['email'])\n"
)


def test_mixed_pdf_and_email_costs_recommend_the_strictest_limit(tmp_path):
    from dpr.api import review

    write(tmp_path, "requirements.txt", "fastapi\nweasyprint\nazure-communication-email\n")
    write(tmp_path, "app/services/invoices.py", INVOICES_SERVICE)
    write(tmp_path, "app/routes.py", INVOICES_ROUTES)
    report = review(tmp_path, reviews=["abuse"])
    parts = {p.title: p for p in report.sections["abuse"].parts}
    limits = {row[0]: row for row in parts["Limits per endpoint"].rows}
    assert limits["POST /invoices"][2:5] == ("3", "10", "1 h")


def test_cost_surface_gains_an_app_column_with_two_apps(tmp_path):
    from dpr.api import review

    api(tmp_path, "apps/admin")
    write(tmp_path, "apps/shop/requirements.txt", "fastapi\n")
    write(
        tmp_path,
        "apps/shop/app/main.py",
        "import httpx\nfrom fastapi import FastAPI\napp = FastAPI()\n\n"
        "@app.get('/rates')\nasync def rates():\n    return httpx.get(RATES_URL).json()\n",
    )
    report = review(tmp_path, reviews=["abuse"])
    parts = {p.title: p for p in report.sections["abuse"].parts}
    surface = parts["Cost surface"]
    assert surface.columns[0] == "App"
    assert ("apps/shop", "GET /rates", "outbound HTTP") == surface.rows[-1][:3]
    limits = parts["Limits per endpoint"].rows
    assert limits[-1][:5] == (
        "apps/shop: GET /rates",
        "outbound provider quota per call",
        "60",
        "120",
        "1 min",
    )


class CountingModule:
    """Delegates to a module and counts calls to class_defs."""

    def __init__(self, module):
        self.module = module
        self.class_scans = 0

    def __getattr__(self, name):
        return getattr(self.module, name)

    def class_defs(self, tree):
        self.class_scans += 1
        return self.module.class_defs(tree)


def test_self_clients_scan_each_class_once_however_many_routes_reach_it(tmp_path, monkeypatch):
    methods = "".join(
        f"    def step_{n}(self, item):\n        self.cache_{n} = item\n"
        f"        return self._client.begin_send(item)\n\n"
        for n in range(30)
    )
    write(tmp_path, "api/requirements.txt", "fastapi\nazure-communication-email\n")
    write(
        tmp_path,
        "api/app/services/mailer.py",
        "from azure.communication.email import EmailClient\n\n\nclass Mailer:\n"
        "    def __init__(self, conn):\n"
        "        self._client = EmailClient.from_connection_string(conn)\n\n" + methods,
    )
    routes = "".join(
        f"\n\n@router.post('/send/{n}')\nasync def send_{n}(item: dict):\n"
        f"    return Mailer('x').step_{n}(item)\n"
        for n in range(30)
    )
    write(
        tmp_path,
        "api/app/routes.py",
        "from fastapi import APIRouter\nfrom app.services.mailer import Mailer\n\n"
        "router = APIRouter()\n" + routes,
    )
    counter = CountingModule(cost_trace.pyast)
    monkeypatch.setattr(cost_trace, "pyast", counter)
    rows = cost_trace.cost_rows(ctx_for(tmp_path))
    assert len(rows) == 30
    assert all(r.calls == ("azure-communication-email",) for r in rows)
    assert counter.class_scans <= 2
