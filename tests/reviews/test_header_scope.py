from dpr.reviews.owasp_a01 import attacker
from tests.reviews.helpers import findings_for, write

API = "from fastapi import FastAPI\napp = FastAPI()\n"


def api(root, main=API):
    write(root, "api/requirements.txt", "fastapi\n")
    write(root, "api/app/main.py", main)
    return root


def test_json_api_is_only_checked_for_transport_headers(tmp_path):
    api(tmp_path)
    for key in ("CSP", "FRAME", "REFERRER", "PERMISSIONS"):
        assert findings_for(tmp_path, "baseline", f"BASE-HEADER-MISSING-{key}") == [], key
    [hsts] = findings_for(tmp_path, "baseline", "BASE-HEADER-MISSING-HSTS")
    [xcto] = findings_for(tmp_path, "baseline", "BASE-HEADER-MISSING-XCTO")
    assert str(hsts.locations[0]) == str(xcto.locations[0]) == "api/app/main.py:2"


def test_server_app_that_renders_pages_is_checked_for_document_headers(tmp_path):
    api(tmp_path)
    write(
        tmp_path,
        "api/app/pages.py",
        "from fastapi.templating import Jinja2Templates\ntemplates = Jinja2Templates('t')\n",
    )
    [csp] = findings_for(tmp_path, "baseline", "BASE-HEADER-MISSING-CSP")
    assert [str(loc) for loc in csp.locations] == ["api/app/main.py:2"]


def test_hsts_is_low_unless_a_session_cookie_lacks_secure(tmp_path):
    api(tmp_path)
    [hsts] = findings_for(tmp_path, "baseline", "BASE-HEADER-MISSING-HSTS")
    assert hsts.severity.value == "low"
    write(
        tmp_path,
        "api/app/auth.py",
        "def login(response):\n"
        "    response.set_cookie('session', 'x', httponly=True, secure=False, samesite='lax')\n",
    )
    [hsts] = findings_for(tmp_path, "baseline", "BASE-HEADER-MISSING-HSTS")
    assert hsts.severity.value == "medium"


def test_csp_is_never_above_medium(tmp_path):
    write(tmp_path, "web/staticwebapp.config.json", '{"globalHeaders": {}}')
    [csp] = findings_for(tmp_path, "baseline", "BASE-HEADER-MISSING-CSP")
    assert csp.severity.value == "medium"


def test_attacker_role_comes_from_the_auth_dependency():
    assert attacker("Depends(ManagerOrAdmin)") == "any manager account"
    assert attacker("Depends(get_current_user)") == "any signed-in user"
    assert attacker("Depends(StaffOrAdmin)") == "any staff account"
    assert attacker("@login_required") == "any signed-in user"
    assert attacker("Depends(require_agents)") == "any agent account"


def test_unscoped_query_attack_names_the_role(tmp_path):
    write(tmp_path, "api/requirements.txt", "fastapi\n")
    write(
        tmp_path,
        "api/app/models.py",
        "class Attachment(Base):\n    __tablename__ = 'attachments'\n"
        "    id = Column(String, primary_key=True)\n    uploaded_by_id = Column(String)\n",
    )
    write(
        tmp_path,
        "api/app/routes.py",
        "from fastapi import APIRouter\nfrom sqlalchemy import select\nrouter = APIRouter()\n"
        "ManagerOrAdmin = Annotated[User, Depends(require_manager_or_admin)]\n"
        "@router.get('/attachments/{attachment_id}')\n"
        "async def download(attachment_id: str, current_user: ManagerOrAdmin):\n"
        "    return await db.execute(select(Attachment).where(Attachment.id == attachment_id))\n",
    )
    [finding] = findings_for(tmp_path, "owasp", "OWASP-A01-UNSCOPED-QUERY")
    assert finding.attack.startswith("1. Sign in as any manager account.")
