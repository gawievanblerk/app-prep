"""FastAPI router dependencies as gates for paid and public-sensitive routes."""

from tests.reviews.helpers import findings_for, write

CHECKED_GATE = (
    "from fastapi import Header, HTTPException\nfrom app.config import settings\n"
    "async def verify_internal_token(x_internal_token: str | None = Header(default=None)):\n"
    '    """Reject callers without the shared token."""\n'
    "    expected = settings.internal_token\n"
    "{guard}"
    "    if not x_internal_token or not secrets.compare_digest(x_internal_token, expected):\n"
    "        raise HTTPException(status_code=401, detail='invalid token')\n"
)
FAIL_OPEN = "    if not expected:\n        return\n"
ROUTES = (
    "from fastapi import APIRouter\nimport anthropic\nrouter = APIRouter(prefix='/notes')\n"
    "client = anthropic.Anthropic()\n"
    "@router.post('/generate')\nasync def generate(payload: dict):\n"
    "    return client.messages.create(messages=[])\n"
    "@router.post('/summarise')\nasync def summarise(payload: dict):\n"
    "    return client.messages.create(messages=[])\n"
)
MAIN = (
    "from fastapi import Depends, FastAPI\nfrom app.deps import verify_internal_token\n"
    "from app.routes import notes\napp = FastAPI()\n"
    "_internal = [Depends(verify_internal_token)]\n"
    "app.include_router(notes.router, prefix='/api', dependencies=_internal)\n"
)


def service(root, guard=FAIL_OPEN, main=MAIN, gate=None):
    write(root, "requirements.txt", "fastapi\nanthropic\n")
    write(root, "app/__init__.py", "")
    write(root, "app/routes/__init__.py", "")
    write(root, "app/deps.py", gate if gate is not None else CHECKED_GATE.format(guard=guard))
    write(root, "app/routes/notes.py", ROUTES)
    write(root, "app/main.py", main)
    return root


def test_include_router_dependency_list_name_gates_paid_routes(tmp_path):
    root = service(tmp_path)
    assert findings_for(root, "abuse", "ABUSE-PAID-UNAUTH") == []
    assert findings_for(root, "abuse", "ABUSE-PAID-UNLIMITED") == []


def test_fail_open_gate_is_one_low_finding_per_service(tmp_path):
    root = service(tmp_path)
    [found] = findings_for(root, "abuse", "ABUSE-GATE-FAIL-OPEN")
    assert found.severity.value == "low"
    assert str(found.locations[0]) == "app/deps.py:3"
    assert "INTERNAL_TOKEN" in found.title
    assert "2 paid routes" in found.detail


def test_enforced_gate_gives_no_fail_open_finding(tmp_path):
    root = service(tmp_path, guard="    if not expected:\n        raise RuntimeError('unset')\n")
    assert findings_for(root, "abuse", "ABUSE-GATE-FAIL-OPEN") == []
    root2 = tmp_path / "strict"
    service(root2, guard="")
    assert findings_for(root2, "abuse", "ABUSE-GATE-FAIL-OPEN") == []
    assert findings_for(root2, "abuse", "ABUSE-PAID-UNAUTH") == []


def test_gate_named_plainly_counts_when_its_body_rejects(tmp_path):
    gate = (
        "from fastapi import Header, HTTPException\n"
        "def caller_check(x_key: str = Header(None)):\n"
        "    if x_key != os.environ['SERVICE_KEY']:\n"
        "        raise HTTPException(status_code=403)\n"
    )
    main = MAIN.replace("verify_internal_token", "caller_check")
    root = service(tmp_path, main=main, gate=gate)
    assert findings_for(root, "abuse", "ABUSE-PAID-UNAUTH") == []


def test_auth_named_dependency_that_does_nothing_is_not_a_gate(tmp_path):
    gate = "def require_auth():\n    pass\n"
    main = MAIN.replace("verify_internal_token", "require_auth")
    root = service(tmp_path, main=main, gate=gate)
    assert len(findings_for(root, "abuse", "ABUSE-PAID-UNAUTH")) == 2
    assert len(findings_for(root, "abuse", "ABUSE-PAID-UNLIMITED")) == 2


def test_apirouter_and_fastapi_dependencies_gate_routes(tmp_path):
    routes = ROUTES.replace(
        "router = APIRouter(prefix='/notes')",
        "from fastapi import Depends\nfrom app.deps import verify_internal_token\n"
        "router = APIRouter(prefix='/notes', dependencies=[Depends(verify_internal_token)])",
    )
    root = service(tmp_path, guard="", main="from app.routes import notes\n")
    write(root, "app/routes/notes.py", routes)
    assert findings_for(root, "abuse", "ABUSE-PAID-UNAUTH") == []
    root2 = service(
        tmp_path / "appwide",
        guard="",
        main=MAIN.replace("app = FastAPI()", "app = FastAPI(dependencies=_internal)")
        .replace("_internal = [Depends(verify_internal_token)]\n", "")
        .replace(
            "from fastapi import Depends, FastAPI\n",
            "from fastapi import Depends, FastAPI\n_internal = [Depends(verify_internal_token)]\n",
        )
        .replace(", dependencies=_internal)", ")"),
    )
    assert findings_for(root2, "abuse", "ABUSE-PAID-UNAUTH") == []


def test_route_without_dependency_stays_reported(tmp_path):
    root = service(tmp_path, main=MAIN.replace(", dependencies=_internal", ""))
    assert len(findings_for(root, "abuse", "ABUSE-PAID-UNAUTH")) == 2
    assert len(findings_for(root, "abuse", "ABUSE-PAID-UNLIMITED")) == 2
    assert findings_for(root, "abuse", "ABUSE-GATE-FAIL-OPEN") == []


def test_user_gate_keeps_unlimited_findings(tmp_path):
    gate = (
        "from fastapi import Header, HTTPException\n"
        "def get_current_user(authorization: str = Header(None)):\n"
        "    return decode_jwt(authorization)\n"
    )
    main = MAIN.replace("verify_internal_token", "get_current_user")
    root = service(tmp_path, main=main, gate=gate)
    assert findings_for(root, "abuse", "ABUSE-PAID-UNAUTH") == []
    assert len(findings_for(root, "abuse", "ABUSE-PAID-UNLIMITED")) == 2
