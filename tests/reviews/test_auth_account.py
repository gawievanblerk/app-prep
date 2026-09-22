from tests.reviews.auth_app import auth_app
from tests.reviews.helpers import findings_for, write

UPDATE_SERVICE = (
    "class UserService:\n"
    "    async def update_user(self, user_id, data, requesting_user):\n"
    "        update = data.model_dump(exclude_unset=True)\n"
    "        allowed_fields = {'first_name', 'last_name', 'email'}\n"
    "        for field, value in update.items():\n"
    "            if field in allowed_fields:\n"
    "                setattr(requesting_user, field, value)\n"
)
USERS = (
    "from typing import Annotated\nfrom fastapi import APIRouter, Depends\n"
    "from app.services.user_service import UserService\n"
    "router = APIRouter(prefix='/users')\n"
    "CurrentUser = Annotated[dict, Depends(get_current_user)]\n\n"
    "@router.put('/{user_id}')\n"
    "async def update_user(user_id: str, data: UserUpdate, current_user: CurrentUser):\n"
    "    return await UserService().update_user(user_id, data, current_user)\n"
)


def test_self_update_that_allows_email_is_confirmed(tmp_path):
    auth_app(tmp_path, users=USERS)
    write(tmp_path, "api/app/services/user_service.py", UPDATE_SERVICE)
    [finding] = findings_for(tmp_path, "auth", "AUTH-EMAIL-CHANGE-UNVERIFIED")
    assert (finding.tag.value, str(finding.locations[0])) == (
        "CONFIRMED",
        "api/app/services/user_service.py:4",
    )


def test_email_change_with_verification_passes(tmp_path):
    auth_app(tmp_path, users=USERS)
    guarded = UPDATE_SERVICE.replace(
        "        allowed_fields",
        "        if 'email' in update:\n"
        "            await self.start_email_verification(requesting_user, update.pop('email'))\n"
        "        allowed_fields",
    )
    write(tmp_path, "api/app/services/user_service.py", guarded)
    assert findings_for(tmp_path, "auth", "AUTH-EMAIL-CHANGE-UNVERIFIED") == []
    without_email = UPDATE_SERVICE.replace(", 'email'}", "}")
    write(tmp_path, "api/app/services/user_service.py", without_email)
    assert findings_for(tmp_path, "auth", "AUTH-EMAIL-CHANGE-UNVERIFIED") == []


def test_javascript_profile_update_writing_email(tmp_path):
    write(
        tmp_path,
        "server/me.js",
        "router.patch('/me', requireUser, async (req, res) => {\n"
        "  await prisma.user.update({ where: { id: req.user.id }, data: { email: req.body.email } })\n"
        "  res.json({ ok: true })\n})\n",
    )
    [finding] = findings_for(tmp_path, "auth", "AUTH-EMAIL-CHANGE-UNVERIFIED")
    assert str(finding.locations[0]) == "server/me.js:2"


def model(root, email_line, extra=""):
    write(
        root,
        "api/app/models.py",
        f"class User(Base):\n    __tablename__ = 'users'\n    {email_line}\n{extra}",
    )


def test_email_uniqueness_on_the_user_model(tmp_path):
    auth_app(tmp_path)
    model(tmp_path, "email = Column(String)")
    [finding] = findings_for(tmp_path, "auth", "AUTH-EMAIL-NOT-UNIQUE")
    assert (finding.tag.value, str(finding.locations[0])) == ("CONFIRMED", "api/app/models.py:3")
    model(tmp_path, "email = Column(String, unique=True)")
    assert findings_for(tmp_path, "auth", "AUTH-EMAIL-NOT-UNIQUE") == []
    model(
        tmp_path,
        "email = Column(String)",
        "    __table_args__ = (Index('ix_live_email', 'email', unique=True),)\n",
    )
    assert findings_for(tmp_path, "auth", "AUTH-EMAIL-NOT-UNIQUE") == []


def web_app(root, client, screen):
    auth_app(root)
    write(root, "web/package.json", '{"dependencies": {"react": "18"}}')
    write(root, "web/index.html", "<div id=root></div>\n")
    write(root, "web/src/api.ts", client)
    write(root, "web/src/Screen.tsx", screen)


def test_signup_route_defined_in_the_client_but_never_called(tmp_path):
    client = (
        "export const authApi = {\n"
        "  register: (data) => api.post('/auth/register', data),\n"
        "  login: (data) => api.post('/auth/login', data),\n}\n"
    )
    web_app(tmp_path, client, "authApi.login({})\n")
    [finding] = findings_for(tmp_path, "auth", "AUTH-SIGNUP-NO-UI")
    assert finding.tag.value == "INFERRED"
    assert "defines register() for this path at web/src/api.ts:2" in finding.detail
    web_app(tmp_path, client, "authApi.register({})\n")
    assert findings_for(tmp_path, "auth", "AUTH-SIGNUP-NO-UI") == []


def root_web_app(root, client, screen):
    auth_app(root)
    write(root, "package.json", '{"dependencies": {"react": "18"}}')
    write(root, "index.html", "<div id=root></div>\n")
    write(root, "src/api.ts", client)
    write(root, "src/Screen.tsx", screen)


def test_repository_root_web_app_files_count_toward_the_frontend(tmp_path):
    client = (
        "export const authApi = {\n"
        "  register: (data) => api.post('/auth/register', data),\n"
        "  login: (data) => api.post('/auth/login', data),\n}\n"
    )
    root_web_app(tmp_path, client, "authApi.register({})\n")
    assert findings_for(tmp_path, "auth", "AUTH-SIGNUP-NO-UI") == []


def test_signup_route_with_no_reference_and_without_a_frontend(tmp_path):
    web_app(tmp_path, "export const x = 1\n", "export {}\n")
    [finding] = findings_for(tmp_path, "auth", "AUTH-SIGNUP-NO-UI")
    assert "No frontend source refers to this path." in finding.detail
    api_only = tmp_path / "api_only"
    auth_app(api_only)
    assert findings_for(api_only, "auth", "AUTH-SIGNUP-NO-UI") == []


def test_no_second_factor_per_app_and_mfa_signals(tmp_path):
    auth_app(tmp_path)
    [finding] = findings_for(tmp_path, "auth", "AUTH-NO-MFA")
    assert (finding.tag.value, finding.title) == ("INFERRED", "No second factor for sign-in in api")
    write(tmp_path, "api/requirements.txt", "fastapi\npython-jose\npasslib\npyotp\n")
    assert findings_for(tmp_path, "auth", "AUTH-NO-MFA") == []


LOGIN_ROUTE = (
    "from fastapi import APIRouter, HTTPException\n\n"
    "router = APIRouter(prefix='/auth')\n\n\n"
    "@router.post('/login')\n"
    "async def login(data: dict):\n"
    "    if not await check_credentials(data):\n"
    "        raise HTTPException(status_code=401, detail='Invalid email or password')\n"
    "    return {'ok': True}\n"
)


def two_root_app(root):
    write(root, "admin/requirements.txt", "fastapi\n")
    write(root, "admin/app/routes/auth.py", LOGIN_ROUTE)
    write(root, "api/requirements.txt", "fastapi\n")
    write(root, "api/app/routes/auth.py", LOGIN_ROUTE)


def test_mfa_package_in_one_root_does_not_guard_another_root(tmp_path):
    two_root_app(tmp_path)
    write(tmp_path, "admin/requirements.txt", "fastapi\npyotp\n")
    findings = findings_for(tmp_path, "auth", "AUTH-NO-MFA")
    assert {f.title for f in findings} == {"No second factor for sign-in in api"}


def test_shared_manifest_guards_every_root(tmp_path):
    two_root_app(tmp_path)
    write(tmp_path, "requirements.txt", "pyotp\n")
    assert findings_for(tmp_path, "auth", "AUTH-NO-MFA") == []


LEGACY_USER = (
    "from sqlalchemy.orm import Mapped, mapped_column\n"
    "from sqlalchemy import String, Integer\n\n"
    "class User(Base):\n"
    "    __tablename__ = 'users'\n"
    "    id: Mapped[int] = mapped_column(Integer, primary_key=True)\n"
    "    email: Mapped[str] = mapped_column(String)\n"
    "    totp_secret: Mapped[str] = mapped_column(String)\n"
    "    failed_login_attempts: Mapped[int] = mapped_column(Integer)\n"
)


def test_mfa_field_on_a_user_model_in_another_root_does_not_guard_sign_in(tmp_path):
    write(tmp_path, "api/requirements.txt", "fastapi\n")
    write(tmp_path, "api/app/routes/auth.py", LOGIN_ROUTE)
    write(tmp_path, "legacy/requirements.txt", "flask\n")
    write(tmp_path, "legacy/models.py", LEGACY_USER)
    [finding] = findings_for(tmp_path, "auth", "AUTH-NO-MFA")
    assert finding.title == "No second factor for sign-in in api"
    write(tmp_path, "api/app/models.py", LEGACY_USER)
    assert findings_for(tmp_path, "auth", "AUTH-NO-MFA") == []


def test_email_uniqueness_is_judged_only_where_a_register_flow_shares_the_root(tmp_path):
    write(tmp_path, "api/requirements.txt", "fastapi\n")
    write(
        tmp_path,
        "api/app/routes/auth.py",
        "from fastapi import APIRouter\n\nrouter = APIRouter(prefix='/auth')\n\n\n"
        "@router.post('/register')\nasync def register(data: RegisterRequest):\n"
        "    return {'ok': True}\n",
    )
    write(tmp_path, "legacy/requirements.txt", "flask\n")
    write(tmp_path, "legacy/models.py", LEGACY_USER)
    assert findings_for(tmp_path, "auth", "AUTH-EMAIL-NOT-UNIQUE") == []
    write(tmp_path, "api/app/models.py", LEGACY_USER)
    [finding] = findings_for(tmp_path, "auth", "AUTH-EMAIL-NOT-UNIQUE")
    assert str(finding.locations[0]) == "api/app/models.py:7"
