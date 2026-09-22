from dpr import reviews, rules
from dpr.discovery.detect import detect
from dpr.reviews.auth_flows import flows, lifetimes, managed_provider, user_models
from dpr.walk import RepoIndex
from tests.reviews.auth_app import auth_app
from tests.reviews.helpers import findings_for, write


def context(root):
    reviews.available()
    index = RepoIndex(root)
    return rules.Context(index=index, detection=detect(index))


def test_flow_kinds_from_paths_and_access(tmp_path):
    ctx = context(auth_app(tmp_path))
    kinds = sorted((f.kind, f.route.method, f.route.path) for f in flows(ctx))
    assert kinds == [
        ("forgot", "POST", "/auth/forgot-password"),
        ("login", "POST", "/auth/login"),
        ("logout", "POST", "/auth/logout"),
        ("refresh", "POST", "/auth/refresh"),
        ("register", "POST", "/auth/register"),
        ("reset", "POST", "/auth/reset-password"),
        ("update_self", "PUT", "/users/{user_id}"),
        ("verify", "POST", "/auth/verify-email"),
    ]


def test_flow_code_follows_service_methods(tmp_path):
    ctx = context(auth_app(tmp_path))
    [login] = [f for f in flows(ctx) if f.kind == "login"]
    names = [getattr(c.node, "name", "") for c in login.code]
    assert names == ["login", "authenticate_user", "get_user_by_email"]
    assert login.code[1].rel == "api/app/services/auth_service.py"
    assert "verify_password" in login.code[1].text()


def test_javascript_flows_follow_local_helpers(tmp_path):
    write(
        tmp_path,
        "server/routes.js",
        "function findUser(email) { return db.user.findFirst({ where: { email } }) }\n"
        "router.post('/signup', async (req, res) => {\n"
        "  const user = await findUser(req.body.email)\n  res.json({ ok: !user })\n})\n",
    )
    ctx = context(tmp_path)
    [signup] = flows(ctx)
    assert signup.kind == "register"
    assert [c.line for c in signup.code] == [2, 1]


def test_managed_provider_user_models_and_lifetimes(tmp_path):
    auth_app(tmp_path)
    write(
        tmp_path,
        "api/app/models.py",
        "class User(Base):\n    __tablename__ = 'users'\n    email = Column(String, unique=True)\n"
        "class Invoice(Base):\n    __tablename__ = 'invoices'\n    id = Column(String)\n",
    )
    write(tmp_path, "web/lib/token.ts", "jwt.sign(payload, secret, { expiresIn: '30d' })\n")
    ctx = context(tmp_path)
    assert managed_provider(ctx) is None
    assert [m.name for m in user_models(ctx)] == ["User"]
    assert [(n, v, str(loc)) for n, v, loc in lifetimes(ctx)] == [
        ("jwt_access_token_expire_minutes", "30", "api/app/config.py:2"),
        ("jwt_refresh_token_expire_days", "7", "api/app/config.py:3"),
        ("expiresIn", "'30d'", "web/lib/token.ts:1"),
    ]
    write(tmp_path, "web/lib/auth.ts", "const { data } = await supabase.auth.getUser()\n")
    assert managed_provider(context(tmp_path)) == "Supabase Auth"


def test_self_path_requires_no_param_segment_before_the_self_word(tmp_path):
    write(tmp_path, "api/requirements.txt", "fastapi\n")
    write(
        tmp_path,
        "api/app/routes/misc.py",
        "from typing import Annotated\n\n"
        "from fastapi import APIRouter, Depends\n\n"
        "router = APIRouter()\n"
        "CurrentUser = Annotated[dict, Depends(get_current_user)]\n\n\n"
        '@router.patch("/insureds/{insured_id}/profile")\n'
        "async def update_profile(insured_id: str, data: dict, current_user: CurrentUser):\n"
        '    return {"ok": True}\n\n\n'
        '@router.put("/users/{user_id}")\n'
        "async def update_user(user_id: str, data: dict, current_user: CurrentUser):\n"
        '    return {"ok": True}\n\n\n'
        '@router.patch("/me")\n'
        "async def update_me(data: dict, current_user: CurrentUser):\n"
        '    return {"ok": True}\n\n\n'
        '@router.patch("/account/email")\n'
        "async def update_email(data: dict, current_user: CurrentUser):\n"
        '    return {"ok": True}\n',
    )
    ctx = context(tmp_path)
    kinds = {(f.route.method, f.route.path): f.kind for f in flows(ctx)}
    assert ("PATCH", "/insureds/{insured_id}/profile") not in kinds
    assert kinds[("PUT", "/users/{user_id}")] == "update_self"
    assert kinds[("PATCH", "/me")] == "update_self"
    assert kinds[("PATCH", "/account/email")] == "update_self"


def test_lifetimes_scoped_by_app_root(tmp_path):
    auth_app(tmp_path)
    write(tmp_path, "web/package.json", '{"name": "web"}')
    write(tmp_path, "web/lib/token.ts", "jwt.sign(payload, secret, { expiresIn: '14d' })\n")
    ctx = context(tmp_path)
    api_only = [(n, v) for n, v, _ in lifetimes(ctx, "api")]
    web_only = [(n, v) for n, v, _ in lifetimes(ctx, "web")]
    assert api_only == [
        ("jwt_access_token_expire_minutes", "30"),
        ("jwt_refresh_token_expire_days", "7"),
    ]
    assert web_only == [("expiresIn", "'14d'")]
    assert len(lifetimes(ctx)) == 3


BUSINESS_ROUTES = (
    "from fastapi import APIRouter, Depends\n\nrouter = APIRouter()\n\n\n"
    "@router.post('/subscriptions/{sub_id}/activate')\n"
    "async def activate_subscription(sub_id: int, user=Depends(get_current_user)):\n"
    "    sub = await service.load(sub_id, user)\n"
    "    sub.active = True\n"
    "    return sub\n\n\n"
    "@router.get('/orders/{order_id}/verify-address')\n"
    "async def verify_address(order_id: int, user=Depends(get_current_user)):\n"
    "    return await geo.check(order_id)\n\n\n"
    "@router.get('/public/orders/{order_id}/verify-address')\n"
    "async def check_address(order_id: int):\n"
    "    return await geo.check(order_id)\n"
)
VERIFY_ROUTES = (
    "from fastapi import APIRouter, Depends\n\nrouter = APIRouter()\n\n\n"
    "@router.get('/auth/verify')\n"
    "async def verify(token: str):\n"
    "    return await accounts.verify(token)\n\n\n"
    "@router.post('/me/confirm-email')\n"
    "async def confirm(data: ConfirmRequest, user=Depends(get_current_user)):\n"
    "    return await accounts.confirm(user, data.code)\n\n\n"
    "@router.get('/activate/{activation_key}')\n"
    "async def activate(activation_key: str):\n"
    "    return await accounts.activate(activation_key)\n"
)


def test_business_routes_that_verify_or_activate_are_not_verify_flows(tmp_path):
    write(tmp_path, "requirements.txt", "fastapi\n")
    write(tmp_path, "app/routes.py", BUSINESS_ROUTES)
    ctx = context(tmp_path)
    assert [f for f in flows(ctx) if f.kind == "verify"] == []
    for rule_id in ("AUTH-VERIFY-NO-EXPIRY", "AUTH-VERIFY-REUSABLE"):
        assert findings_for(tmp_path, "auth", rule_id) == []


def test_verify_flows_read_a_token_or_name_an_account_word(tmp_path):
    write(tmp_path, "requirements.txt", "fastapi\n")
    write(tmp_path, "app/routes.py", VERIFY_ROUTES)
    ctx = context(tmp_path)
    assert sorted(f.route.path for f in flows(ctx) if f.kind == "verify") == [
        "/activate/{activation_key}",
        "/auth/verify",
        "/me/confirm-email",
    ]
