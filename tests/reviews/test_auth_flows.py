from dpr import reviews, rules
from dpr.discovery.detect import detect
from dpr.reviews.auth_flows import flows, lifetimes, managed_provider, user_models
from dpr.walk import RepoIndex
from tests.reviews.auth_app import auth_app
from tests.reviews.helpers import write


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
