from tests.reviews.auth_app import SERVICE, auth_app
from tests.reviews.helpers import findings_for, write


def locations(found):
    return sorted(str(f.locations[0]) for f in found)


def test_signup_message_that_confirms_an_account(tmp_path):
    service = SERVICE.replace(
        'raise ValueError("Check your email to continue")',
        'raise ValueError("An account with this email already exists")',
    )
    auth_app(tmp_path, service=service)
    [finding] = findings_for(tmp_path, "auth", "AUTH-ENUM-SIGNUP-MESSAGE")
    assert (finding.tag.value, str(finding.locations[0])) == (
        "CONFIRMED",
        "api/app/services/auth_service.py:16",
    )
    assert str(finding.locations[-1]) == "api/app/routes/auth.py:17"


def test_generic_signup_message_and_logged_text_are_not_reported(tmp_path):
    service = SERVICE.replace(
        'raise ValueError("Check your email to continue")',
        'logger.info("user already exists")\n            return {"message": "Check your email"}',
    )
    auth_app(tmp_path, service=service)
    assert findings_for(tmp_path, "auth", "AUTH-ENUM-SIGNUP-MESSAGE") == []


def test_javascript_signup_and_reset_messages(tmp_path):
    write(
        tmp_path,
        "server/auth.js",
        "router.post('/signup', async (req, res) => {\n"
        "  if (await db.user.findFirst({ where: { email: req.body.email } })) {\n"
        "    console.log('email already registered')\n"
        "    return res.status(409).json({ error: 'Email already registered' })\n  }\n"
        "  res.json({ ok: true })\n})\n"
        "router.post('/forgot-password', async (req, res) => {\n"
        "  return res.status(404).json({ error: 'No account with that email' })\n})\n"
        "router.post('/password/forgot', async (req, res) => res.json({ message: 'Check your inbox' }))\n",
    )
    assert locations(findings_for(tmp_path, "auth", "AUTH-ENUM-SIGNUP-MESSAGE")) == [
        "server/auth.js:4"
    ]
    assert locations(findings_for(tmp_path, "auth", "AUTH-ENUM-RESET-MESSAGE")) == [
        "server/auth.js:9"
    ]


def test_locked_account_status_and_message(tmp_path):
    routes_423 = (
        "from fastapi import APIRouter, HTTPException, status\nrouter = APIRouter()\n"
        "@router.post('/login')\nasync def login(data):\n"
        "    if await is_locked(data.email):\n"
        "        raise HTTPException(status_code=status.HTTP_423_LOCKED, detail='Try later')\n"
        "    raise HTTPException(status_code=401, detail='Invalid email or password')\n"
    )
    write(tmp_path, "a/routes.py", routes_423)
    write(
        tmp_path,
        "b/routes.js",
        "router.post('/signin', (req, res) => {\n"
        "  if (locked) return res.status(403).json({ error: 'Too many failed attempts' })\n})\n",
    )
    assert locations(findings_for(tmp_path, "auth", "AUTH-ENUM-LOCKOUT-STATUS")) == [
        "a/routes.py:6",
        "b/routes.js:2",
    ]


def test_lock_recorded_server_side_with_a_generic_response_is_fine(tmp_path):
    write(
        tmp_path,
        "a/routes.py",
        "from fastapi import APIRouter, HTTPException\nrouter = APIRouter()\n"
        "@router.post('/login')\nasync def login(data):\n"
        "    if await is_locked(data.email):\n"
        "        logger.warning('account locked until later')\n"
        "        raise HTTPException(status_code=401, detail='Invalid email or password')\n",
    )
    assert findings_for(tmp_path, "auth", "AUTH-ENUM-LOCKOUT-STATUS") == []


def test_sign_in_timing_needs_an_early_return_without_a_dummy_hash(tmp_path):
    auth_app(tmp_path)
    [finding] = findings_for(tmp_path, "auth", "AUTH-ENUM-TIMING")
    assert (finding.tag.value, str(finding.locations[0])) == (
        "INFERRED",
        "api/app/services/auth_service.py:4",
    )
    assert finding.title == "Sign-in response time reveals whether an account exists"
    dummy = SERVICE.replace(
        "        if user is None:\n            return None\n",
        "        if user is None:\n            verify_password(password, DUMMY_HASH)\n"
        "            return None\n",
    )
    auth_app(tmp_path, service=dummy)
    assert findings_for(tmp_path, "auth", "AUTH-ENUM-TIMING") == []


def test_reset_timing_inline_send_versus_background_task(tmp_path):
    inline = SERVICE.replace(
        "    async def initiate_password_reset(self, email):\n"
        "        user = await self.get_user_by_email(email)\n        return user\n",
        "    async def initiate_password_reset(self, email):\n"
        "        user = await self.get_user_by_email(email)\n"
        "        if not user:\n            return None\n"
        "        await mailer.send_reset_email(user.email)\n",
    )
    auth_app(tmp_path, service=inline)
    found = findings_for(tmp_path, "auth", "AUTH-ENUM-TIMING")
    assert "Reset request response time reveals whether an account exists" in [
        f.title for f in found
    ]
    queued = inline.replace(
        "        await mailer.send_reset_email(user.email)\n",
        "        await queue.enqueue(mailer.send_reset_email, user.email)\n",
    )
    auth_app(tmp_path, service=queued)
    assert all(
        f.title.startswith("Sign-in") for f in findings_for(tmp_path, "auth", "AUTH-ENUM-TIMING")
    )


def test_one_time_token_lookup_is_not_an_unscoped_record(tmp_path):
    write(
        tmp_path,
        "server/verify.js",
        "router.get('/verify', async (req, res) => {\n"
        "  const user = await prisma.user.findFirst({ where: { verifyToken: req.query.token } })\n"
        "  res.json({ ok: !!user })\n})\n",
    )
    assert findings_for(tmp_path, "owasp", "OWASP-A01-UNSCOPED-QUERY") == []


def test_public_email_form_is_not_reported_as_paid_without_sign_in(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"express": "4", "nodemailer": "6"}}')
    write(
        tmp_path,
        "server/app.js",
        "import nodemailer from 'nodemailer'\nconst mail = nodemailer.createTransport({})\n"
        "app.post('/forgot-password', async (req, res) => {\n"
        "  await mail.sendMail({ to: req.body.email })\n  res.json({ ok: true })\n})\n"
        "app.post('/campaigns/send', async (req, res) => {\n"
        "  await mail.sendMail({ to: req.body.list })\n  res.json({ ok: true })\n})\n",
    )
    found = findings_for(tmp_path, "abuse", "ABUSE-PAID-UNAUTH")
    assert [str(f.locations[0]) for f in found] == ["server/app.js:7"]
    assert len(findings_for(tmp_path, "abuse", "ABUSE-PAID-UNLIMITED")) == 2
