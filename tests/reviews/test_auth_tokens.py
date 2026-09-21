from dpr.api import review
from dpr.reviews.auth_tokens import token_column
from tests.reviews.helpers import findings_for, write

ROUTES = (
    "from fastapi import APIRouter\nfrom app.service import Accounts\nrouter = APIRouter()\n\n"
    "@router.post('/reset-password')\nasync def reset(data):\n"
    "    return await Accounts().reset(data)\n\n"
    "@router.post('/verify-email')\nasync def verify(token: str):\n"
    "    return await Accounts().verify(token)\n"
)


def app(root, service):
    write(root, "api/requirements.txt", "fastapi\n")
    write(root, "api/app/routes.py", ROUTES)
    write(root, "api/app/service.py", service)
    return root


PLAIN = (
    "class Accounts:\n"
    "    async def reset(self, data):\n"
    "        query = select(User).where(User.password_reset_token == data.token)\n"
    "        user = (await self.db.execute(query)).scalar_one()\n"
    "        user.password_hash = hash_password(data.new_password)\n\n"
    "    async def verify(self, token):\n"
    "        user = await User.objects.aget(email_verification_token=token)\n"
    "        user.verified = True\n"
)
SAFE = (
    "class Accounts:\n"
    "    async def reset(self, data):\n"
    "        query = select(User).where(User.reset_token_hash == digest(data.token))\n"
    "        user = (await self.db.execute(query)).scalar_one()\n"
    "        if datetime.now(timezone.utc) - user.reset_sent_at > LIFETIME:\n"
    "            raise HTTPException(status_code=400, detail='expired')\n"
    "        user.reset_token_hash = None\n\n"
    "    async def verify(self, token):\n"
    "        user = await User.objects.aget(verification_token_hash=digest(token))\n"
    "        if user.created_at < now() - LIFETIME:\n            raise Expired()\n"
    "        user.verification_token_hash = None\n"
)


def test_token_column_names():
    assert token_column("password_reset_token") and token_column("verifyToken")
    assert token_column("email_verification_token") and token_column("inviteToken")
    assert not token_column("reset_token_hash") and not token_column("access_token")
    assert not token_column("csrf_token")


def test_plaintext_comparisons_are_confirmed_per_flow(tmp_path):
    app(tmp_path, PLAIN)
    found = {f.title: f for f in findings_for(tmp_path, "auth", "AUTH-TOKEN-PLAINTEXT")}
    assert set(found) == {
        "Reset tokens are stored and compared in plain text",
        "Verification tokens are stored and compared in plain text",
    }
    reset = found["Reset tokens are stored and compared in plain text"]
    assert (reset.tag.value, str(reset.locations[0])) == ("CONFIRMED", "api/app/service.py:3")
    verify = found["Verification tokens are stored and compared in plain text"]
    assert str(verify.locations[0]) == "api/app/service.py:8"


def test_hashed_tokens_with_expiry_and_consumption_pass(tmp_path):
    app(tmp_path, SAFE)
    for rule_id in (
        "AUTH-TOKEN-PLAINTEXT",
        "AUTH-RESET-NO-EXPIRY",
        "AUTH-VERIFY-NO-EXPIRY",
        "AUTH-VERIFY-REUSABLE",
        "AUTH-RESET-TRUSTS-EMAIL",
    ):
        assert findings_for(tmp_path, "auth", rule_id) == [], rule_id
    cases = {p.title: p for p in review(tmp_path, reviews=["auth"]).sections["auth"].parts}
    body = cases["Cases"].body
    assert "#### CASE 6: Reset link opened after it expired (PASSES)" in body
    assert "#### CASE 3: Verification link clicked twice (PASSES)" in body
    assert "#### CASE 7: Reset token that belongs to someone else (PASSES)" in body


def test_missing_expiry_and_reuse_are_inferred(tmp_path):
    app(tmp_path, PLAIN)
    [reset] = findings_for(tmp_path, "auth", "AUTH-RESET-NO-EXPIRY")
    [verify] = findings_for(tmp_path, "auth", "AUTH-VERIFY-NO-EXPIRY")
    [reusable] = findings_for(tmp_path, "auth", "AUTH-VERIFY-REUSABLE")
    assert (reset.tag.value, reset.severity.value, str(reset.locations[0])) == (
        "INFERRED",
        "medium",
        "api/app/routes.py:6",
    )
    assert str(verify.locations[0]) == "api/app/routes.py:10"
    assert reusable.proof_needed


def test_case_3_and_6_split_plaintext_findings_by_flow(tmp_path):
    service = SAFE.replace(
        "aget(verification_token_hash=digest(token))", "aget(verification_token=token)"
    )
    app(tmp_path, service)
    body = {p.title: p for p in review(tmp_path, reviews=["auth"]).sections["auth"].parts}[
        "Cases"
    ].body
    assert "#### CASE 3: Verification link clicked twice (FAILS)" in body
    assert "#### CASE 6: Reset link opened after it expired (PASSES)" in body


def test_reset_keyed_by_the_email_field(tmp_path):
    write(
        tmp_path,
        "server/reset.js",
        "router.post('/reset-password', async (req, res) => {\n"
        "  const user = await prisma.user.findFirst({ where: { resetToken: req.body.token } })\n"
        "  if (!user) return res.status(400).json({})\n"
        "  await prisma.user.update({ where: { email: req.body.email }, data: { hash } })\n})\n",
    )
    [finding] = findings_for(tmp_path, "auth", "AUTH-RESET-TRUSTS-EMAIL")
    assert (finding.tag.value, finding.severity.value) == ("INFERRED", "high")
    assert [str(loc) for loc in finding.locations[:2]] == ["server/reset.js:4", "server/reset.js:2"]


def test_email_and_token_in_one_query_is_not_trusting_email(tmp_path):
    service = PLAIN.replace(
        "where(User.password_reset_token == data.token)",
        "where(User.email == data.email, User.password_reset_token == data.token)",
    )
    app(tmp_path, service)
    assert findings_for(tmp_path, "auth", "AUTH-RESET-TRUSTS-EMAIL") == []


def test_digest_and_sha256_reset_columns_give_case_7_a_pass(tmp_path):
    for column in ("reset_token_digest", "reset_token_sha256"):
        service = SAFE.replace("reset_token_hash", column)
        app(tmp_path, service)
        assert findings_for(tmp_path, "auth", "AUTH-TOKEN-PLAINTEXT") == [], column
        body = {p.title: p for p in review(tmp_path, reviews=["auth"]).sections["auth"].parts}[
            "Cases"
        ].body
        assert "#### CASE 7: Reset token that belongs to someone else (PASSES)" in body, column
        assert "api/app/service.py:3" in body, column
