from dataclasses import replace

from dpr import reviews, rules
from dpr.api import review
from dpr.discovery.detect import detect
from dpr.model import Finding, Location, Tag
from dpr.report.markdown import render_markdown
from dpr.reviews import auth
from dpr.reviews.auth_flows import record_pass
from dpr.walk import RepoIndex
from tests.reviews.auth_app import auth_app
from tests.reviews.helpers import write


def context(root):
    reviews.available()
    index = RepoIndex(root)
    return rules.Context(index=index, detection=detect(index))


def cases_text(root):
    report = review(root, reviews=["auth"])
    parts = {p.title: p for p in report.sections["auth"].parts}
    return report, parts


def test_ten_cases_and_extras_are_always_written(tmp_path):
    report, parts = cases_text(auth_app(tmp_path))
    body = parts["Cases"].body
    for number in range(1, 11):
        assert f"#### CASE {number}: " in body
    assert "#### CASE 11: Public signup that no screen uses (UNVERIFIED)" in body
    assert "#### CASE 12: Second factor for staff and admin accounts (FAILS)" in body
    assert "committed-passwords" not in body and "CASE 13" not in body
    assert (
        "This app: CONFIRMED. Logout only deletes cookies (`api/app/routes/auth.py:27`, "
        "AUTH-LOGOUT-NO-REVOKE)."
    ) in body
    assert list(parts) == [
        "How to read the cases",
        "Flows read",
        "Cases",
        "Findings",
        "Executable tests",
    ]
    assert "- login: POST /auth/login (`api/app/routes/auth.py:9`)" in parts["Flows read"].body
    assert (
        "- Lifetime setting (api) jwt_access_token_expire_minutes = 30" in parts["Flows read"].body
    )
    text = render_markdown(report)
    assert "## 3. Failure path test plan" in text


def test_case_with_flow_but_no_decision_is_unverified_not_unknown(tmp_path):
    write(tmp_path, "api/requirements.txt", "fastapi\n")
    write(
        tmp_path,
        "api/app/routes/auth.py",
        'from fastapi import APIRouter\n\nrouter = APIRouter(prefix="/auth")\n\n\n'
        '@router.post("/register")\n'
        "async def register(data: RegisterRequest):\n"
        '    return {"ok": True}\n',
    )
    _, parts = cases_text(tmp_path)
    body = parts["Cases"].body
    assert "#### CASE 8: Concurrent and out-of-order operations (UNVERIFIED)" in body
    assert "This app: UNVERIFIED. The flow is at `api/app/routes/auth.py:" in body
    assert "Only a live test can decide this case:" in body


def test_case_with_no_matching_flow_is_unknown(tmp_path):
    write(tmp_path, "api/requirements.txt", "fastapi\n")
    write(
        tmp_path,
        "api/app/routes/auth.py",
        'from fastapi import APIRouter\n\nrouter = APIRouter(prefix="/auth")\n\n\n'
        '@router.post("/register")\n'
        "async def register(data: RegisterRequest):\n"
        '    return {"ok": True}\n',
    )
    _, parts = cases_text(tmp_path)
    body = parts["Cases"].body
    assert "#### CASE 1: Wrong password five times in a row (UNKNOWN)" in body
    assert "This app: UNKNOWN. No login route was found." in body


def test_flows_read_groups_lifetimes_by_app_root(tmp_path):
    auth_app(tmp_path)
    write(tmp_path, "web/package.json", '{"name": "web"}')
    write(tmp_path, "web/lib/token.ts", "jwt.sign(payload, secret, { expiresIn: '14d' })\n")
    _, parts = cases_text(tmp_path)
    body = parts["Flows read"].body
    assert "- Lifetime setting (api) jwt_access_token_expire_minutes = 30" in body
    assert "- Lifetime setting (web) expiresIn = '14d'" in body


def test_managed_provider_cases_are_unverified(tmp_path):
    write(
        tmp_path, "package.json", '{"dependencies": {"next": "14", "@supabase/supabase-js": "2"}}'
    )
    write(tmp_path, "lib/auth.ts", "export const user = () => supabase.auth.getUser()\n")
    _, parts = cases_text(tmp_path)
    assert (
        "#### CASE 2: Reset requested for an email that was never registered (UNVERIFIED)"
        in parts["Cases"].body
    )
    assert "Handled by Supabase Auth; check the provider settings" in parts["Cases"].body


def test_not_applicable_without_flows_or_provider(tmp_path):
    write(tmp_path, "app.py", "x = 1\n")
    report = review(tmp_path, reviews=["auth"])
    assert "auth" not in report.sections
    assert (
        "Review 3 (auth): not applicable, no sign-in, signup or reset routes and no auth provider "
        "found"
    ) in report.not_covered


def finding(rule_id, exploitability, line):
    return Finding(
        rule_id=rule_id,
        review="auth",
        title=f"{rule_id} title",
        tag=Tag.CONFIRMED,
        severity="medium",
        exploitability=exploitability,
        effort_minutes=5,
        locations=(Location("api/app/services/auth_service.py", line),),
        detail="d",
        fix="f",
    )


def test_failing_cases_come_first_by_exploitability_and_passes_are_named(tmp_path):
    ctx = context(auth_app(tmp_path))
    record_pass(
        ctx, 7, Tag.CONFIRMED, "The reset request carries only the token", Location("a.py", 3)
    )
    findings = [
        finding("AUTH-ENUM-SIGNUP-MESSAGE", "medium", 15),
        finding("AUTH-EMAIL-CHANGE-UNVERIFIED", "high", 24),
    ]
    body = auth.case_blocks(ctx, findings)
    assert (
        body.index("CASE 9: Email change (FAILS)")
        < body.index("CASE 4: Signup with")
        < body.index("CASE 1: Wrong password")
    )
    assert (
        "This app: CONFIRMED. AUTH-ENUM-SIGNUP-MESSAGE title (`api/app/services/auth_service.py:15`, AUTH-ENUM-SIGNUP-MESSAGE)."
        in body
    )
    assert "#### CASE 7: Reset token that belongs to someone else (PASSES)" in body
    assert "This app: CONFIRMED. The reset request carries only the token (`a.py:3`)." in body


def committed_password_app(root):
    write(root, "api/requirements.txt", "fastapi\npasslib\n")
    write(
        root,
        "api/app/db/seed.py",
        "from app.core.security import get_password_hash\n\n"
        "def seed():\n"
        "    return get_password_hash('placeholder-demo-value')\n",
    )
    write(root, "api/start.sh", "#!/bin/sh\npython -m app.db.seed\nuvicorn app.main:app\n")
    write(
        root,
        "api/app/routes/auth.py",
        "from fastapi import APIRouter, HTTPException\n\nrouter = APIRouter(prefix='/auth')\n\n\n"
        "@router.post('/login')\nasync def login(data: dict):\n"
        "    if not await check_credentials(data):\n"
        "        raise HTTPException(status_code=401, detail='Invalid email or password')\n"
        "    return {'ok': True}\n",
    )
    return root


def test_committed_password_case_fails_from_baseline_findings(tmp_path):
    report = review(committed_password_app(tmp_path))
    assert {"BASE-LITERAL-PASSWORD-HASH", "BASE-SEED-ON-START"} <= {
        f.rule_id for f in report.findings
    }
    body = {p.title: p for p in report.sections["auth"].parts}["Cases"].body
    assert "Accounts created with passwords written in the repository (FAILS)" in body
    assert "BASE-LITERAL-PASSWORD-HASH)" in body and "BASE-SEED-ON-START)" in body
    assert "placeholder-demo-value" not in render_markdown(report)


def test_committed_password_case_stays_out_when_baseline_did_not_run(tmp_path):
    report = review(committed_password_app(tmp_path), reviews=["auth"])
    body = {p.title: p for p in report.sections["auth"].parts}["Cases"].body
    assert "Accounts created with passwords written in the repository" not in body


def test_timing_findings_are_listed_only_under_their_own_flow_case(tmp_path):
    ctx = context(auth_app(tmp_path))
    sign_in = replace(
        finding("AUTH-ENUM-TIMING", "medium", 30),
        title="Sign-in response time reveals whether an account exists",
    )
    reset = replace(
        finding("AUTH-ENUM-TIMING", "medium", 40),
        title="Reset request response time reveals whether an account exists",
    )
    blocks = auth.case_blocks(ctx, [sign_in, reset]).split("#### ")
    [case1] = [b for b in blocks if b.startswith("CASE 1:")]
    [case2] = [b for b in blocks if b.startswith("CASE 2:")]
    assert "Sign-in response time" in case1 and "Reset request response time" not in case1
    assert "Reset request response time" in case2 and "Sign-in response time" not in case2
