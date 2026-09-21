from dpr import reviews, rules
from dpr.api import review
from dpr.discovery.detect import detect
from dpr.model import Finding, Location, Tag
from dpr.report.markdown import render_markdown
from dpr.reviews import auth
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
    assert "#### CASE 11: Public signup that no screen uses (UNKNOWN)" in body
    assert "#### CASE 12: Second factor for staff and admin accounts (UNKNOWN)" in body
    assert "committed-passwords" not in body and "CASE 13" not in body
    assert "This app: UNKNOWN. The flow is at `api/app/routes/auth.py:9`" in body
    assert list(parts) == [
        "How to read the cases",
        "Flows read",
        "Cases",
        "Findings",
        "Executable tests",
    ]
    assert "- login: POST /auth/login (`api/app/routes/auth.py:9`)" in parts["Flows read"].body
    text = render_markdown(report)
    assert "## 3. Failure path test plan" in text


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
    auth.record_pass(
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
