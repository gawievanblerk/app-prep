from dpr.api import review
from dpr.cli import summary_lines
from dpr.model import AppRoot, Finding, Location
from dpr.report.markdown import render_markdown
from dpr.report.register import build_register
from tests.reviews.helpers import write

ROOTS = [AppRoot("api", "server", True), AppRoot("worker", "server", True)]


def finding(rule_id, file, line=1, severity="medium", tag="CONFIRMED", review="abuse", **extra):
    return Finding(
        rule_id=rule_id,
        review=review,
        title=extra.pop("title", f"{rule_id} title"),
        tag=tag,
        severity=severity,
        exploitability=extra.pop("exploitability", "medium"),
        effort_minutes=10,
        locations=(Location(file, line), *extra.pop("more", ())),
        detail="d",
        fix="f",
        proof_needed="p" if tag == "INFERRED" else None,
    )


def test_chains_group_per_app_and_rules_group_per_app():
    issues = build_register(
        [
            finding("ABUSE-INMEMORY-LIMITER", "api/app/limit.py", tag="INFERRED"),
            finding("ABUSE-LIMITER-PROXY-IP", "api/app/limit.py", 2),
            finding("ABUSE-INMEMORY-LIMITER", "worker/limit.py"),
            finding("ABUSE-ERROR-LEAK", "api/app/a.py"),
            finding("ABUSE-ERROR-LEAK", "api/app/b.py"),
        ],
        ROOTS,
    )
    by_title = {i.title: i for i in issues}
    api = by_title["Rate limits do not hold in production (api)"]
    assert (api.count, api.tags, api.findings) == (
        2,
        "CONFIRMED and INFERRED",
        ("ABUSE-LIMITER-PROXY-IP", "ABUSE-INMEMORY-LIMITER"),
    )
    assert by_title["Rate limits do not hold in production (worker)"].count == 1
    assert by_title["ABUSE-ERROR-LEAK title"].count == 2
    assert [i.id for i in issues] == ["F-01", "F-02", "F-03"]


def test_repo_scope_and_ranking_by_best_score():
    issues = build_register(
        [
            finding("BASE-HEADER-MISSING-HSTS", "api/main.py", severity="low", review="baseline"),
            finding("BASE-HEADER-MISSING-CSP", "worker/app.py", review="baseline"),
            finding("OWASP-A01-UNSCOPED-QUERY", "api/r.py", severity="high", review="owasp"),
        ],
        ROOTS,
    )
    assert [(i.id, i.severity.value, i.reviews) for i in issues] == [
        ("F-01", "high", (5,)),
        ("F-02", "medium", (4,)),
    ]
    assert issues[1].title == "Security headers or HTTPS enforcement are missing or weak"


def test_headers_chain_title_holds_for_a_weak_csp_alone():
    issues = build_register(
        [finding("BASE-CSP-WEAK", "api/main.py", review="baseline")],
        ROOTS,
    )
    [issue] = issues
    assert issue.title == "Security headers or HTTPS enforcement are missing or weak"


def test_tokens_chain_title_holds_for_a_reusable_token_alone():
    issues = build_register(
        [finding("AUTH-VERIFY-REUSABLE", "api/auth.py", review="auth")],
        ROOTS,
    )
    [issue] = issues
    assert issue.title == "One-time tokens are stored in plain text, never expire or can be reused"


def test_chain_title_holds_for_a_subset_of_its_rules():
    issues = build_register(
        [
            finding("ABUSE-PAID-UNLIMITED", "api/app/chat.py", severity="high", review="abuse"),
            finding(
                "ABUSE-NO-KILL-SWITCH", "api/app/chat.py", 2, severity="medium", review="abuse"
            ),
        ],
        ROOTS,
    )
    [issue] = issues
    assert issue.title == "Paid endpoints can run up the bill"
    assert "sign-in" not in issue.title


def test_linked_scope_attaches_start_commands_to_the_password_they_seed():
    seed = finding(
        "BASE-LITERAL-PASSWORD-HASH",
        "api/app/db/seed.py",
        4,
        severity="critical",
        review="baseline",
        title="Account passwords are written in api/app/db/seed.py",
    )
    migrate = finding(
        "BASE-LITERAL-PASSWORD-HASH",
        "api/scripts/migrate.py",
        9,
        severity="critical",
        review="baseline",
        title="Account passwords are written in api/scripts/migrate.py",
    )
    start = finding(
        "BASE-SEED-ON-START",
        "api/startup.sh",
        severity="critical",
        tag="INFERRED",
        review="baseline",
        more=(Location("api/app/db/seed.py", 4),),
    )
    issues = build_register([seed, migrate, start], ROOTS)
    titles = sorted(i.title for i in issues)
    assert titles == [
        "Account passwords are written in api/app/db/seed.py, and a start command runs it",
        "Account passwords are written in api/scripts/migrate.py",
    ]


def app(root):
    write(root, ".env.example", "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=\n")
    write(root, "supabase/migrations/1.sql", "create table public.notes (id int, user_id uuid);")
    write(root, "app/page.tsx", "export default function Page() { return null }\n")
    return root


def test_summary_counts_issues_and_prints_the_register(tmp_path):
    report = review(app(tmp_path))
    text = render_markdown(report)
    summary = text[text.index("## Summary") : text.index("## Evidence tags")]
    assert f"They group {len(report.findings)} findings" in summary
    assert "### Findings register" in summary
    assert "| ID | Severity | Tag | Title | Reviews | Findings |" in summary
    assert "about" in summary and ", F-01)" in summary
    line = summary_lines(report, [], None)[0]
    assert line.endswith(f", {len(report.register)} distinct issues")
