from dpr.api import review
from dpr.cli import summary_lines
from dpr.model import (
    AppRoot,
    Detection,
    Finding,
    Location,
    Part,
    Report,
    ReportMeta,
    ReviewSection,
)
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


def unscoped(path, model, line):
    return finding(
        "OWASP-A01-UNSCOPED-QUERY",
        "api/app/routes/items.py",
        line,
        severity="high",
        review="owasp",
        title=f"GET {path} loads {model} by item_id with no owner check",
    )


def test_rule_issue_title_names_every_member_when_titles_differ():
    issues = build_register(
        [unscoped("/invoices/{item_id}", "Invoice", 5), unscoped("/notes/{item_id}", "Note", 9)],
        ROOTS,
    )
    [issue] = issues
    assert issue.count == 2
    assert issue.title == (
        "GET /invoices/{item_id} loads Invoice by item_id with no owner check"
        " (also GET /notes/{item_id})"
    )


def test_rule_issue_title_lists_three_other_subjects_then_a_count():
    paths = [f"/r{n}/{{item_id}}" for n in range(6)]
    issues = build_register([unscoped(p, "Record", n + 1) for n, p in enumerate(paths)], ROOTS)
    [issue] = issues
    assert issue.title.endswith(
        "(also GET /r1/{item_id}, GET /r2/{item_id}, GET /r3/{item_id} and 2 more)"
    )


def test_rule_issue_title_names_each_sdk_and_keeps_equal_titles():
    sdks = [
        finding(
            "INV-SDK-RECEIVES-PII",
            "api/app/mail.py",
            review="inventory",
            title=f"{name} receives personal data",
        )
        for name in ("mailer-sdk", "llm-sdk")
    ]
    [issue] = build_register(sdks, ROOTS)
    assert issue.title == "mailer-sdk receives personal data (also llm-sdk)"
    same = [
        finding(
            "ABUSE-ERROR-LEAK", f"api/app/{n}.py", title="Exception text returned to the caller"
        )
        for n in "ab"
    ]
    [issue] = build_register(same, ROOTS)
    assert issue.title == "Exception text returned to the caller"


def test_rule_issue_title_counts_members_whose_title_has_another_shape():
    shaped = [
        finding("ABUSE-ERROR-LEAK", "api/app/a.py", title="First wording"),
        finding("ABUSE-ERROR-LEAK", "api/app/b.py", title="Second wording"),
    ]
    [issue] = build_register(shaped, ROOTS)
    assert issue.title == "First wording (and 1 similar finding)"


def test_register_names_both_unscoped_routes_of_a_scan(tmp_path):
    write(tmp_path, "api/requirements.txt", "fastapi\nsqlalchemy\n")
    routes = ["from fastapi import APIRouter, Depends\n\nrouter = APIRouter()\n"]
    for name, model in (("invoices", "Invoice"), ("notes", "Note")):
        routes.append(
            f"\n\n@router.get('/{name}/{{item_id}}')\n"
            f"async def get_{name}(item_id: int, user=Depends(get_current_user)):\n"
            f"    return await db.get({model}, item_id)\n"
        )
    write(tmp_path, "api/app/routes/items.py", "".join(routes))
    write(
        tmp_path,
        "api/app/models.py",
        "from sqlalchemy.orm import Mapped, mapped_column\nfrom sqlalchemy import Integer\n\n"
        "class Invoice(Base):\n    __tablename__ = 'invoices'\n"
        "    id: Mapped[int] = mapped_column(Integer, primary_key=True)\n"
        "    user_id: Mapped[int] = mapped_column(Integer)\n\n"
        "class Note(Base):\n    __tablename__ = 'notes'\n"
        "    id: Mapped[int] = mapped_column(Integer, primary_key=True)\n"
        "    user_id: Mapped[int] = mapped_column(Integer)\n",
    )
    report = review(tmp_path, reviews=["owasp"])
    [issue] = [i for i in report.register if "OWASP-A01-UNSCOPED-QUERY" in i.findings]
    assert issue.count == 2
    assert "/invoices/{item_id}" in issue.title and "/notes/{item_id}" in issue.title


def test_linked_scope_joins_every_literal_first_hashed_in_one_seed_file():
    literals = [
        finding(
            "BASE-LITERAL-PASSWORD-HASH",
            "api/app/db/seed.py",
            line,
            severity="critical",
            review="baseline",
            title="Account passwords are written in api/app/db/seed.py",
            more=(Location("api/scripts/reset.py", line),) if line == 12 else (),
        )
        for line in (4, 8, 12)
    ]
    start = finding(
        "BASE-SEED-ON-START",
        "api/startup.sh",
        severity="critical",
        tag="INFERRED",
        review="baseline",
        more=(Location("api/app/db/seed.py", 4),),
    )
    other = finding(
        "BASE-LITERAL-PASSWORD-HASH",
        "api/scripts/migrate.py",
        9,
        severity="critical",
        review="baseline",
        title="Account passwords are written in api/scripts/migrate.py",
    )
    issues = build_register([*literals, start, other], ROOTS)
    assert sorted((i.title, i.count) for i in issues) == [
        ("Account passwords are written in api/app/db/seed.py, and a start command runs it", 4),
        ("Account passwords are written in api/scripts/migrate.py", 1),
    ]
    assert [i.severity.value for i in issues] == ["critical", "critical"]


def test_sibling_issues_label_the_repository_root_app():
    roots = [AppRoot("", "server", True), AppRoot("api", "server", True)]
    issues = build_register(
        [finding("ABUSE-ERROR-LEAK", "app/main.py"), finding("ABUSE-ERROR-LEAK", "api/main.py")],
        roots,
    )
    assert sorted(i.title for i in issues) == [
        "ABUSE-ERROR-LEAK title (api)",
        "ABUSE-ERROR-LEAK title (repository root)",
    ]


def test_unpinned_chain_title_reads_as_either_rule():
    [issue] = build_register(
        [finding("OWASP-A08-UNPINNED-DEPS", "api/requirements.txt", review="owasp")], ROOTS
    )
    assert issue.title == "Unpinned dependencies or installs"


def test_role_gated_unscoped_lookups_form_their_own_issue_per_app():
    gated = [
        finding(
            "OWASP-A01-UNSCOPED-QUERY",
            "api/app/views.py",
            line,
            severity="low",
            tag="INFERRED",
            review="owasp",
            title=f"ANY /staff/{line} loads Policy by policy_id with no owner check",
        )
        for line in (3, 9, 20)
    ]
    issues = build_register([unscoped("/items/<id>", "Item", 5), *gated], ROOTS)
    titles = sorted((i.title, i.count, i.severity.value) for i in issues)
    assert titles == [
        ("GET /items/<id> loads Item by item_id with no owner check", 1, "high"),
        ("Role-gated back-office routes load records with no owner check", 3, "low"),
    ]


def test_markdown_folds_role_gated_tenant_findings_into_one_entry():
    gated = [
        finding(
            "OWASP-A01-UNSCOPED-QUERY",
            f"api/app/{name}.py",
            line,
            severity="medium",
            tag="INFERRED",
            review="owasp",
            title=f"ANY /staff/{line} loads Brokerage by brokerage_id with no owner check",
        )
        for name, line in (("views", 3), ("views", 9), ("admin", 20))
    ]
    findings = [unscoped("/items/<id>", "Item", 5), *gated]
    report = Report(
        meta=ReportMeta(
            project="shop",
            scope=".",
            revision="abc",
            date="2026-09-23",
            reviews_run=("owasp",),
            method="",
            applicability=(),
        ),
        detection=Detection(app_roots=ROOTS),
        findings=findings,
        sections={"owasp": ReviewSection("owasp", [Part("findings", "Findings")])},
        questions=[],
        not_covered=[],
    )
    text = render_markdown(report)
    body = text[text.index("## 5. OWASP") :]
    assert body.count("#### FINDING") == 2
    assert (
        "#### FINDING 2: Role-gated routes reach any brokerage, company or branch by its id "
        "(3 findings)" in body
    )
    assert "- `api/app/views.py`: ANY /staff/3 (line 3), ANY /staff/9 (line 9)" in body
    assert "- `api/app/admin.py`: ANY /staff/20 (line 20)" in body
