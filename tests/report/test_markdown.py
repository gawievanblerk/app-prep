from dpr.model import (
    Detection,
    Finding,
    Location,
    Part,
    Question,
    QuestionResult,
    Report,
    ReportMeta,
    ReviewSection,
)
from dpr.report.markdown import BANNED_PHRASES, render_markdown


def finding(rule_id, review, sev, title, **extra):
    base = dict(
        rule_id=rule_id,
        review=review,
        title=title,
        tag="CONFIRMED",
        severity=sev,
        exploitability="high",
        effort_minutes=5,
        locations=(Location("a.ts", 3),),
        detail="Detail text.",
        fix="Fix text.",
    )
    base.update(extra)
    return Finding(**base)


def report():
    q_open = Question(
        id="q1",
        reviews=("rls",),
        text="Are buckets public?",
        type="choice",
        why="Dashboards.",
        who="Admin | owner",
    )
    q_done = Question(
        id="q2", reviews=("rls",), text="Which key ships?", type="choice", why="Env.", who="Ops"
    )
    return Report(
        meta=ReportMeta(
            project="shop",
            scope=".",
            revision="abc123",
            date="2026-09-16",
            reviews_run=("rls", "leaks"),
            method="Static analysis of the repository",
            applicability=(
                ("inventory", "not available in this version"),
                ("rls", "runs"),
                ("leaks", "runs"),
            ),
        ),
        detection=Detection(
            frameworks=["next"], databases=["supabase"], languages={"javascript/typescript": 4}
        ),
        findings=[
            finding(
                "RLS-TABLE-OFF",
                "rls",
                "critical",
                "RLS off on public.notes",
                fix="```sql\nalter table public.notes enable row level security;\n```",
            ),
            finding(
                "LEAK-LOGGED-PII",
                "leaks",
                "high",
                "Log call",
                tag="INFERRED",
                proof_needed="Check it.",
                snippet="console.error(body)",
            ),
            finding(
                "LEAK-PUBLIC-SECRET", "leaks", "low", "Public secret", verify="Search the bundle."
            ),
        ],
        sections={
            "leaks": ReviewSection("leaks", [Part("findings", "Leaks")]),
            "rls": ReviewSection(
                "rls",
                [
                    Part(
                        "table",
                        "Table protection status",
                        columns=("Table", "Verdict"),
                        rows=(("public.notes", "exposed | bad"),),
                    ),
                    Part("findings", "Policy defects"),
                    Part("text", "Confirm in the database", body="Run the queries."),
                ],
            ),
        },
        questions=[
            QuestionResult(q_open, None, "none", True),
            QuestionResult(q_done, "Anon only", "answers", False),
        ],
        not_covered=["big.js: larger than 1 MB"],
    )


def test_header_summary_and_top_fixes():
    text = render_markdown(report())
    assert text.startswith(
        "# Data Protection Review: shop\n\nDate: 2026-09-16\nScope: . @ abc123\n"
    )
    assert "Reviews run: rls, leaks" in text
    assert (
        "| Critical | 1 |" in text
        and "| High | 1 |" in text
        and "| Open questions (UNKNOWN) | 1 |" in text
    )
    assert "1. RLS off on public.notes (`a.ts:3`, about 5 min)" in text
    assert "not legal advice" in text


def test_sections_in_number_order_with_tables_and_blocks():
    text = render_markdown(report())
    assert text.index("## 2. Database lock check") < text.index("## 6. Leak hunt")
    assert "| public.notes | exposed \\| bad |" in text
    assert "#### RLS 1: RLS off on public.notes" in text
    leaks = text[text.index("## 6. Leak hunt") :]
    assert leaks.index("#### LEAK 1: Public secret") < leaks.index("#### LEAK 2: Log call")
    assert "Proof needed: Check it." in text
    assert "```text\nconsole.error(body)\n```" in text
    assert "```sql\nalter table public.notes enable row level security;\n```" in text
    assert "- Review 2, Database lock check: runs" in text


def test_questions_and_not_covered():
    text = render_markdown(report())
    assert "- Which key ships? Anon only (from the answers file)" in text
    assert "| Are buckets public? | Dashboards. | Admin \\| owner |" in text
    assert "- big.js: larger than 1 MB" in text
    assert "- Systems outside this repository" in text


def test_no_triple_newlines_legal_phrases_or_em_dashes():
    text = render_markdown(report())
    assert "\n\n\n" not in text
    assert "\u2014" not in text
    assert not any(p in text.lower() for p in BANNED_PHRASES)


def test_empty_report():
    r = report()
    r.findings, r.sections, r.questions, r.not_covered = [], {}, [], []
    text = render_markdown(r)
    assert "No findings." in text
    assert "### Still open: needs a human\n\nNone." in text


def test_snippet_fence_is_longer_than_any_backtick_run_inside():
    r = report()
    code = "const md = `a ``` b ```` c`"
    r.findings = [
        finding(
            "LEAK-LOGGED-PII",
            "leaks",
            "high",
            "Log call",
            tag="INFERRED",
            proof_needed="Check it.",
            snippet=code,
        )
    ]
    text = render_markdown(r)
    assert f"`````text\n{code}\n`````" in text
