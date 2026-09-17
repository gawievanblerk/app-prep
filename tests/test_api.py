import datetime

import pytest

from dpr import rules
from dpr.api import review
from dpr.model import ScanError
from dpr.rank import score
from tests.reviews.helpers import write


def app(tmp_path):
    write(
        tmp_path, "package.json", '{"dependencies": {"next": "14", "@supabase/supabase-js": "2"}}'
    )
    write(
        tmp_path,
        ".env.example",
        "NEXT_PUBLIC_SUPABASE_ANON_KEY=\nNEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=\n",
    )
    write(
        tmp_path, "supabase/migrations/1.sql", "create table public.notes (id int, user_id uuid);"
    )
    write(tmp_path, "app/page.tsx", "export default function Page() { return null }\n")
    return tmp_path


def files(root):
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*"))


def test_full_run(tmp_path):
    root = app(tmp_path)
    before = files(root)
    report = review(root, today=datetime.date(2026, 9, 16))
    assert files(root) == before
    assert set(report.sections) == {"leaks", "rls"}
    assert report.meta.reviews_run == ("rls", "leaks")
    assert report.meta.date == "2026-09-16"
    assert report.meta.project == root.name
    assert dict(report.meta.applicability) == {
        "inventory": "not available in this version",
        "rls": "runs",
        "auth": "not available in this version",
        "baseline": "not available in this version",
        "owasp": "not available in this version",
        "leaks": "runs",
        "abuse": "not available in this version",
    }
    assert [s for s, _ in report.meta.applicability] == [
        "inventory",
        "rls",
        "auth",
        "baseline",
        "owasp",
        "leaks",
        "abuse",
    ]
    rule_ids = {f.rule_id for f in report.findings}
    assert {"LEAK-PUBLIC-SECRET", "RLS-TABLE-OFF"} <= rule_ids
    scores = [score(f) for f in report.findings]
    assert scores == sorted(scores, reverse=True)
    assert "Review 1 (inventory): not available in this version" in report.not_covered
    assert len(report.questions) == 22
    assert all(q.open for q in report.questions)


def test_selected_reviews_only(tmp_path):
    report = review(app(tmp_path), reviews=["leaks"])
    assert set(report.sections) == {"leaks"}
    assert dict(report.meta.applicability)["rls"] == "not selected"
    assert {q.question.id for q in report.questions} == {
        "hosting_env_not_in_repo",
        "log_tool_access_retention",
    }
    assert not any(f.review == "rls" for f in report.findings)


def test_not_applicable_reason(tmp_path):
    write(tmp_path, "a.py", "x = 1\n")
    report = review(tmp_path, reviews=[2])
    assert report.sections == {}
    assert (
        dict(report.meta.applicability)["rls"]
        == "not applicable, no SQL tables, Supabase client or database dump found"
    )


def test_answers_and_warnings(tmp_path):
    report = review(app(tmp_path), reviews=["rls"], answers={"buckets_public": "No", "typo": 1})
    answered = {q.question.id: q for q in report.questions}
    assert answered["buckets_public"].open is False
    assert "unknown answer key ignored: typo" in report.not_covered


def test_validation(tmp_path):
    root = app(tmp_path)
    with pytest.raises(ScanError, match="i-own-this-host"):
        review(root, url="https://example.com")
    with pytest.raises(ScanError, match="semgrep rules folder"):
        review(root, semgrep=str(tmp_path / "nope"))
    with pytest.raises(ScanError, match="database dump"):
        review(root, db_dump=str(tmp_path / "nope.csv"))
    with pytest.raises(ScanError, match="unknown review"):
        review(root, reviews=["9"])


def test_url_note_until_baseline_exists(tmp_path):
    report = review(app(tmp_path), url="https://example.com", owns_host=True)
    assert any("Live header read skipped" in n for n in report.not_covered)


def test_sanity_check_propagates(tmp_path):
    write(tmp_path, "package.json", "{}")
    with pytest.raises(ScanError, match="package.json"):
        review(tmp_path)


def test_failing_rule_is_recorded_when_not_strict(tmp_path, monkeypatch):
    monkeypatch.delenv("DPR_STRICT")
    root = app(tmp_path)
    review(root, reviews=["leaks"])

    def boom(ctx):
        raise RuntimeError("x")

    monkeypatch.setitem(rules.CHECKS, "leaks", [*rules.CHECKS["leaks"], ("TEST-BOOM", boom)])
    report = review(root, reviews=["leaks"])
    assert "rule TEST-BOOM failed: RuntimeError" in report.not_covered


def test_failing_review_module_is_recorded_when_not_strict(tmp_path, monkeypatch):
    from dpr.reviews import leaks

    root = app(tmp_path)

    def boom(ctx):
        raise RuntimeError("x")

    monkeypatch.setattr(leaks, "run", boom)
    monkeypatch.delenv("DPR_STRICT")
    report = review(root)
    assert "review leaks failed: RuntimeError" in report.not_covered
    assert set(report.sections) == {"rls"}
    assert not any(f.review == "leaks" for f in report.findings)
    assert dict(report.meta.applicability)["leaks"] == "failed: RuntimeError"
    monkeypatch.setenv("DPR_STRICT", "1")
    with pytest.raises(RuntimeError):
        review(root)
