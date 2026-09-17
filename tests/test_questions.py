import pytest
import yaml

from dpr.model import Detection, Question, ScanError
from dpr.questions.catalogue import (
    answers_template,
    load_questions,
    options,
    questions_for,
    resolve,
)
from dpr.questions.prompt import ask_on_terminal

SLUGS = {"inventory", "rls", "auth", "baseline", "owasp", "leaks", "abuse"}


def test_catalogue_shape():
    questions = load_questions()
    assert len(questions) == 22
    assert len({q.id for q in questions}) == 22
    for q in questions:
        assert set(q.reviews) <= SLUGS
        assert q.type in ("choice", "multi", "text")
        assert q.why and q.who and q.text.endswith("?")
        assert all(isinstance(o, str) for o in q.static_options + q.honest_out)


def test_questions_for():
    assert [q.id for q in questions_for(["rls"])] == [
        "frontend_key_type",
        "rls_via_dashboard",
        "tables_not_in_migrations",
        "buckets_public",
    ]
    assert [q.id for q in questions_for(["leaks"])] == [
        "hosting_env_not_in_repo",
        "log_tool_access_retention",
    ]


def test_options_from_detection():
    [db_region] = [q for q in load_questions() if q.id == "db_region"]
    assert options(db_region, Detection(hosting=["vercel"])) == ["vercel", "Not sure"]


def test_resolve_from_dict():
    qs = questions_for(["rls"])
    results, warnings = resolve(
        qs,
        Detection(),
        {
            "frontend_key_type": "Anon or publishable key only",
            "rls_via_dashboard": "Not sure",
            "nonsense": 1,
        },
    )
    by_id = {r.question.id: r for r in results}
    assert [r.question.id for r in results] == [q.id for q in qs]
    assert (by_id["frontend_key_type"].open, by_id["frontend_key_type"].source) == (
        False,
        "answers",
    )
    assert (by_id["rls_via_dashboard"].open, by_id["rls_via_dashboard"].answer) == (
        True,
        "Not sure",
    )
    assert (by_id["buckets_public"].open, by_id["buckets_public"].source) == (True, "none")
    assert warnings == ["unknown answer key ignored: nonsense"]


def test_resolve_from_file_and_errors(tmp_path):
    good = tmp_path / "a.yaml"
    good.write_text("buckets_public: 'No'\n")
    results, _ = resolve(questions_for(["rls"]), Detection(), str(good))
    assert next(r for r in results if r.question.id == "buckets_public").answer == "No"
    with pytest.raises(ScanError, match="not found"):
        resolve([], Detection(), str(tmp_path / "missing.yaml"))
    bad = tmp_path / "bad.yaml"
    bad.write_text("a: [unclosed\n")
    with pytest.raises(ScanError, match="YAML"):
        resolve([], Detection(), str(bad))
    listy = tmp_path / "list.yaml"
    listy.write_text("- a\n")
    with pytest.raises(ScanError, match="mapping"):
        resolve([], Detection(), str(listy))


def test_interactive_is_capped_at_eight():
    calls = []

    def ask(question, opts):
        calls.append(question.id)
        return opts[-1] if opts else "Not sure"

    results, _ = resolve(load_questions(), Detection(), None, interactive=True, ask=ask)
    assert len(calls) == 8
    assert sum(r.source == "interactive" for r in results) == 8
    assert sum(r.source == "none" for r in results) == 14


def test_answered_by_detection():
    q = Question(
        id="x", reviews=("rls",), text="Host?", type="text", why="w", who="w", answered_by="hosting"
    )
    [result] = resolve([q], Detection(hosting=["vercel", "docker"]))[0]
    assert (result.answer, result.source, result.open) == ("vercel, docker", "detection", False)


def test_answers_template_is_valid_yaml():
    qs = questions_for(["inventory"])
    text = answers_template(qs, Detection(hosting=["vercel"]))
    assert "# Options: vercel, Not sure" in text
    assert yaml.safe_load(text) == {q.id: None for q in qs}


def test_ask_on_terminal():
    [q] = [x for x in load_questions() if x.id == "buckets_public"]
    printed = []
    assert ask_on_terminal(q, ["Yes", "No"], input_fn=lambda _: "2", output=printed.append) == "No"
    assert ask_on_terminal(q, ["Yes", "No"], input_fn=lambda _: "  ", output=printed.append) is None
    assert (
        ask_on_terminal(q, ["Yes"], input_fn=lambda _: "only avatars", output=printed.append)
        == "only avatars"
    )
    assert q.text in printed
