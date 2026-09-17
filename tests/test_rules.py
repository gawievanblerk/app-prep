import pytest

from dpr import rules
from dpr.model import Detection, Location, Tag

TEXT = {
    "T-ONE": {
        "title": "Key ${name} exposed",
        "effort_minutes": 5,
        "detail": "Found ${name}.",
        "fix": "Rename ${name}. Keep $ANON_KEY as is.",
        "proof_needed": "Check it.",
    },
    "T-BOOM": {"title": "boom", "effort_minutes": 1, "fix": "none"},
}


@pytest.fixture
def registry(monkeypatch):
    monkeypatch.setattr(rules, "SPECS", {})
    monkeypatch.setattr(rules, "CHECKS", {})
    monkeypatch.setattr(rules, "_OWNERS", {})
    monkeypatch.setattr(rules, "_all_rule_text", lambda: TEXT)
    return rules


def ctx():
    return rules.Context(index=None, detection=Detection())


def test_make_finding_fills_text_and_defaults(registry):
    @registry.rule("T-ONE", review="leaks", severity="high", exploitability="medium")
    def check(c):
        yield registry.make_finding(
            "T-ONE", tag="CONFIRMED", locations=[Location("a.ts", 2)], name="NEXT_PUBLIC_X"
        )

    [finding] = registry.run_checks("leaks", ctx())
    assert finding.title == "Key NEXT_PUBLIC_X exposed"
    assert finding.detail == "Found NEXT_PUBLIC_X."
    assert finding.fix == "Rename NEXT_PUBLIC_X. Keep $ANON_KEY as is."
    assert finding.severity.value == "high"
    assert finding.effort_minutes == 5
    assert finding.proof_needed is None  # CONFIRMED drops proof text
    assert finding.review == "leaks"


def test_inferred_keeps_proof_needed(registry):
    registry.rule("T-ONE", review="leaks", severity="low", exploitability="low")(lambda c: [])
    finding = registry.make_finding("T-ONE", tag=Tag.INFERRED, locations=[], name="Y")
    assert finding.proof_needed == "Check it."


def test_severity_override(registry):
    registry.rule("T-ONE", review="leaks", severity="low", exploitability="low")(lambda c: [])
    finding = registry.make_finding(
        "T-ONE", tag="CONFIRMED", locations=[Location("a", 1)], severity="critical", name="Z"
    )
    assert finding.severity.value == "critical"


def test_duplicate_rule_id_from_other_function_raises(registry):
    registry.rule("T-ONE", review="leaks", severity="low", exploitability="low")(lambda c: [])
    with pytest.raises(ValueError, match="duplicate"):

        @registry.rule("T-ONE", review="leaks", severity="low", exploitability="low")
        def other(c):
            return []


def test_failing_rule_raises_in_strict_mode(registry):
    @registry.rule("T-BOOM", review="leaks", severity="low", exploitability="low")
    def boom(c):
        raise RuntimeError("x")

    with pytest.raises(RuntimeError):
        registry.run_checks("leaks", ctx())


def test_failing_rule_is_recorded_when_not_strict(registry, monkeypatch):
    monkeypatch.delenv("DPR_STRICT")

    @registry.rule("T-BOOM", review="leaks", severity="low", exploitability="low")
    def boom(c):
        raise RuntimeError("x")

    c = ctx()
    assert registry.run_checks("leaks", c) == []
    assert c.not_covered == ["rule T-BOOM failed: RuntimeError"]
