import pytest
import yaml

from dpr.api import review
from tests.fixture_builder import FIXTURES, build

BAD = ("next-supabase-bad",)
GOOD = {
    "next-supabase-good": {"leaks", "rls", "baseline", "owasp", "abuse"},
}


def found(report):
    return {
        (f.rule_id, f.locations[0].file, f.locations[0].line, f.tag.value) for f in report.findings
    }


@pytest.mark.parametrize("name", BAD)
def test_bad_fixture_reports_exactly_the_planted_defects(tmp_path, name):
    root = build(name, tmp_path)
    expected = yaml.safe_load((FIXTURES / name / "expected.yaml").read_text())
    want = {(e["rule"], e["file"], e["line"], e["tag"]) for e in expected["findings"]}
    got = found(review(root))
    assert got - want == set(), "unexpected findings"
    assert want - got == set(), "missing findings"


def test_bad_fixture_severities(tmp_path):
    report = review(build("next-supabase-bad", tmp_path))
    severity = {(f.rule_id, f.locations[0].line): f.severity.value for f in report.findings}
    assert severity[("RLS-TABLE-OFF", 10)] == "critical"
    assert severity[("LEAK-BROAD-RESPONSE", 6)] == "high"
    assert severity[("RLS-WEAK-WITH-CHECK", 3)] == "high"
    assert severity[("RLS-DEFINER-FUNCTION", 17)] == "high"
    assert severity[("ABUSE-PAID-UNAUTH", 6)] == "critical"
    assert severity[("ABUSE-CORS-REFLECT", 12)] == "critical"
    assert severity[("BASE-COOKIE-HTTPONLY", 9)] == "high"


@pytest.mark.parametrize("name", sorted(GOOD))
def test_good_fixture_reports_none_of_the_defects(tmp_path, name):
    report = review(build(name, tmp_path))
    banned = set(yaml.safe_load((FIXTURES / name / "expected.yaml").read_text())["must_not_report"])
    assert [f for f in report.findings if f.rule_id in banned] == []
    assert set(report.sections) == GOOD[name]
