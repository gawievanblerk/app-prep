from dpr.model import Finding, Location
from dpr.rank import dedupe, order_for_section, rank, score


def f(rule_id="R", sev="high", expl="high", tag="CONFIRMED", effort=10, file="a.ts", line=1,
      owasp=None, source="dpr", review="leaks"):
    return Finding(
        rule_id=rule_id, review=review, title=rule_id, tag=tag, severity=sev,
        exploitability=expl, effort_minutes=effort, locations=(Location(file, line),),
        detail="d", fix="x", proof_needed="p" if tag == "INFERRED" else None,
        owasp=owasp, source=source,
    )


def test_score_formula():
    # 40 (high) * 3 (high) * 1.0 (CONFIRMED) / 10 minutes
    assert score(f()) == 12.0
    # A01 boost 1.5, INFERRED factor 0.6
    assert score(f(tag="INFERRED", owasp="A01")) == 40 * 3 * 0.6 * 1.5 / 10


def test_effort_zero_counts_as_one_minute():
    assert score(f(effort=0)) == 120.0


def test_rank_orders_by_score_then_rule_id():
    low = f(rule_id="B", sev="low")
    crit = f(rule_id="A", sev="critical")
    assert [x.rule_id for x in rank([low, crit])] == ["A", "B"]


def test_dedupe_same_rule_same_line():
    assert len(dedupe([f(), f()])) == 1


def test_dedupe_keeps_different_rules_on_same_line():
    assert len(dedupe([f(rule_id="A", owasp="A01"), f(rule_id="B", owasp="A01")])) == 2


def test_semgrep_dropped_when_dpr_has_same_owasp_and_line():
    own = f(rule_id="OWN", owasp="A03")
    sg = f(rule_id="sg", owasp="A03", source="semgrep:python.sqli", tag="INFERRED")
    out = dedupe([sg, own])
    assert [x.rule_id for x in out] == ["OWN"]
    assert out[0].refs == ("semgrep:python.sqli",)


def test_semgrep_kept_when_no_match():
    sg = f(rule_id="sg", owasp="A03", source="semgrep:x", tag="INFERRED", line=9)
    assert len(dedupe([f(owasp="A03"), sg])) == 2


def test_leaks_section_order_puts_credentials_first():
    logged = f(rule_id="LEAK-LOGGED-PII", sev="critical", effort=1)
    key = f(rule_id="LEAK-PUBLIC-SECRET", sev="low", effort=100)
    ordered = order_for_section("leaks", [logged, key])
    assert [x.rule_id for x in ordered] == ["LEAK-PUBLIC-SECRET", "LEAK-LOGGED-PII"]
