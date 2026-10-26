import json
from importlib.resources import files

import pytest

import dpr
from dpr import reviews, rules
from dpr.cli import main
from dpr.data import load
from dpr.model import Finding, Location, Question, QuestionResult, ScanError
from dpr.report.register import build_register
from dpr.report.sarif import render_sarif
from dpr.report.standards import (
    build_standards,
    frameworks,
    resolve_standards,
    standard_tags,
    status_counts,
)
from tests.reviews.helpers import write

EXPECTED_IDS = ("asvs", "nist-800-63b", "iso-27799", "iec-81001-5-1", "hipaa", "gdpr", "popia")
ALL_REVIEWS = set(reviews.REVIEWS)


def finding(rule_id, severity="high", detail="Detail.", file="app/a.py"):
    reviews.available()
    return Finding(
        rule_id=rule_id,
        review=rules.SPECS[rule_id].review,
        title=f"Title {rule_id}",
        tag="CONFIRMED",
        severity=severity,
        exploitability="high",
        effort_minutes=5,
        locations=(Location(file, 7),),
        detail=detail,
        fix="Fix.",
    )


def control(built, standard, name):
    framework = next(f for f in built if f.id == standard)
    return next(c for c in framework.controls if c.name == name)


def build(findings, sections=ALL_REVIEWS, questions=(), selected=EXPECTED_IDS):
    register = build_register(findings, [])
    return build_standards(selected, findings, register, set(sections), list(questions))


def test_all_seven_standards_are_mapped():
    assert tuple(f["id"] for f in frameworks()) == EXPECTED_IDS


def test_every_mapped_rule_is_registered():
    reviews.available()
    for spec in frameworks():
        for item in spec["controls"]:
            for rule_id in item.get("rules", []):
                assert rule_id in rules.SPECS, (spec["id"], item["name"], rule_id)


def test_every_registered_rule_speaks_to_some_control():
    reviews.available()
    mapped = {r for spec in frameworks() for c in spec["controls"] for r in c.get("rules", [])}
    assert set(rules.SPECS) - mapped == set()


def test_every_control_has_rules_or_evidence_and_known_questions():
    question_ids = {q["id"] for q in load("questions.yaml")["questions"]}
    for spec in frameworks():
        assert spec["name"] and spec["scope"]
        for item in spec["controls"]:
            assert item.get("rules") or item.get("evidence"), (spec["id"], item["name"])
            assert set(item.get("questions", [])) <= question_ids, (spec["id"], item["name"])


def test_standards_text_has_no_legal_verdicts_or_em_dashes():
    raw = files("dpr.data").joinpath("standards.yaml").read_text(encoding="utf-8")
    for phrase in ("compliant with", "complies with", "satisfies article", "lawful basis is"):
        assert phrase not in raw.lower(), phrase
    assert chr(0x2014) not in raw


def test_resolve_standards():
    assert resolve_standards(["all"]) == list(EXPECTED_IDS)
    assert resolve_standards(["none"]) == []
    assert resolve_standards(["HIPAA", "popia"]) == ["hipaa", "popia"]
    with pytest.raises(ScanError, match="unknown standard"):
        resolve_standards(["sox"])


def test_findings_status_names_the_register_issue():
    built = build([finding("AUTH-NO-MFA")])
    mfa = control(built, "nist-800-63b", "Multi-factor authentication")
    assert mfa.status == "findings"
    assert mfa.rules == ("AUTH-NO-MFA",)
    assert mfa.issues == ("F-01",)
    assert mfa.detail.startswith("1 finding(s): F-01 (high).")


def test_clear_partial_and_not_checked():
    clear = control(build([]), "hipaa", "Transmission security")
    assert clear.status == "clear"
    assert "none fired" in clear.detail
    only_auth = control(build([], sections={"auth"}), "hipaa", "Person or entity authentication")
    assert only_auth.status == "clear"  # every rule of this control belongs to review 3
    not_run = control(build([], sections={"leaks"}), "hipaa", "Audit controls")
    assert not_run.status == "not-checked"
    assert "Reviews not run: 5 (owasp)." in not_run.detail


def test_partial_lists_the_reviews_that_did_not_run():
    item = control(
        build([], sections={"auth"}), "gdpr", "Confidentiality of systems and access control"
    )
    assert item.status == "partial"
    assert "Reviews not run:" in item.detail and "leaks" in item.detail


def test_evidence_only_control_shows_question_answers():
    question = Question("alert_channel", ("abuse",), "Which channel?", "text", "why", "who")
    answered = QuestionResult(question, "The ops channel.", "answers", False)
    item = control(
        build([], questions=[answered]), "gdpr", "Lawful basis for each processing purpose"
    )
    assert item.status == "evidence"
    breach = control(build([], questions=[answered]), "hipaa", "Security incident procedures")
    assert breach.status == "evidence"
    assert breach.detail.endswith("Which channel? The ops channel.")
    still_open = QuestionResult(question, None, "none", True)
    breach = control(build([], questions=[still_open]), "hipaa", "Security incident procedures")
    assert "Open question: Which channel?" in breach.detail


def test_control_with_rules_and_evidence_adds_also_needs():
    item = control(build([]), "hipaa", "Encryption and decryption at rest")
    assert item.status == "clear"
    assert "Also needs: Confirm that databases" in item.detail


def test_health_signal_only_on_health_standards():
    health = finding(
        "INV-SPECIAL-CATEGORY",
        severity="medium",
        detail="Fields of Patient carry special category data by name: diagnosis.",
        file="prisma/schema.prisma",
    )
    built = {f.id: f for f in build([health])}
    assert built["hipaa"].signal.startswith("The data inventory found health fields")
    assert built["iso-27799"].signal and built["iec-81001-5-1"].signal
    assert built["gdpr"].signal == "" and built["asvs"].signal == ""
    none_found = {f.id: f for f in build([])}
    assert none_found["hipaa"].signal == "The data inventory found no health fields by name."


def test_status_counts_add_up():
    for framework in build([finding("OWASP-A03-RAW-SQL")]):
        assert sum(status_counts(framework).values()) == len(framework.controls)


def test_standard_tags_for_sarif():
    tags = standard_tags("AUTH-NO-MFA")
    assert "OWASP ASVS 5.0 V6" in tags
    assert "HIPAA Security and Privacy Rules 164.312(d)" in tags
    assert any(t.startswith("NIST SP 800-63B") for t in tags)


def small_app(tmp_path):
    write(
        tmp_path, "supabase/migrations/1.sql", "create table public.notes (id int, user_id uuid);"
    )
    write(tmp_path, "app/api/notes/route.ts", "export async function GET() {}\n")
    return tmp_path


def test_report_has_standards_section_and_json(tmp_path):
    report = dpr.review(small_app(tmp_path))
    assert [f.id for f in report.standards] == list(EXPECTED_IDS)
    text = dpr.render_markdown(report)
    assert "## Standards readiness" in text
    for name in ("### OWASP ASVS 5.0", "### NIST SP 800-63B Rev. 4", "### POPIA", "### GDPR"):
        assert name in text
    assert "not a certification" in text
    data = json.loads(dpr.render_json(report))
    assert data["standards"][0]["controls"][0]["ref"] == "V1"


def test_standards_none_drops_the_section(tmp_path):
    report = dpr.review(small_app(tmp_path), standards=["none"])
    assert report.standards == []
    assert "## Standards readiness" not in dpr.render_markdown(report)


def test_sarif_rules_carry_standard_tags(tmp_path):
    write(
        tmp_path, "infra/db.tf", 'resource "aws_db_instance" "main" {\n  engine = "postgres"\n}\n'
    )
    sarif = json.loads(render_sarif(dpr.review(tmp_path)))
    rule = next(
        r
        for r in sarif["runs"][0]["tool"]["driver"]["rules"]
        if r["id"] == "BASE-STORAGE-UNENCRYPTED"
    )
    assert "HIPAA Security and Privacy Rules 164.312(a)(2)(iv)" in rule["properties"]["tags"]


def test_cli_standards_option(tmp_path, capsys):
    root = small_app(tmp_path / "app")
    out = tmp_path / "out"
    assert main(["scan", str(root), "--out", str(out), "--standards", "hipaa,popia"]) == 0
    [report] = out.glob("report-*.json")
    data = json.loads(report.read_text())
    assert [s["id"] for s in data["standards"]] == ["hipaa", "popia"]
    assert main(["scan", str(root), "--out", str(out), "--standards", "sox"]) == 2


def test_header_lists_the_standards_tested(tmp_path):
    text = dpr.render_markdown(dpr.review(small_app(tmp_path)))
    header = text.split("## Summary")[0]
    assert "Standards tested:\n\n- OWASP Top 10 2021 (review 5, OWASP sweep)\n" in header
    for name in ("OWASP ASVS 5.0", "NIST SP 800-63B Rev. 4", "ISO 27799:2016", "GDPR", "POPIA"):
        assert f"- {name} (readiness, see Standards readiness)" in header


def test_header_list_follows_the_selection(tmp_path):
    report = dpr.review(small_app(tmp_path), reviews=["leaks"], standards=["popia"])
    header = dpr.render_markdown(report).split("## Summary")[0]
    assert "OWASP Top 10" not in header
    assert "- POPIA (readiness, see Standards readiness)" in header
    report = dpr.review(small_app(tmp_path), reviews=["leaks"], standards=["none"])
    assert "Standards tested" not in dpr.render_markdown(report)
