import json
import socket

import pytest

from dpr import reviews, rules
from dpr.api import review
from dpr.cli import main
from dpr.model import Tag
from dpr.report.markdown import BANNED_PHRASES, render_markdown
from tests.fixture_builder import SECRETS, build

ALL = (
    "next-supabase-bad",
    "django-bad",
    "fastapi-bad",
    "express-prisma",
    "next-supabase-good",
    "fastapi-good",
)
SECTIONS = (
    "## Summary",
    "## Evidence tags",
    "## Detection",
    "## 1. Data inventory",
    "## 2. Database lock check",
    "## 3. Failure path test plan",
    "## 4. Security baseline",
    "## 5. OWASP sweep",
    "## 6. Leak hunt",
    "## 7. Abuse and bill guard",
    "## Open questions",
    "## What this review did not cover",
)
REQUIRED_PARTS = (
    "### Findings register",
    "### Personal data map",
    "### Table protection status",
    "### Cases",
    "### Checks that pass",
    "### Place 1: public variables reviewed",
    "### Cost surface",
    "### For the data protection lawyer",
)
PLANTED_EMAIL = "maria.okafor" + "@" + "gmail.com"


@pytest.mark.parametrize("name", ALL)
def test_every_review_runs_with_the_same_section_structure(tmp_path, name):
    report = review(build(name, tmp_path))
    assert all(status == "runs" for _, status in report.meta.applicability)
    text = render_markdown(report)
    assert tuple(line for line in text.splitlines() if line.startswith("## ")) == SECTIONS
    for heading in REQUIRED_PARTS:
        assert f"\n{heading}\n" in text, heading


@pytest.mark.parametrize("name", ALL)
def test_evidence_wording_and_templates_hold_in_every_fixture(tmp_path, name):
    report = review(build(name, tmp_path))
    for finding in report.findings:
        if finding.tag is Tag.CONFIRMED:
            assert finding.locations, finding.rule_id
        if finding.tag is Tag.INFERRED:
            assert finding.proof_needed, finding.rule_id
        for text in (finding.title, finding.detail, finding.fix, finding.proof_needed or ""):
            assert "${" not in text, finding.rule_id
    text = render_markdown(report)
    assert not any(phrase in text.lower() for phrase in BANNED_PHRASES)
    assert chr(0x2014) not in text


@pytest.mark.parametrize("name", ("express-prisma", "django-bad"))
def test_no_secret_or_planted_address_in_any_format(tmp_path, capsys, name):
    root = build(name, tmp_path)
    out_dir = tmp_path / "out"
    assert main(["scan", str(root), "--format", "md,json,sarif", "--out", str(out_dir)]) == 0
    outputs = [p.read_text() for p in out_dir.iterdir()]
    captured = capsys.readouterr()
    outputs += [captured.out, captured.err]
    for value in (*SECRETS, PLANTED_EMAIL):
        assert not any(value in text for text in outputs), value
    data = json.loads(next(p for p in out_dir.iterdir() if p.suffix == ".json").read_text())
    assert data["register"]


def test_express_prisma_opens_no_network_connection(tmp_path, monkeypatch):
    root = build("express-prisma", tmp_path)

    def refuse(*args, **kwargs):
        raise AssertionError("network connection attempted")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    review(root, semgrep="off")


def test_every_rule_has_a_title_and_fix_without_em_dashes():
    reviews.available()
    for rule_id in rules.SPECS:
        text = rules.rule_text(rule_id)
        assert text.title and text.fix, rule_id
        assert chr(0x2014) not in f"{text.title}{text.detail}{text.fix}{text.proof_needed}", rule_id


def test_limits_found_by_the_comparison_are_listed_as_not_covered(tmp_path):
    report = review(build("express-prisma", tmp_path))
    assert any(
        n.startswith("Infrastructure hostnames and internal endpoints") for n in report.not_covered
    )
    assert any(
        n.startswith("Copies of personal data kept outside the repository")
        for n in report.not_covered
    )
    assert any(n.startswith("Screening new passwords") for n in report.not_covered)
