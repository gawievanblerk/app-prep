import json
import socket

import pytest

from dpr import reviews, rules
from dpr.api import review
from dpr.cli import main
from dpr.model import Tag
from dpr.report.markdown import BANNED_PHRASES, render_markdown
from dpr.report.sarif import render_sarif
from tests.fixture_builder import SECRETS, build

BAD = ("next-supabase-bad", "django-bad", "fastapi-bad")


@pytest.mark.parametrize("name", BAD)
def test_no_secret_value_in_any_format(tmp_path, capsys, name):
    root = build(name, tmp_path)
    report = review(root)
    outputs = [render_markdown(report), render_sarif(report), repr(report.findings)]
    out_dir = tmp_path / "out"
    assert main(["scan", str(root), "--format", "md,json,sarif", "--out", str(out_dir)]) == 0
    outputs += [p.read_text() for p in out_dir.iterdir()]
    captured = capsys.readouterr()
    outputs += [captured.out, captured.err]
    for secret in SECRETS:
        for text in outputs:
            assert secret not in text
    sarif = json.loads(next(p for p in out_dir.iterdir() if p.suffix == ".sarif").read_text())
    assert len(sarif["runs"][0]["results"]) == len(report.findings)


@pytest.mark.parametrize("name", BAD)
def test_evidence_rules_and_wording_hold(tmp_path, name):
    report = review(build(name, tmp_path))
    for finding in report.findings:
        assert finding.tag is not Tag.UNKNOWN
        if finding.tag is Tag.CONFIRMED:
            assert finding.locations, finding.rule_id
        if finding.tag is Tag.INFERRED:
            assert finding.proof_needed, finding.rule_id
    text = render_markdown(report)
    assert not any(phrase in text.lower() for phrase in BANNED_PHRASES)
    assert chr(0x2014) not in text


@pytest.mark.parametrize("name", BAD)
def test_default_run_opens_no_network_connection(tmp_path, monkeypatch, name):
    root = build(name, tmp_path)

    def refuse(*args, **kwargs):
        raise AssertionError("network connection attempted")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    review(root, semgrep="off")


def test_every_milestone_2_rule_has_owasp_or_is_a_leak_or_rls_rule():
    reviews.available()
    for rule_id, spec in rules.SPECS.items():
        if spec.review in ("baseline", "owasp", "abuse"):
            assert spec.owasp, rule_id
