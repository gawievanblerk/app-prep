import socket
import subprocess
from pathlib import Path

import pytest

from dpr.api import review
from dpr.cli import main
from dpr.model import Tag
from dpr.report.json_out import render_json
from dpr.report.markdown import BANNED_PHRASES, render_markdown
from tests.fixture_builder import SECRETS, build


@pytest.fixture
def bad(tmp_path):
    return build("next-supabase-bad", tmp_path)


def test_no_secret_value_in_any_output(bad, tmp_path, capsys):
    report = review(bad)
    outputs = [render_markdown(report), render_json(report), repr(report.findings)]
    out_dir = tmp_path / "out"
    main(["scan", str(bad), "--out", str(out_dir)])
    outputs += [p.read_text() for p in out_dir.iterdir()]
    captured = capsys.readouterr()
    outputs += [captured.out, captured.err]
    for secret in SECRETS:
        for text in outputs:
            assert secret not in text


def test_default_run_opens_no_network_connection(bad, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("network connection attempted")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    review(bad, semgrep="off")


def test_evidence_rules_hold_for_every_finding(bad):
    for finding in review(bad).findings:
        assert finding.tag is not Tag.UNKNOWN
        if finding.tag is Tag.CONFIRMED:
            assert finding.locations
        if finding.tag is Tag.INFERRED:
            assert finding.proof_needed


def test_report_has_no_legal_verdicts_or_em_dashes(bad):
    text = render_markdown(review(bad))
    assert not any(phrase in text.lower() for phrase in BANNED_PHRASES)
    assert chr(0x2014) not in text


def test_review_does_not_change_the_repository(bad):
    before = subprocess.run(["git", "-C", str(bad), "status", "--porcelain", "--ignored"],
                            capture_output=True, text=True, check=True).stdout
    listing = sorted(p.relative_to(bad).as_posix() for p in bad.rglob("*") if ".git/" not in p.as_posix())
    review(bad)
    after = subprocess.run(["git", "-C", str(bad), "status", "--porcelain", "--ignored"],
                           capture_output=True, text=True, check=True).stdout
    assert after == before
    assert sorted(p.relative_to(bad).as_posix() for p in bad.rglob("*") if ".git/" not in p.as_posix()) == listing


def test_no_em_dash_characters_in_source_or_tests():
    root = Path(__file__).resolve().parents[1]
    offenders = []
    for folder in ("src", "tests"):
        for path in (root / folder).rglob("*"):
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            data = path.read_bytes()
            if b"\0" in data[:8192]:
                continue
            if chr(0x2014) in data.decode("utf-8", errors="ignore"):
                offenders.append(str(path.relative_to(root)))
    assert offenders == []