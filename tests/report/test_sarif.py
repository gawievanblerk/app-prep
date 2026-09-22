import json

import dpr
from dpr.model import Detection, Finding, Location, Report, ReportMeta
from dpr.report.sarif import render_sarif


def finding(rule_id, severity, **extra):
    base = dict(
        rule_id=rule_id,
        review="owasp",
        title=f"Title {rule_id}",
        tag="CONFIRMED",
        severity=severity,
        exploitability="high",
        effort_minutes=5,
        locations=(Location("app/a.py", 7),),
        detail="Detail.",
        fix="Fix.",
        owasp="A01",
    )
    base.update(extra)
    return Finding(**base)


def report(findings):
    meta = ReportMeta("shop", ".", "abc", "2026-09-17", ("owasp",), "Static analysis", ())
    return Report(meta, Detection(), findings, {}, [], [])


def test_sarif_shape_levels_and_rules():
    findings = [
        finding("OWASP-A01-UNSCOPED-QUERY", "critical"),
        finding("OWASP-A01-UNSCOPED-QUERY", "high", locations=(Location("app/b.py", 3),)),
        finding("ABUSE-ERROR-LEAK", "medium", review="abuse", owasp=None),
        finding(
            "BASE-HEADER-MISSING-HSTS",
            "low",
            review="baseline",
            tag="UNVERIFIED",
            locations=(),
            owasp=None,
        ),
    ]
    data = json.loads(render_sarif(report(findings)))
    assert data["version"] == "2.1.0"
    [run] = data["runs"]
    assert run["tool"]["driver"]["name"] == "dpr"
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == [
        "OWASP-A01-UNSCOPED-QUERY",
        "ABUSE-ERROR-LEAK",
        "BASE-HEADER-MISSING-HSTS",
    ]
    levels = [r["level"] for r in run["results"]]
    assert levels == ["error", "error", "warning", "note"]
    first = run["results"][0]
    assert first["ruleIndex"] == 0 and run["results"][2]["ruleIndex"] == 1
    region = first["locations"][0]["physicalLocation"]
    assert region["artifactLocation"]["uri"] == "app/a.py"
    assert region["region"]["startLine"] == 7
    assert first["properties"] == {
        "tag": "CONFIRMED",
        "severity": "critical",
        "exploitability": "high",
        "review": "owasp",
        "owasp": "A01",
    }
    assert "locations" not in run["results"][3]
    assert "owasp" not in run["results"][2]["properties"]


def test_sarif_excludes_questions_and_is_exported(tmp_path):
    data = json.loads(render_sarif(report([])))
    assert data["runs"][0]["results"] == []
    assert "questions" not in json.dumps(data)
    assert dpr.render_sarif is render_sarif
