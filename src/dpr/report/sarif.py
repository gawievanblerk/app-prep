"""Render a Report as SARIF 2.1.0."""

from __future__ import annotations

import json

from dpr.model import Finding, Report
from dpr.report.standards import standard_tags

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def _properties(f: Finding) -> dict:
    props = {
        "tag": f.tag.value,
        "severity": f.severity.value,
        "exploitability": f.exploitability.value,
        "review": f.review,
    }
    if f.owasp:
        props["owasp"] = f.owasp
    return props


def _rule(f: Finding) -> dict:
    properties = {"review": f.review, **({"owasp": f.owasp} if f.owasp else {})}
    tags = standard_tags(f.rule_id)
    if tags:
        properties["tags"] = tags
    return {
        "id": f.rule_id,
        "name": f.rule_id,
        "shortDescription": {"text": f.title},
        "help": {"text": f.fix},
        "properties": properties,
    }


def _location(file: str, line: int) -> dict:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": file},
            "region": {"startLine": max(line, 1)},
        }
    }


def _result(f: Finding, rule_index: int) -> dict:
    text = f.title if not f.detail else f"{f.title}. {f.detail}"
    result = {
        "ruleId": f.rule_id,
        "ruleIndex": rule_index,
        "level": LEVELS[f.severity.value],
        "message": {"text": text},
        "properties": _properties(f),
    }
    if f.locations:
        result["locations"] = [_location(loc.file, loc.line) for loc in f.locations]
    return result


def render_sarif(report: Report) -> str:
    from dpr import __version__

    rules: list[dict] = []
    index: dict[str, int] = {}
    results = []
    for f in report.findings:
        if f.rule_id not in index:
            index[f.rule_id] = len(rules)
            rules.append(_rule(f))
        results.append(_result(f, index[f.rule_id]))
    data = {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "dpr",
                        "version": __version__,
                        "informationUri": "https://example.invalid/dpr",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"
