"""Standards readiness: what the findings say about each control of a security or privacy
standard (data/standards.yaml). Readiness is not certification and not a legal opinion."""

from __future__ import annotations

import re
from collections.abc import Iterable

from dpr.data import load
from dpr.model import (
    ControlReadiness,
    Finding,
    FrameworkReadiness,
    QuestionResult,
    ScanError,
)
from dpr.reviews import number
from dpr.rules import SPECS

HEALTH = re.compile(
    r"(?i)health|medic|diagnos|patient|allerg|prescri|disabilit|mental|pregnan|\bhiv\b|genetic"
    r"|treatment|clinical"
)
STATUS_LABELS = {
    "findings": "Findings",
    "clear": "No findings in code",
    "partial": "Partly checked",
    "not-checked": "Not checked",
    "evidence": "Evidence needed",
}


def frameworks() -> list[dict]:
    return load("standards.yaml")["frameworks"]


def standard_ids() -> tuple[str, ...]:
    return tuple(f["id"] for f in frameworks())


def resolve_standards(requested: Iterable[str]) -> list[str]:
    known = standard_ids()
    selected: set[str] = set()
    for item in requested:
        token = str(item).strip().lower()
        if token == "all":
            selected.update(known)
        elif token == "none":
            continue
        elif token in known:
            selected.add(token)
        else:
            raise ScanError(f"unknown standard: {item}. Use all, none, or {', '.join(known)}")
    return [i for i in known if i in selected]


def _health_signal(findings: list[Finding], sections: set[str]) -> str:
    special = [
        f for f in findings if f.rule_id == "INV-SPECIAL-CATEGORY" and HEALTH.search(f.detail)
    ]
    if special:
        names = ", ".join(sorted({f.locations[0].file for f in special if f.locations}))
        return f"The data inventory found health fields ({len(special)} model(s) in {names})."
    if "inventory" in sections:
        return "The data inventory found no health fields by name."
    return "The data inventory did not run, so health fields were not looked for."


def _answers(ids: list[str], questions: dict[str, QuestionResult]) -> list[str]:
    lines = []
    for qid in ids:
        result = questions.get(qid)
        if result is None:
            continue
        if result.open:
            lines.append(f"Open question: {result.question.text}")
        else:
            lines.append(f"{result.question.text} {result.answer}")
    return lines


def _control(
    spec: dict,
    fired: dict[str, list[Finding]],
    issues_by_rule: dict[str, list[tuple[str, str]]],
    sections: set[str],
    questions: dict[str, QuestionResult],
) -> ControlReadiness:
    mapped = spec.get("rules", [])
    evidence = spec.get("evidence", "")
    extra = _answers(spec.get("questions", []), questions)
    hit = [r for r in mapped if r in fired]
    owners = sorted({SPECS[r].review for r in mapped}, key=number)
    missing = [o for o in owners if o not in sections]
    if hit:
        status = "findings"
        issues = sorted(
            {issue for r in hit for issue in issues_by_rule.get(r, [])}, key=lambda i: i[0]
        )
        count = sum(len(fired[r]) for r in hit)
        detail = f"{count} finding(s)"
        if issues:
            detail += ": " + ", ".join(f"{i} ({severity})" for i, severity in issues)
        detail += "."
    elif not mapped:
        status, issues, detail = "evidence", [], ""
    elif len(missing) == len(owners):
        status, issues = "not-checked", []
        detail = "Reviews not run: " + ", ".join(f"{number(o)} ({o})" for o in missing) + "."
    elif missing:
        status, issues = "partial", []
        detail = (
            "No findings from the reviews that ran. Reviews not run: "
            + ", ".join(f"{number(o)} ({o})" for o in missing)
            + "."
        )
    else:
        status, issues = "clear", []
        detail = f"Checked by {len(mapped)} rule(s); none fired."
    parts = [detail] if detail else []
    if evidence:
        parts.append(evidence if status == "evidence" else f"Also needs: {evidence}")
    parts += extra
    return ControlReadiness(
        ref=str(spec["ref"]),
        name=spec["name"],
        status=status,
        detail=" ".join(parts),
        rules=tuple(hit),
        issues=tuple(i for i, _ in issues),
    )


def build_standards(
    selected: Iterable[str],
    findings: list[Finding],
    register: list,
    sections: set[str],
    questions: list[QuestionResult],
) -> list[FrameworkReadiness]:
    wanted = set(selected)
    fired: dict[str, list[Finding]] = {}
    for f in findings:
        fired.setdefault(f.rule_id, []).append(f)
    issues_by_rule: dict[str, list[tuple[str, str]]] = {}
    for issue in register:
        for rule_id in issue.findings:
            issues_by_rule.setdefault(rule_id, []).append((issue.id, issue.severity.value))
    by_id = {r.question.id: r for r in questions}
    built = []
    for spec in frameworks():
        if spec["id"] not in wanted:
            continue
        controls = tuple(
            _control(c, fired, issues_by_rule, sections, by_id) for c in spec["controls"]
        )
        built.append(
            FrameworkReadiness(
                id=spec["id"],
                name=spec["name"],
                scope=spec["scope"],
                signal=_health_signal(findings, sections) if spec.get("health") else "",
                controls=controls,
            )
        )
    return built


def status_counts(framework: FrameworkReadiness) -> dict[str, int]:
    counts = dict.fromkeys(STATUS_LABELS, 0)
    for control in framework.controls:
        counts[control.status] += 1
    return counts


def standard_tags(rule_id: str) -> list[str]:
    """Every control a rule speaks to, as "<standard> <ref>" labels, for SARIF rule tags."""
    tags = []
    for spec in frameworks():
        for control in spec["controls"]:
            if rule_id in control.get("rules", []):
                tag = f"{spec['name']} {control['ref']}"
                if tag not in tags:
                    tags.append(tag)
    return tags
