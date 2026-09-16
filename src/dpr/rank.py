"""Risk removed per minute: scoring, dedupe and ordering."""

from __future__ import annotations

from dataclasses import replace

from dpr.data import load
from dpr.model import Finding


def score(f: Finding) -> float:
    w = load("weights.yaml")
    value = w["severity"][f.severity.value] * w["exploitability"][f.exploitability.value]
    value *= w["tag_factor"][f.tag.value]
    value *= w["boost"].get(f.owasp or "", 1.0)
    return value / max(f.effort_minutes, 1)


def _first(f: Finding) -> tuple[str, int]:
    if not f.locations:
        return ("", 0)
    return (f.locations[0].file, f.locations[0].line)


def dedupe(findings: list[Finding]) -> list[Finding]:
    own: list[Finding] = []
    seen: set[tuple[str, str, int]] = set()
    for item in findings:
        if item.source != "dpr":
            continue
        key = (item.rule_id, *_first(item))
        if key in seen:
            continue
        seen.add(key)
        own.append(item)

    by_owasp: dict[tuple[str, str, int], int] = {}
    for i, item in enumerate(own):
        if item.owasp:
            by_owasp.setdefault((item.owasp, *_first(item)), i)

    external: list[Finding] = []
    for item in findings:
        if item.source == "dpr":
            continue
        key = (item.owasp or "", *_first(item))
        if item.owasp and key in by_owasp:
            i = by_owasp[key]
            own[i] = replace(own[i], refs=own[i].refs + (item.source,))
            continue
        external.append(item)
    return own + external


def _key(f: Finding) -> tuple:
    return (-score(f), f.rule_id, *_first(f))


def rank(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=_key)


def order_for_section(review: str, findings: list[Finding]) -> list[Finding]:
    items = [f for f in findings if f.review == review]
    if review != "leaks":
        return rank(items)
    order = {rule_id: i for i, rule_id in enumerate(load("weights.yaml")["leaks_order"])}
    return sorted(items, key=lambda f: (order.get(f.rule_id, len(order)), *_key(f)))
