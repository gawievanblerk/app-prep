"""The findings register: findings grouped into distinct issues, ranked, with stable ids."""

from __future__ import annotations

from dataclasses import dataclass

from dpr.data import load
from dpr.discovery.approots import root_of
from dpr.model import AppRoot, Finding, Severity, Tag
from dpr.rank import score
from dpr.reviews import REVIEWS, number

SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)


@dataclass(frozen=True)
class Issue:
    id: str
    title: str
    severity: Severity
    tags: str
    reviews: tuple[int, ...]
    findings: tuple[str, ...]  # rule ids, in rank order
    count: int
    first: str
    effort_minutes: int


def _chain_of(rule_id: str) -> tuple[int, dict] | None:
    for position, chain in enumerate(load("register.yaml")["chains"]):
        if rule_id in chain["rules"]:
            return position, chain
    return None


def _app(finding: Finding, roots: list[AppRoot]) -> str:
    home = root_of(roots, finding.locations[0].file) if finding.locations else None
    return home.path if home is not None else ""


def _linked_key(finding: Finding, spec: dict, position: int, findings: list[Finding]) -> tuple:
    anchor = finding
    if finding.rule_id != spec["rules"][0]:
        files = {loc.file for loc in finding.locations[1:]}
        anchor = next(
            (
                f
                for f in findings
                if f.rule_id == spec["rules"][0] and files & {loc.file for loc in f.locations}
            ),
            finding,
        )
    first = anchor.locations[0] if anchor.locations else None
    return ("chain", position, f"{anchor.rule_id} {first}")


def _key(finding: Finding, roots: list[AppRoot], findings: list[Finding]) -> tuple:
    chain = _chain_of(finding.rule_id)
    if chain is not None:
        position, spec = chain
        if spec["scope"] == "linked":
            return _linked_key(finding, spec, position, findings)
        return ("chain", position, _app(finding, roots) if spec["scope"] == "app" else "")
    return ("rule", finding.rule_id, _app(finding, roots))


def _tags(findings: list[Finding]) -> str:
    present = [
        t.value
        for t in (Tag.CONFIRMED, Tag.INFERRED, Tag.UNVERIFIED)
        if any(f.tag is t for f in findings)
    ]
    return " and ".join(present)


def build_register(findings: list[Finding], roots: list[AppRoot]) -> list[Issue]:
    groups: dict[tuple, list[Finding]] = {}
    for finding in findings:
        groups.setdefault(_key(finding, roots, findings), []).append(finding)
    ordered = sorted(
        groups.items(),
        key=lambda item: (-max(score(f) for f in item[1]), SEVERITY_ORDER.index(_worst(item[1]))),
    )
    issues = []
    for position, (key, members) in enumerate(ordered, start=1):
        members = sorted(members, key=lambda f: -score(f))
        lead = members[0]
        title = _title(key, members, lead)
        apps = {_app(f, roots) for f in members}
        siblings = [k for k in groups if k[:2] == key[:2]]
        if len(siblings) > 1 and len(apps) == 1 and next(iter(apps)) not in title:
            title += f" ({next(iter(apps)) or 'repository root'})"
        issues.append(
            Issue(
                id=f"F-{position:02d}",
                title=title,
                severity=_worst(members),
                tags=_tags(members),
                reviews=tuple(sorted({number(f.review) for f in members if f.review in REVIEWS})),
                findings=tuple(dict.fromkeys(f.rule_id for f in members)),
                count=len(members),
                first=str(lead.locations[0]) if lead.locations else "not tied to a file",
                effort_minutes=lead.effort_minutes,
            )
        )
    return issues


def _title(key: tuple, members: list[Finding], lead: Finding) -> str:
    if key[0] != "chain":
        return lead.title
    spec = load("register.yaml")["chains"][key[1]]
    if spec["scope"] != "linked":
        return spec["title"]
    anchors = [f for f in members if f.rule_id == spec["rules"][0]]
    title = anchors[0].title if anchors else lead.title
    if anchors and len({f.rule_id for f in members}) > 1:
        title += ", and a start command runs it"
    return title


def _worst(findings: list[Finding]) -> Severity:
    return min((f.severity for f in findings), key=SEVERITY_ORDER.index)
