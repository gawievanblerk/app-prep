"""Rule registry, rule text and the shared run context."""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from functools import cache
from importlib.resources import files
from string import Template

from dpr.data import load
from dpr.model import Detection, Exploitability, Finding, QuestionResult, Severity, Tag


@dataclass(frozen=True)
class RuleSpec:
    rule_id: str
    review: str
    severity: Severity
    exploitability: Exploitability
    owasp: str | None = None


@dataclass
class Options:
    url: str | None = None
    owns_host: bool = False
    login_path: str | None = None
    with_audit: bool = False
    semgrep: str = "auto"
    db_dump: str | None = None


@dataclass
class Context:
    index: object  # dpr.walk.RepoIndex
    detection: Detection
    answers: dict[str, QuestionResult] = field(default_factory=dict)
    options: Options = field(default_factory=Options)
    facts: dict[str, object] = field(default_factory=dict)
    not_covered: list[str] = field(default_factory=list)


CheckFn = Callable[[Context], Iterable[Finding]]
SPECS: dict[str, RuleSpec] = {}
CHECKS: dict[str, list[tuple[str, CheckFn]]] = {}
_OWNERS: dict[str, str] = {}


def rule(rule_id: str, *, review: str, severity: str, exploitability: str,
         owasp: str | None = None) -> Callable[[CheckFn], CheckFn]:
    def wrap(fn: CheckFn) -> CheckFn:
        owner = f"{getattr(fn, '__module__', '')}.{getattr(fn, '__qualname__', '')}"
        if rule_id in _OWNERS:
            if _OWNERS[rule_id] != owner or owner.endswith("<lambda>"):
                raise ValueError(f"duplicate rule id {rule_id}")
            return fn
        _OWNERS[rule_id] = owner
        SPECS[rule_id] = RuleSpec(
            rule_id, review, Severity(severity), Exploitability(exploitability), owasp
        )
        CHECKS.setdefault(review, []).append((rule_id, fn))
        return fn

    return wrap


@dataclass(frozen=True)
class RuleText:
    title: str
    effort_minutes: int
    fix: str
    detail: str = ""
    proof_needed: str | None = None
    attack: str | None = None
    blast: str | None = None
    verify: str | None = None


@cache
def _all_rule_text() -> dict:
    merged: dict = {}
    folder = files("dpr.data").joinpath("rule_text")
    if folder.is_dir():
        for item in sorted(folder.iterdir(), key=lambda entry: entry.name):
            if item.name.endswith(".yaml"):
                merged.update(load(f"rule_text/{item.name}") or {})
    return merged


def rule_text(rule_id: str) -> RuleText:
    data = _all_rule_text()
    if rule_id not in data:
        raise KeyError(f"no rule text for {rule_id}")
    return RuleText(**data[rule_id])


def _fill(value: str | None, fmt: dict[str, object]) -> str | None:
    if value is None:
        return None
    return Template(value).safe_substitute({k: str(v) for k, v in fmt.items()})


def make_finding(rule_id: str, *, tag: Tag | str, locations: Iterable,
                 detail: str | None = None, snippet: str | None = None,
                 severity: str | None = None, exploitability: str | None = None,
                 fix: str | None = None, proof_needed: str | None = None,
                 attack: str | None = None, blast: str | None = None,
                 verify: str | None = None, refs: Iterable[str] = (),
                 **fmt: object) -> Finding:
    spec = SPECS[rule_id]
    text = rule_text(rule_id)
    tag = Tag(tag)
    proof = proof_needed if proof_needed is not None else _fill(text.proof_needed, fmt)
    return Finding(
        rule_id=rule_id,
        review=spec.review,
        title=_fill(text.title, fmt) or rule_id,
        tag=tag,
        severity=Severity(severity or spec.severity),
        exploitability=Exploitability(exploitability or spec.exploitability),
        effort_minutes=text.effort_minutes,
        locations=tuple(locations),
        detail=detail if detail is not None else (_fill(text.detail, fmt) or ""),
        fix=fix if fix is not None else (_fill(text.fix, fmt) or ""),
        snippet=snippet,
        proof_needed=proof if tag is Tag.INFERRED else None,
        attack=attack if attack is not None else _fill(text.attack, fmt),
        blast=blast if blast is not None else _fill(text.blast, fmt),
        verify=verify if verify is not None else _fill(text.verify, fmt),
        owasp=spec.owasp,
        refs=tuple(refs),
    )


def run_checks(review: str, ctx: Context) -> list[Finding]:
    found: list[Finding] = []
    for rule_id, fn in CHECKS.get(review, []):
        try:
            found.extend(fn(ctx))
        except Exception as exc:
            if os.environ.get("DPR_STRICT") == "1":
                raise
            ctx.not_covered.append(f"rule {rule_id} failed: {type(exc).__name__}")
    return found
