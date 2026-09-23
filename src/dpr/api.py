"""The review() pipeline."""

from __future__ import annotations

import dataclasses
import datetime
import os
import sys
from collections.abc import Iterable
from pathlib import Path

from dpr.discovery.approots import lower_undeployed, undeployed
from dpr.discovery.detect import detect
from dpr.model import Detection, Finding, Report, ReportMeta, ReviewSection, ScanError
from dpr.questions.catalogue import questions_for, resolve
from dpr.questions.prompt import ask_on_terminal
from dpr.rank import dedupe, rank
from dpr.report.coverage import coverage_notes
from dpr.report.register import build_register
from dpr.reviews import REVIEWS, RUN_ORDER, available, number, resolve_reviews
from dpr.rules import Context, Options, run_checks
from dpr.walk import RepoIndex

SKIPPED_OPTIONS = (
    (
        "url",
        "baseline",
        "Live header read skipped: it belongs to review 4 (baseline), which did not run",
    ),
    (
        "with_audit",
        "owasp",
        "Dependency audit skipped: it belongs to review 5 (owasp), which did not run",
    ),
)


UNTRACKED = (
    " {file} is not tracked by git: it is in this working folder only, not in the repository."
)


def discover(
    path: str | os.PathLike[str], include_untracked: bool = False
) -> tuple[RepoIndex, Detection]:
    index = RepoIndex(path, include_untracked=include_untracked)
    index.sanity_check()
    return index, detect(index)


def _validate(url: str | None, owns_host: bool, semgrep: str, db_dump: str | None) -> None:
    if url and not owns_host:
        raise ScanError(
            "--url needs --i-own-this-host: dpr only reads headers from a host you control"
        )
    if semgrep not in ("auto", "off") and not Path(semgrep).is_dir():
        raise ScanError(f"semgrep rules folder not found: {semgrep}")
    if db_dump and not Path(db_dump).is_file():
        raise ScanError(f"database dump not found: {db_dump}")


def _mark_untracked(findings: list[Finding], index: RepoIndex) -> list[Finding]:
    """Say so on a finding whose every site is in an untracked file scanned on request."""
    marked = []
    for finding in findings:
        files = {loc.file for loc in finding.locations}
        if files and files <= index.untracked:
            note = UNTRACKED.format(file=finding.locations[0].file)
            finding = dataclasses.replace(finding, detail=finding.detail + note)
        marked.append(finding)
    return marked


def _reason(slug: str, selected: list[str], modules: dict, sections: dict, notes: list[str]) -> str:
    if slug in sections:
        return "runs"
    if slug not in selected:
        return "not selected"
    if slug not in modules:
        return "not available in this version"
    failed = f"review {slug} failed: "
    if any(n.startswith(failed) for n in notes):
        return next(n for n in notes if n.startswith(failed))[len(f"review {slug} ") :]
    prefix = f"Review {number(slug)} ({slug}): "
    return next((n[len(prefix) :] for n in notes if n.startswith(prefix)), "not applicable")


def review(
    path: str | os.PathLike[str] = ".",
    reviews: Iterable[str | int] = ("all",),
    answers: str | Path | dict | None = None,
    interactive: bool = False,
    url: str | None = None,
    owns_host: bool = False,
    login_path: str | None = None,
    with_audit: bool = False,
    semgrep: str = "auto",
    db_dump: str | None = None,
    today: datetime.date | None = None,
    include_untracked: bool = False,
) -> Report:
    _validate(url, owns_host, semgrep, db_dump)
    selected = resolve_reviews(reviews)
    index, detection = discover(path, include_untracked)
    options = Options(
        url=url,
        owns_host=owns_host,
        login_path=login_path,
        with_audit=with_audit,
        semgrep=semgrep,
        db_dump=db_dump,
    )
    ask = ask_on_terminal if interactive and sys.stdin.isatty() else None
    results, warnings = resolve(
        questions_for(selected, detection), detection, answers, interactive, ask
    )
    ctx = Context(
        index=index,
        detection=detection,
        options=options,
        answers={r.question.id: r for r in results},
    )
    ctx.not_covered.extend(warnings)

    modules = available()
    sections: dict[str, ReviewSection] = {}
    findings: list[Finding] = []
    for slug in RUN_ORDER:
        if slug not in selected:
            continue
        if slug not in modules:
            ctx.not_covered.append(f"Review {number(slug)} ({slug}): not available in this version")
            continue
        try:
            section = modules[slug].run(ctx)
        except Exception as exc:
            if os.environ.get("DPR_STRICT") == "1":
                raise
            ctx.not_covered.append(f"review {slug} failed: {type(exc).__name__}")
            continue
        if section is None:
            continue
        sections[slug] = section
        found = run_checks(slug, ctx)
        findings.extend(found)
        finish = getattr(modules[slug], "finish", None)
        if finish is not None:
            ctx.run_findings = tuple(findings)
            try:
                finish(ctx, section, found)
            except Exception as exc:
                if os.environ.get("DPR_STRICT") == "1":
                    raise
                ctx.not_covered.append(f"review {slug} failed: {type(exc).__name__}")

    findings = lower_undeployed(_mark_untracked(findings, index), detection.app_roots)
    for root in undeployed(detection.app_roots):
        ctx.not_covered.append(
            f"App root {root.path} is not named by any deploy or CI configuration; its findings "
            "are listed one severity step lower"
        )

    ctx.not_covered.extend(coverage_notes(index.root, detection, options, set(sections)))

    for option, owner, note in SKIPPED_OPTIONS:
        if getattr(options, option) and owner not in sections:
            ctx.not_covered.append(note)

    applicability = tuple(
        (slug, _reason(slug, selected, modules, sections, ctx.not_covered)) for slug in REVIEWS
    )
    meta = ReportMeta(
        project=index.root.name,
        scope=str(path),
        revision=detection.git.revision,
        date=(today or datetime.date.today()).isoformat(),
        reviews_run=tuple(slug for slug in REVIEWS if slug in sections),
        method="Static analysis of the repository",
        applicability=applicability,
    )
    not_covered = list(dict.fromkeys([*index.notes, *index.skipped, *ctx.not_covered]))
    ranked = rank(dedupe(findings))
    return Report(
        meta=meta,
        detection=detection,
        findings=ranked,
        sections=sections,
        questions=results,
        not_covered=not_covered,
        answered=list(ctx.facts.get("answered", [])),
        register=build_register(ranked, detection.app_roots),
    )
