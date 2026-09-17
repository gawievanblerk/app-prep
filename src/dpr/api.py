"""The review() pipeline."""

from __future__ import annotations

import datetime
import os
import sys
from collections.abc import Iterable
from pathlib import Path

from dpr.discovery.detect import detect
from dpr.model import Detection, Finding, Report, ReportMeta, ReviewSection, ScanError
from dpr.questions.catalogue import questions_for, resolve
from dpr.questions.prompt import ask_on_terminal
from dpr.rank import dedupe, rank
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


def discover(path: str | os.PathLike[str]) -> tuple[RepoIndex, Detection]:
    index = RepoIndex(path)
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
) -> Report:
    _validate(url, owns_host, semgrep, db_dump)
    selected = resolve_reviews(reviews)
    index, detection = discover(path)
    options = Options(
        url=url,
        owns_host=owns_host,
        login_path=login_path,
        with_audit=with_audit,
        semgrep=semgrep,
        db_dump=db_dump,
    )
    ask = ask_on_terminal if interactive and sys.stdin.isatty() else None
    results, warnings = resolve(questions_for(selected), detection, answers, interactive, ask)
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
        findings.extend(run_checks(slug, ctx))

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
    not_covered = list(dict.fromkeys([*index.skipped, *ctx.not_covered]))
    return Report(
        meta=meta,
        detection=detection,
        findings=rank(dedupe(findings)),
        sections=sections,
        questions=results,
        not_covered=not_covered,
    )
