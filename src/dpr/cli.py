"""Command line: dpr scan and dpr questions."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dpr import __version__
from dpr.api import discover, review
from dpr.gitutil import run_git
from dpr.model import Report, ScanError
from dpr.questions.catalogue import answers_template, load_questions
from dpr.report.json_out import render_json
from dpr.report.markdown import render_markdown
from dpr.reviews import REVIEWS

FORMATS = ("md", "json")
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
FAIL_LEVELS = {"none": 0, "medium": 2, "high": 3, "critical": 4}
MAX_SUMMARY_LINES = 15


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dpr", description="Data protection review. No LLM.")
    parser.add_argument("--version", action="version", version=f"dpr {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="review a repository and write the report")
    scan.add_argument("path", nargs="?", default=".")
    scan.add_argument(
        "--reviews",
        nargs="+",
        default=["all"],
        metavar="REVIEW",
        help="all, 1 to 7, or " + ", ".join(REVIEWS),
    )
    scan.add_argument("--answers", metavar="FILE")
    scan.add_argument("--interactive", action="store_true")
    scan.add_argument("--url")
    scan.add_argument("--i-own-this-host", dest="owns_host", action="store_true")
    scan.add_argument("--login-path")
    scan.add_argument("--with-audit", action="store_true")
    scan.add_argument("--semgrep", default="auto", metavar="auto|off|DIR")
    scan.add_argument("--db-dump", metavar="FILE")
    scan.add_argument("--format", default="md,json", help="comma separated: md, json")
    scan.add_argument("--out", metavar="DIR")
    scan.add_argument("--fail-on", default="none", choices=list(FAIL_LEVELS))

    questions = commands.add_parser("questions", help="write a starter answers file")
    questions.add_argument("path", nargs="?", default=".")
    questions.add_argument("--out", metavar="FILE")
    return parser


def _formats(value: str) -> list[str]:
    tokens = [token.strip().lower() for token in value.split(",") if token.strip()]
    for token in tokens:
        if token not in FORMATS:
            raise ScanError(f"unknown format: {token} (supported: {', '.join(FORMATS)})")
    if not tokens:
        raise ScanError("no output format selected")
    return tokens


def gitignore_tip(root: Path, written: Path) -> str | None:
    try:
        rel_dir = written.resolve().parent.relative_to(root.resolve()).as_posix()
    except ValueError:
        return None
    if run_git(root, "rev-parse", "--is-inside-work-tree") is None:
        return None
    if run_git(root, "check-ignore", "-q", str(written.resolve())) is not None:
        return None
    return (
        f'Tip: add "{rel_dir}/" to .gitignore. '
        "The report maps where the data and the weaknesses are."
    )


def summary_lines(report: Report, written: list[Path], tip: str | None) -> list[str]:
    counts = {s: sum(f.severity.value == s for f in report.findings) for s in SEVERITY_RANK}
    open_count = sum(q.open for q in report.questions)
    lines = [
        f"dpr: {len(report.findings)} findings (critical {counts['critical']}, "
        f"high {counts['high']}, medium {counts['medium']}, low {counts['low']}), "
        f"{open_count} open questions"
    ]
    if report.findings:
        lines.append("Top fixes:")
        lines += [
            f"  {i}. {f.title} ({f.locations[0] if f.locations else 'no file'})"
            for i, f in enumerate(report.findings[:3], start=1)
        ]
    lines += [f"Wrote {path}" for path in written]
    if tip:
        lines.append(tip)
    return lines[:MAX_SUMMARY_LINES]


def exit_code(report: Report, fail_on: str) -> int:
    threshold = FAIL_LEVELS[fail_on]
    if threshold and any(SEVERITY_RANK[f.severity.value] >= threshold for f in report.findings):
        return 1
    return 0


def _scan(args: argparse.Namespace) -> int:
    formats = _formats(args.format)
    reviews = [part for token in args.reviews for part in token.split(",") if part]
    report = review(
        args.path,
        reviews=reviews,
        answers=args.answers,
        interactive=args.interactive,
        url=args.url,
        owns_host=args.owns_host,
        login_path=args.login_path,
        with_audit=args.with_audit,
        semgrep=args.semgrep,
        db_dump=args.db_dump,
    )
    root = Path(args.path)
    out_dir = Path(args.out) if args.out else root / "data-protection-review"
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    if "md" in formats:
        written.append(out_dir / f"REPORT-{report.meta.date}.md")
        written[-1].write_text(render_markdown(report), encoding="utf-8")
    if "json" in formats:
        written.append(out_dir / f"report-{report.meta.date}.json")
        written[-1].write_text(render_json(report), encoding="utf-8")
    for line in summary_lines(report, written, gitignore_tip(root, written[0])):
        print(line)
    return exit_code(report, args.fail_on)


def _questions(args: argparse.Namespace) -> int:
    _, detection = discover(args.path)
    target = Path(args.out) if args.out else Path(args.path) / "dpr-answers.yaml"
    if target.exists():
        raise ScanError(f"{target} already exists; remove it or pass --out")
    target.write_text(answers_template(load_questions(), detection), encoding="utf-8")
    print(f"Wrote {target}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _scan(args) if args.command == "scan" else _questions(args)
    except ScanError as exc:
        print(f"dpr: error: {exc}", file=sys.stderr)
        return 2
