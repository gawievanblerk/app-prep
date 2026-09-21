"""Render a Report as Markdown."""

from __future__ import annotations

import re

from jinja2 import Environment, PackageLoader

from dpr.model import Finding, Part, Report
from dpr.rank import order_for_section
from dpr.report.register import build_register
from dpr.reviews import LABELS, REVIEWS, TITLES, number

DISCLAIMER = (
    "This is an inventory of what the code shows, not legal advice. Compliance conclusions and "
    "lawful basis are for a qualified data protection lawyer. Open questions for that "
    "conversation are listed near the end."
)
BANNED_PHRASES = (
    "compliant with",
    "complies with",
    "satisfies article",
    "satisfies section",
    "lawful basis is",
)
SEVERITIES = ("critical", "high", "medium", "low")
SOURCE_LABELS = {
    "answers": "from the answers file",
    "interactive": "answered in the terminal",
    "detection": "detected in the repository",
}
ALWAYS_NOT_COVERED = (
    "Systems outside this repository",
    "Production configuration that differs from the repository",
    "Runtime behaviour that static analysis cannot observe",
)


def _cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _table(columns: tuple[str, ...], rows: list[tuple[str, ...]] | tuple) -> str:
    if not rows:
        return "None found."
    lines = ["| " + " | ".join(_cell(c) for c in columns) + " |", "|" + "---|" * len(columns)]
    lines += ["| " + " | ".join(_cell(c) for c in row) + " |" for row in rows]
    return "\n".join(lines)


def _block(label: str, position: int, f: Finding) -> str:
    where = ", ".join(f"`{loc}`" for loc in f.locations) or "not tied to a file"
    lines = [
        f"#### {label} {position}: {f.title}",
        "",
        f"Severity: {f.severity.value}, exploitability: {f.exploitability.value}, "
        f"tag: {f.tag.value}, effort: about {f.effort_minutes} min",
        f"Where: {where}",
        "",
        f.detail,
    ]
    if f.snippet:
        longest = max((len(run) for run in re.findall(r"`+", f.snippet)), default=0)
        fence = "`" * max(3, longest + 1)
        lines += ["", f"{fence}text", f.snippet, fence]
    for heading, value in (
        ("Proof needed", f.proof_needed),
        ("Attack", f.attack),
        ("Blast radius", f.blast),
    ):
        if value:
            lines += ["", f"{heading}: {value}"]
    lines += ["", "Fix:", "", f.fix]
    if f.verify:
        lines += ["", f"Verify: {f.verify}"]
    if f.source != "dpr":
        lines += ["", f"Source: {f.source}"]
    if f.refs:
        lines += ["", "Related: " + ", ".join(f.refs)]
    return "\n".join(lines)


def _refs(part: Part, report: Report) -> str:
    items = [f for f in report.findings if f.rule_id in part.columns]
    if not items:
        return part.body
    lines = [
        f"- {f.title} ({f.severity.value}, {f.tag.value}, reported in review "
        f"{number(f.review)}): " + ", ".join(f"`{loc}`" for loc in f.locations[:5])
        for f in items
    ]
    return "\n".join(lines)


def _part_body(slug: str, part: Part, report: Report) -> str:
    if part.kind == "table":
        return _table(part.columns, part.rows)
    if part.kind == "refs":
        return _refs(part, report)
    if part.kind == "findings":
        items = order_for_section(slug, report.findings)
        if not items:
            return "None found."
        return "\n\n".join(_block(LABELS[slug], i, f) for i, f in enumerate(items, start=1))
    return part.body


def _detection_table(report: Report) -> str:
    d = report.detection
    schema = d.schema
    has_policies = bool(getattr(schema, "policies", None))
    sdks = f"{len(d.sdks)}" + (f" ({', '.join(s.name for s in d.sdks)})" if d.sdks else "")
    rows = [
        ("Language / framework", ", ".join([*d.languages, *d.frameworks]) or "none detected"),
        ("Database / ORM", ", ".join([*d.databases, *d.orms]) or "none detected"),
        ("Auth provider", ", ".join(d.auth_providers) or "none detected"),
        ("Hosting", ", ".join(d.hosting) or "none detected"),
        ("API routes", str(len(d.routes))),
        ("Third-party SDKs", sdks),
        ("RLS or policy files present", "yes" if has_policies else "no"),
        ("Rate limiting present", ", ".join(d.rate_limiters) or "no"),
        ("Security headers configured", ", ".join(d.header_config) or "no"),
    ]
    return "| | |\n|---|---|\n" + "\n".join(f"| {a} | {_cell(b)} |" for a, b in rows)


def issues_of(report: Report) -> list:
    return report.register or build_register(report.findings, report.detection.app_roots)


def _register(report: Report) -> str:
    if not issues_of(report):
        return ""
    rows = [
        (
            issue.id,
            issue.severity.value.capitalize(),
            issue.tags,
            issue.title,
            ", ".join(str(n) for n in issue.reviews),
            f"{issue.count} ({', '.join(issue.findings)})",
        )
        for issue in issues_of(report)
    ]
    columns = ("ID", "Severity", "Tag", "Title", "Reviews", "Findings")
    return "### Findings register\n\n" + _table(columns, rows)


def _view(report: Report) -> dict:
    issues = issues_of(report)
    counts = {s: sum(i.severity.value == s for i in issues) for s in SEVERITIES}
    open_questions = [q for q in report.questions if q.open]
    summary = _table(
        ("Severity", "Count"),
        [
            *[(s.capitalize(), str(counts[s])) for s in SEVERITIES],
            ("Open questions (UNKNOWN)", str(len(open_questions))),
        ],
    )
    if issues:
        summary += (
            f"\n\nCounts are distinct issues. They group {len(report.findings)} findings; "
            "the register below maps each issue to its findings."
        )
        top = "Top three fixes by risk removed per minute spent:\n\n" + "\n".join(
            f"{i}. {issue.title} (`{issue.first}`, about {issue.effort_minutes} min, {issue.id})"
            for i, issue in enumerate(issues[:3], start=1)
        )
        top += "\n\n" + _register(report)
    else:
        top = "No findings."
    sections = []
    for slug in REVIEWS:
        section = report.sections.get(slug)
        if section is not None:
            parts = [{"title": p.title, "body": _part_body(slug, p, report)} for p in section.parts]
            sections.append({"number": number(slug), "title": TITLES[slug], "parts": parts})
    answered = [q for q in report.questions if not q.open]
    return {
        "meta": report.meta,
        "reviews_run": ", ".join(report.meta.reviews_run) or "none",
        "disclaimer": DISCLAIMER,
        "summary_table": summary,
        "top_fixes": top,
        "detection_table": _detection_table(report),
        "applicability": "Reviews:\n\n"
        + "\n".join(
            f"- Review {number(slug)}, {TITLES[slug]}: {reason}"
            for slug, reason in report.meta.applicability
        ),
        "sections": sections,
        "answered": "\n".join(
            [
                *(
                    f"- {q.question.text} {q.answer} ({SOURCE_LABELS.get(q.source, q.source)})"
                    for q in answered
                ),
                *(f"- {a.question} {a.answer} Evidence: {a.evidence}." for a in report.answered),
            ]
        )
        or "None.",
        "still_open": _table(
            ("Question", "Why the repository cannot answer it", "Who can answer"),
            [(q.question.text, q.question.why, q.question.who) for q in open_questions],
        )
        if open_questions
        else "None.",
        "not_covered": "\n".join(
            f"- {item}" for item in [*ALWAYS_NOT_COVERED, *report.not_covered]
        ),
    }


def render_markdown(report: Report) -> str:
    env = Environment(
        loader=PackageLoader("dpr", "report/templates"),
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    text = env.get_template("report.md.j2").render(**_view(report))
    return re.sub(r"\n{3,}", "\n\n", text).rstrip("\n") + "\n"
