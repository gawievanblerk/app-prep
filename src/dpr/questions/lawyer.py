"""Questions for the data protection lawyer, drawn from what the review found."""

from __future__ import annotations

from dpr.model import Report

CREDENTIAL_RULES = {
    "BASE-LITERAL-PASSWORD-HASH",
    "LEAK-HARDCODED-KEY",
    "LEAK-PUBLIC-SECRET",
    "LEAK-ENV-TRACKED",
    "LEAK-KEY-IN-BUILD",
}
LLM_CATEGORIES = ("llm", "ml")


def _issue_ids(report: Report, rules: set[str]) -> list[str]:
    return [i.id for i in report.register if set(i.findings) & rules]


def lawyer_questions(report: Report) -> list[str]:
    d = report.detection
    recipients = [s.name for s in d.sdks if s.recipient]
    hosts = [h for h in d.hosting if h not in ("docker", "terraform")]
    processors = ", ".join([*recipients, *hosts]) or "any processors the team uses"
    rules = {f.rule_id for f in report.findings}
    items = [
        "What is the purpose of each category of personal data in the data map, and who decided "
        "to collect it?",
        f"Which entity is the controller, and which processors are engaged ({processors})?",
        "Where is each processor located, is a data processing agreement in place with each, and "
        "does personal data cross a border, by what mechanism?",
    ]
    if "INV-NO-DELETION-PATH" in rules:
        items.append(
            "What retention period applies to each category, given that the code enforces none "
            "for the tables listed in the inventory, and what must enforce it?"
        )
    else:
        items.append("What retention period applies to each category, and what enforces it?")
    items.append(
        "How must access, correction and deletion requests be fulfilled, and in what time?"
    )
    items.append("Who may read production data, and must that access be logged?")
    credential_ids = _issue_ids(report, CREDENTIAL_RULES)
    if credential_ids:
        items.append(
            f"If the exposed credentials ({', '.join(credential_ids)}) were used by anyone other "
            "than the account owners, does that trigger a breach assessment or notification duty, "
            "to whom and on what timeline?"
        )
    else:
        items.append("What is the breach detection and notification path, and who owns it?")
    llm = [s.name for s in d.sdks if s.category in LLM_CATEGORIES]
    if llm:
        items.append(
            f"What notice, terms or consent are needed before personal data or free text reaches "
            f"{', '.join(llm)}?"
        )
    if rules & {"INV-SPECIAL-CATEGORY", "INV-CHILDREN-SIGNAL"}:
        items.append(
            "Which legal condition and extra safeguards apply to the special category or "
            "children's data the inventory found?"
        )
    else:
        items.append(
            "Is any special category or children's data processed outside what the code shows?"
        )
    if "INV-PII-FILE-IN-REPO" in rules:
        ids = ", ".join(_issue_ids(report, {"INV-PII-FILE-IN-REPO"}))
        items.append(
            f"Is the personal data committed to the repository ({ids}) a disclosure that needs "
            "assessment, and what purge and notification steps are appropriate?"
        )
    items.append(
        "Does any processing amount to automated decision-making or profiling that must be "
        "disclosed?"
    )
    items.append(
        "Which systems outside this repository hold personal data (support inboxes, CRMs, "
        "spreadsheets, laptops), and are they covered by the same policies?"
    )
    return items
