"""Lines for "What this review did not cover" that depend on what the repository contains."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from dpr.gitutil import tracked_files
from dpr.model import Detection
from dpr.rules import Options

DOCUMENTS = re.compile(
    r"(?i)\.(?:pdf|xlsx|xlsm|xls|docx|doc|pptx|png|jpe?g|sqlite3?|db|bak|bacpac|dump)$"
)
PAID_ROLE = (
    "Paid routes are not compared with the roles the product intends, so a paid route open to "
    "every signed-in role is not reported"
)
BULK = (
    "Request lists that fan out into many renders, sends or imports are not checked for size caps"
)
READ_AUDIT = (
    "Whether reads, exports and downloads of personal data are written to an audit trail is not "
    "checked"
)
OPENAPI = (
    "Whether the API schema route (openapi.json) stays public when interactive docs are turned "
    "off is not checked"
)
BREACHED = "Screening new passwords against breached-password lists is not checked"
EMAILS = "Email addresses in tests and documentation are not checked for real people"


def coverage_notes(root, detection: Detection, options: Options, sections: set[str]) -> list[str]:
    notes = []
    if not options.with_audit:
        notes.append("Dependency vulnerability audit (npm audit, pip-audit) was not run")
    if "leaks" in sections:
        notes.append(
            "Git history was checked for committed .env files only; a full secret scan of every "
            "commit (gitleaks or trufflehog) was not run"
        )
    tracked = tracked_files(root) or []
    documents = [p for p in tracked if DOCUMENTS.search(p) and "node_modules" not in p]
    if documents:
        examples = ", ".join(sorted(documents, key=lambda p: (len(PurePosixPath(p).parts), p))[:3])
        notes.append(
            f"{len(documents)} committed documents, images, spreadsheets or database files (for "
            f"example {examples}) were not read, so personal data inside them is not inventoried"
        )
    if "abuse" in sections and any(s.paid for s in detection.sdks):
        notes.append(PAID_ROLE)
    if detection.routes:
        notes += [BULK, READ_AUDIT, EMAILS]
    if "fastapi" in detection.frameworks:
        notes.append(OPENAPI)
    if "auth" in sections:
        notes.append(BREACHED)
    return notes
