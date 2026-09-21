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
BREACHED = "Screening new passwords against breached-password lists is not checked"
HOSTNAMES = (
    "Infrastructure hostnames and internal endpoints named in committed example env files and "
    "documentation are not reported"
)
OFF_REPO = (
    "Copies of personal data kept outside the repository, such as database restores or exports "
    "on developer machines, cannot be seen from the code"
)


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
    if "auth" in sections:
        notes.append(BREACHED)
    if "leaks" in sections:
        notes.append(HOSTNAMES)
    if "inventory" in sections:
        notes.append(OFF_REPO)
    return notes
