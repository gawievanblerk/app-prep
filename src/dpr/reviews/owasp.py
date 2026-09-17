"""Review 5, OWASP sweep: own rules weighted to broken access control."""

from __future__ import annotations

from dpr.model import Part, ReviewSection
from dpr.rules import Context


def run(ctx: Context) -> ReviewSection:
    return ReviewSection("owasp", [Part("findings", "Findings")])
