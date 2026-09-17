"""Review 5, OWASP sweep: own rules weighted to broken access control."""

from __future__ import annotations

import dpr.reviews.owasp_a01  # noqa: F401  (registers rules)
import dpr.reviews.owasp_assign  # noqa: F401  (registers rules)
import dpr.reviews.owasp_inject  # noqa: F401  (registers rules)
import dpr.reviews.owasp_misc  # noqa: F401  (registers rules)
import dpr.reviews.owasp_paths  # noqa: F401  (registers rules)
from dpr.model import Part, ReviewSection
from dpr.rules import Context


def run(ctx: Context) -> ReviewSection:
    return ReviewSection("owasp", [Part("findings", "Findings")])
