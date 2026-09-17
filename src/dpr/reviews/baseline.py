"""Review 4, security baseline: headers, cookies, transport, password storage."""

from __future__ import annotations

import dpr.reviews.baseline_config  # noqa: F401  (registers rules)
from dpr.model import Part, ReviewSection
from dpr.rules import Context


def run(ctx: Context) -> ReviewSection:
    return ReviewSection("baseline", [Part("findings", "Fix list")])
