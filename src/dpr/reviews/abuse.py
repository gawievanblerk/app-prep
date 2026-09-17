"""Review 7, abuse and bill guard: paid routes, limits, forms, CORS and error text."""

from __future__ import annotations

import dpr.reviews.abuse_paid  # noqa: F401  (registers rules)
from dpr.model import Part, ReviewSection
from dpr.rules import Context


def run(ctx: Context) -> ReviewSection:
    return ReviewSection("abuse", [Part("findings", "Guards")])
