"""Facts shared across reviews. Each is computed on first use, never as a side effect of a rule,
so a review reads the same fact whether or not the review that also reports on it ran or failed."""

from __future__ import annotations

from collections.abc import Callable

from dpr.rules import Context


def fact[T](ctx: Context, key: str, compute: Callable[[Context], T]) -> T:
    if key not in ctx.facts:
        ctx.facts[key] = compute(ctx)
    return ctx.facts[key]
