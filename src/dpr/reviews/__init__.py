"""Review numbers, slugs, titles and loading."""

from __future__ import annotations

import importlib
from collections.abc import Iterable
from types import ModuleType

from dpr.model import ScanError

REVIEWS = ("inventory", "rls", "auth", "baseline", "owasp", "leaks", "abuse")
TITLES = {
    "inventory": "Data inventory",
    "rls": "Database lock check",
    "auth": "Failure path test plan",
    "baseline": "Security baseline",
    "owasp": "OWASP sweep",
    "leaks": "Leak hunt",
    "abuse": "Abuse and bill guard",
}
LABELS = {
    "inventory": "INV",
    "rls": "RLS",
    "auth": "AUTH",
    "baseline": "FIX",
    "owasp": "FINDING",
    "leaks": "LEAK",
    "abuse": "GUARD",
}
RUN_ORDER = ("leaks", "rls", "baseline", "auth", "owasp", "abuse", "inventory")


def number(slug: str) -> int:
    return REVIEWS.index(slug) + 1


def resolve_reviews(requested: Iterable[str | int]) -> list[str]:
    selected: set[str] = set()
    for item in requested:
        token = str(item).strip().lower()
        if token == "all":
            selected.update(REVIEWS)
        elif token.isdigit() and 1 <= int(token) <= len(REVIEWS):
            selected.add(REVIEWS[int(token) - 1])
        elif token in REVIEWS:
            selected.add(token)
        else:
            raise ScanError(f"unknown review: {item}. Use all, 1 to 7, or {', '.join(REVIEWS)}")
    if not selected:
        raise ScanError("no reviews selected")
    return [slug for slug in REVIEWS if slug in selected]


def available() -> dict[str, ModuleType]:
    modules: dict[str, ModuleType] = {}
    for slug in REVIEWS:
        name = f"dpr.reviews.{slug}"
        try:
            modules[slug] = importlib.import_module(name)
        except ModuleNotFoundError as exc:
            if exc.name != name:
                raise
    return modules
