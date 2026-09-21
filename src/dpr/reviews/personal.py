"""Personal data in the data models: which fields, which category, and whose records they are."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cache

from dpr.data import load
from dpr.model import DataModel, Field
from dpr.reviews.leaks_logs import words
from dpr.rules import Context

JSON_TYPES = re.compile(r"(?i)^(?:json|jsonb|Json|JSON|JSONB|JSONField|MutableDict|dict)")
KEY_SUFFIX = re.compile(r"(?:_id|_ids|Id|Ids|_by|_uuid)$")


@dataclass(frozen=True)
class Category:
    key: str
    label: str


@dataclass(frozen=True)
class PersonalField:
    model: DataModel
    field: Field
    category: Category


@cache
def _categories() -> list[tuple[Category, list[tuple[str, ...]]]]:
    return [
        (Category(c["key"], c["label"]), [tuple(words(t)) for t in c["terms"]])
        for c in load("pii_terms.yaml")["categories"]
    ]


def _contains(tokens: list[str], term: tuple[str, ...]) -> bool:
    size = len(term)
    return any(tuple(tokens[i : i + size]) == term for i in range(len(tokens) - size + 1))


def classify(name: str, person: bool = True) -> Category | None:
    """The personal data category of a field name, or None. Keys to other records are not data."""
    if KEY_SUFFIX.search(name):
        return None
    tokens = words(name)
    for category, terms in _categories():
        for term in terms:
            if term == ("name",) and not person:
                continue
            if _contains(tokens, term):
                return category
    return None


def is_person_model(model: DataModel) -> bool:
    names = {model.name.lower(), model.table.split(".")[-1].lower()}
    stems = {w for n in names for w in words(n)}
    person_words = set(load("pii_terms.yaml")["person_models"])
    fields = {f.name.lower() for f in model.fields}
    return bool(stems & person_words) or bool({"email", "phone", "email_address"} & fields)


def about_people(model: DataModel) -> bool:
    """A person model, or a model keyed to one (client_id, user_id, author_id)."""
    if is_person_model(model):
        return True
    person_words = set(load("pii_terms.yaml")["person_models"])
    for field in model.fields:
        if (
            KEY_SUFFIX.search(field.name)
            and set(words(KEY_SUFFIX.sub("", field.name))) & person_words
        ):
            return True
    return False


def personal_fields(ctx: Context) -> list[PersonalField]:
    if "personal_fields" not in ctx.facts:
        found = []
        for model in ctx.detection.models:
            if not about_people(model):
                continue
            person = is_person_model(model)
            for field in model.fields:
                category = classify(field.name, person)
                if category is not None:
                    found.append(PersonalField(model, field, category))
        ctx.facts["personal_fields"] = found
    return ctx.facts["personal_fields"]


def catch_all(field: Field) -> bool:
    names = set(load("pii_terms.yaml")["catch_all_json"])
    return field.name.lower() in names and bool(JSON_TYPES.match(field.type))
