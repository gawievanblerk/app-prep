"""Review 1, inventory: special category fields, signals of children's data, catch-all JSON."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Tag
from dpr.parsing import pyast
from dpr.redact import snippet
from dpr.reviews.paths import is_test
from dpr.reviews.personal import catch_all, personal_fields
from dpr.rules import Context, make_finding, rule
from dpr.walk import line_of

AGE_FIELD = re.compile(r"(?i)^(?:age|min_age|minimum_age)$")
JS_AGE_MIN = re.compile(r"(?i)\bage\s*:\s*z\.number\(\)[\w.()]*?\.(?:min|gte)\(\s*(\d+)")


def _by_model(ctx: Context, key: str) -> dict[str, list]:
    groups: dict[str, list] = {}
    for item in personal_fields(ctx):
        if item.category.key == key:
            groups.setdefault(f"{item.model.location.file}:{item.model.name}", []).append(item)
    return groups


@rule("INV-SPECIAL-CATEGORY", review="inventory", severity="high", exploitability="low")
def special_category(ctx: Context) -> Iterator[Finding]:
    for items in _by_model(ctx, "special").values():
        model = items[0].model
        yield make_finding(
            "INV-SPECIAL-CATEGORY",
            tag=Tag.CONFIRMED,
            locations=[i.field.location for i in items][:10],
            snippet=snippet(
                ctx.index.text(items[0].field.location.file), items[0].field.location.line
            ),
            model=model.name,
            fields=", ".join(i.field.name for i in items),
        )


def _py_age_minimums(ctx: Context) -> Iterator[tuple[Location, int]]:
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel) or "age" not in text:
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for node in ast.walk(tree) if tree else []:
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                if not AGE_FIELD.match(node.target.id) or not isinstance(node.value, ast.Call):
                    continue
                for key in ("ge", "gt", "min_value"):
                    value = pyast.constant(pyast.kwarg(node.value, key), None)
                    if isinstance(value, int) and value < 18:
                        yield Location(entry.rel, node.lineno), value


def _js_age_minimums(ctx: Context) -> Iterator[tuple[Location, int]]:
    for entry in ctx.index.js_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel):
            continue
        for match in JS_AGE_MIN.finditer(text):
            if int(match.group(1)) < 18:
                yield Location(entry.rel, line_of(text, match.start())), int(match.group(1))


@rule("INV-CHILDREN-SIGNAL", review="inventory", severity="high", exploitability="low")
def children_signal(ctx: Context) -> Iterator[Finding]:
    for items in _by_model(ctx, "children").values():
        yield make_finding(
            "INV-CHILDREN-SIGNAL",
            tag=Tag.INFERRED,
            locations=[i.field.location for i in items][:10],
            what=f"{items[0].model.name} stores {', '.join(i.field.name for i in items)}.",
        )
    ages = [*_py_age_minimums(ctx), *_js_age_minimums(ctx)]
    if ages:
        minimum = min(value for _, value in ages)
        yield make_finding(
            "INV-CHILDREN-SIGNAL",
            tag=Tag.INFERRED,
            locations=[loc for loc, _ in ages][:10],
            what=f"An age check accepts users as young as {minimum}.",
        )


@rule("INV-CATCHALL-JSON", review="inventory", severity="medium", exploitability="low")
def catch_all_json(ctx: Context) -> Iterator[Finding]:
    for model in ctx.detection.models:
        for field in model.fields:
            if catch_all(field) and not is_test(field.location.file):
                yield make_finding(
                    "INV-CATCHALL-JSON",
                    tag=Tag.CONFIRMED,
                    locations=[field.location],
                    snippet=snippet(ctx.index.text(field.location.file), field.location.line),
                    model=model.name,
                    field=field.name,
                )
