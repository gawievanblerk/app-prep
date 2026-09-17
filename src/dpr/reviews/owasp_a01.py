"""Review 5, OWASP A01: unscoped lookups, guessable IDs, unguarded methods, email ownership."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Route, Tag
from dpr.parsing import jsts, pyast
from dpr.redact import snippet
from dpr.reviews.access import ADMIN, PUBLIC, access, unread_guard
from dpr.reviews.lookups import USER_MODELS, model_for, owned, route_lookups
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule

WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
EMAIL_SUBJECT = re.compile(
    r"\b(?:current_user|user|me|caller|request\.user|session\.user)\.email\b"
)
MODEL_EMAIL = re.compile(r"\b([A-Z]\w*)\.email\b")


def unscoped(ctx: Context) -> list[tuple[Route, list, str]]:
    """Unscoped lookups on owned or unknown models, grouped per route, first lookup first."""
    if "unscoped_lookups" not in ctx.facts:
        found = []
        for route in ctx.detection.routes:
            level = access(ctx, route)
            if level.level == ADMIN or is_test(route.file):
                continue
            items = [
                (lookup, check)
                for lookup, check in route_lookups(ctx, route, level)
                if check != "owner" and owned(ctx, lookup.model) is not False
            ]
            if items:
                checks = {check for _, check in items}
                found.append(
                    (route, [lookup for lookup, _ in items], "helper" if "helper" in checks else "")
                )
        ctx.facts["unscoped_lookups"] = found
    return ctx.facts["unscoped_lookups"]


@rule(
    "OWASP-A01-UNSCOPED-QUERY", review="owasp", severity="high", exploitability="high", owasp="A01"
)
def unscoped_query(ctx: Context) -> Iterator[Finding]:
    for route, items, check in unscoped(ctx):
        lookup = items[0]
        known = owned(ctx, lookup.model) is not None
        confirmed = check == "" and known
        proof = None
        if check == "helper":
            proof = "A later call receives the caller; confirm it rejects other owners' records."
        elif not known:
            proof = "The model was not found; confirm the record belongs to a user or tenant."
        locations = [lookup.location, *([lookup.via] if lookup.via else [])]
        locations += [item.location for item in items[1:]]
        level = access(ctx, route).level
        yield make_finding(
            "OWASP-A01-UNSCOPED-QUERY",
            tag=Tag.CONFIRMED if confirmed else Tag.INFERRED,
            locations=locations,
            snippet=snippet(ctx.index.text(route.file), lookup.location.line),
            proof_needed=proof,
            method=route.method,
            path=route.path,
            key=", ".join(lookup.keys),
            model=lookup.model or "record",
            level=level,
        )


@rule(
    "OWASP-A01-GUESSABLE-ID",
    review="owasp",
    severity="medium",
    exploitability="medium",
    owasp="A01",
)
def guessable_id(ctx: Context) -> Iterator[Finding]:
    seen = set()
    for route in ctx.detection.routes:
        level = access(ctx, route)
        if level.level == ADMIN or is_test(route.file):
            continue
        for lookup, _check in route_lookups(ctx, route, level):
            model = model_for(ctx, lookup.model)
            if not lookup.by_primary_key or model is None or not owned(ctx, lookup.model):
                continue
            id_field = next((f for f in model.fields if f.name in ("id", "pk")), None)
            key = (route.file, lookup.location.line)
            if id_field is not None and id_field.autoincrement and key not in seen:
                seen.add(key)
                yield make_finding(
                    "OWASP-A01-GUESSABLE-ID",
                    tag=Tag.CONFIRMED,
                    locations=[lookup.location, id_field.location],
                    model=model.name,
                    path=route.path,
                )


@rule(
    "OWASP-A01-UNGUARDED-METHOD",
    review="owasp",
    severity="high",
    exploitability="high",
    owasp="A01",
)
def unguarded_method(ctx: Context) -> Iterator[Finding]:
    groups: dict[tuple[str, str], list[Route]] = {}
    for route in ctx.detection.routes:
        groups.setdefault((route.file, route.path), []).append(route)
    for (_file, path), routes in sorted(groups.items()):
        guarded = [r for r in routes if access(ctx, r).level != PUBLIC]
        if not guarded:
            continue
        for route in routes:
            level = access(ctx, route)
            if route.method in WRITE_METHODS and level.level == PUBLIC:
                proof = unread_guard(level)
                yield make_finding(
                    "OWASP-A01-UNGUARDED-METHOD",
                    tag=Tag.INFERRED if proof else Tag.CONFIRMED,
                    locations=[Location(route.file, route.line)],
                    snippet=snippet(ctx.index.text(route.file), route.line),
                    proof_needed=proof,
                    method=route.method,
                    path=path,
                    guarded=", ".join(sorted({r.method for r in guarded})),
                )


def _py_email_matches(tree: ast.Module) -> Iterator[tuple[int, str]]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            text = ast.unparse(node)
            model = MODEL_EMAIL.search(text)
            if model and EMAIL_SUBJECT.search(text):
                yield node.lineno, model.group(1)
        if isinstance(node, ast.keyword) and node.arg == "email":
            call_text = ast.unparse(node.value)
            if EMAIL_SUBJECT.search(call_text):
                yield node.value.lineno, ""


@rule(
    "OWASP-A01-EMAIL-OWNERSHIP",
    review="owasp",
    severity="high",
    exploitability="medium",
    owasp="A01",
)
def email_ownership(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel) or ".email" not in text:
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for line, model in sorted(set(_py_email_matches(tree))) if tree else []:
            if not model or model.lower().rstrip("s") in {m.rstrip("s") for m in USER_MODELS}:
                continue
            yield make_finding(
                "OWASP-A01-EMAIL-OWNERSHIP",
                tag=Tag.INFERRED,
                locations=[Location(entry.rel, line)],
                snippet=snippet(text, line),
                model=model,
            )
    for entry in ctx.index.js_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel) or "email" not in text:
            continue
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for call in jsts.calls(tree, r"\w+\.(\w+)\.(?:findFirst|findUnique|findMany)"):
                model = jsts.callee(call).split(".")[-2]
                body = jsts.node_text(call)
                if model.lower().rstrip("s") in {m.rstrip("s") for m in USER_MODELS}:
                    continue
                if re.search(
                    r"email\s*:\s*(?:session|user|currentUser)\??\.(?:user\??\.)?email", body
                ):
                    line = jsts.line(tree, call)
                    yield make_finding(
                        "OWASP-A01-EMAIL-OWNERSHIP",
                        tag=Tag.INFERRED,
                        locations=[Location(entry.rel, line)],
                        snippet=snippet(text, line),
                        model=model,
                    )
