"""Review 5, OWASP A01: unscoped lookups and lists, unguarded methods, email ownership."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Route, Tag
from dpr.parsing import jsts, pyast
from dpr.redact import snippet
from dpr.reviews.access import ADMIN, AUTHENTICATED, PUBLIC, Access, access, unread_guard
from dpr.reviews.lookups import USER_MODELS, Lookup, model_for, owned, user_model
from dpr.reviews.lookups_route import handler_functions, route_lookups
from dpr.reviews.owasp_public import public_sensitive_routes
from dpr.reviews.paths import is_test
from dpr.reviews.record_lists import personal_model, route_lists
from dpr.reviews.request_values import request_names
from dpr.rules import Context, make_finding, rule

WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
ROLE_ORDER = ("customer", "client", "viewer", "member", "editor", "agent", "manager", "staff")
EMAIL_SUBJECT = re.compile(
    r"\b(?:current_user|user|me|caller|request\.user|session\.user)\.email\b"
)
MODEL_EMAIL = re.compile(r"\b([A-Z]\w*)\.email\b")
PUBLIC_PROOF = "Confirm this record type is not meant to be public."
ROLE_BODY = r"user\.(?:has_perms?|is_superuser|is_staff|groups)\b"
ROLE_PROOF = (
    "Role-gated back-office access ({role}): confirm by design that every holder of this role "
    "may reach every record."
)
LIST_PROOF = (
    "Confirm that every signed-in account (staff, advisors, partners) may see every {model} "
    "record; a narrower audience needs a role check or a filter on the caller."
)
SEQUENTIAL = " {model} has an auto-increment integer key, so one working ID reveals the others."
PUBLIC_ATTACK = (
    "1. Without signing in, request the route with one identifier. 2. Change the identifier. "
    "3. Read or change a record that was not meant to be public."
)


def attacker(evidence: str) -> str:
    """Who can make the request, from the least privileged role named by the auth check."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", evidence).lower()
    named = set(re.split(r"[^a-z0-9]+", spaced))
    role = next((r for r in ROLE_ORDER if r in named or f"{r}s" in named), None)
    return f"any {role} account" if role else "any signed-in user"


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
                if check != "owner" and not lookup.visible and owned(ctx, lookup.model) is not False
            ]
            if items:
                checks = {check for _, check in items}
                found.append(
                    (route, [lookup for lookup, _ in items], "helper" if "helper" in checks else "")
                )
        ctx.facts["unscoped_lookups"] = found
    return ctx.facts["unscoped_lookups"]


def role_gate(route: Route, level: Access) -> str:
    """A check beyond sign-in: a role decorator or permission class, or a permission, staff,
    superuser or group test on the caller (`request.user`, never a loaded user) in the
    handler itself."""
    if level.level != AUTHENTICATED:
        return ""
    if level.role:
        return level.role
    handler = route.handler if isinstance(route.handler, ast.AST) else None
    for fn in handler_functions(handler) if handler is not None else []:
        callers = "|".join(re.escape(name) for name in request_names(fn, True))
        found = re.search(rf"\b(?:{callers})\.{ROLE_BODY}", ast.unparse(fn))
        if found:
            return found.group(0)
    return ""


def sequential_id(ctx: Context, lookup: Lookup) -> Location | None:
    """The auto-increment integer key of an owned model looked up by primary key."""
    model = model_for(ctx, lookup.model)
    if not lookup.by_primary_key or model is None or not owned(ctx, lookup.model):
        return None
    id_field = next((f for f in model.fields if f.name in ("id", "pk")), None)
    return id_field.location if id_field is not None and id_field.autoincrement else None


@rule(
    "OWASP-A01-UNSCOPED-QUERY", review="owasp", severity="high", exploitability="high", owasp="A01"
)
def unscoped_query(ctx: Context) -> Iterator[Finding]:
    reported = public_sensitive_routes(ctx)
    for route, items, check in unscoped(ctx):
        lookup = items[0]
        known = owned(ctx, lookup.model) is not None
        level = access(ctx, route)
        if level.level == PUBLIC and route in reported:
            continue
        role = role_gate(route, level)
        sequential = sequential_id(ctx, lookup)
        proofs, extra = [], ""
        if check == "helper":
            proofs.append(
                "A later call receives the caller; confirm it rejects other owners' records."
            )
        elif not known:
            proofs.append(
                "The model was not found; confirm the record belongs to a user or tenant."
            )
        if level.level == PUBLIC:
            proofs.append(PUBLIC_PROOF)
        if role:
            proofs.append(ROLE_PROOF.format(role=role))
        if sequential is not None:
            extra = SEQUENTIAL.format(model=model_for(ctx, lookup.model).name)
        locations = [lookup.location, *([lookup.via] if lookup.via else [])]
        locations += [item.location for item in items[1:]]
        locations += [sequential] if sequential is not None else []
        severity = exploitability = None
        if role:
            severity = exploitability = "low"
        elif level.level == PUBLIC and sequential is not None:
            severity = "critical"
        yield make_finding(
            "OWASP-A01-UNSCOPED-QUERY",
            tag=Tag.INFERRED if proofs else Tag.CONFIRMED,
            locations=locations,
            snippet=snippet(ctx.index.text(route.file), lookup.location.line),
            severity=severity,
            exploitability=exploitability,
            proof_needed=" ".join(proofs) or None,
            attack=PUBLIC_ATTACK if level.level == PUBLIC else None,
            method=route.method,
            path=route.path,
            key=", ".join(lookup.keys),
            model=lookup.model or "record",
            level=level.level,
            attacker=attacker(level.evidence),
            extra=extra,
        )


@rule(
    "OWASP-A01-UNSCOPED-LIST", review="owasp", severity="high", exploitability="high", owasp="A01"
)
def unscoped_list(ctx: Context) -> Iterator[Finding]:
    """A signed-in route with no role gate that sends every user or personal record."""
    for route in ctx.detection.routes:
        level = access(ctx, route)
        if level.level != AUTHENTICATED or is_test(route.file) or role_gate(route, level):
            continue
        lists = [i for i in route_lists(ctx, route) if not i.related]
        item = next((i for i in lists if personal_model(ctx, i.model)), None)
        if item is None:
            continue
        users = user_model(item.model)
        proof = unread_guard(level)
        if not users:
            proof = " ".join(p for p in (proof, LIST_PROOF.format(model=item.model)) if p)
        yield make_finding(
            "OWASP-A01-UNSCOPED-LIST",
            tag=Tag.INFERRED if proof else Tag.CONFIRMED,
            locations=[Location(route.file, item.line)],
            snippet=snippet(ctx.index.text(route.file), item.line),
            proof_needed=proof or None,
            method=route.method,
            path=route.path,
            model=item.model,
            attacker=attacker(level.evidence),
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
