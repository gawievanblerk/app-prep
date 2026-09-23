"""Review 5, OWASP A01: sensitive actions on routes anyone can call.

A route the classifier marks public is reported once when it sets a password or changes a
user account, looks up personal data by a value from the request, returns a file, lists stored
records that hold personal data, files or users' records, or starts a background job or a
back-office write that takes no input at all.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from dataclasses import dataclass

from dpr.model import Finding, Location, Route, Tag
from dpr.parsing import pyast
from dpr.redact import snippet
from dpr.reviews.access import PUBLIC, Access, access, path_params, unread_guard
from dpr.reviews.lookups import PY_ORM, Lookup, owned, user_model
from dpr.reviews.lookups_route import handler_functions, route_lookups
from dpr.reviews.owasp_hooks import callback_routes, reachable
from dpr.reviews.paid_targets import py_target
from dpr.reviews.paths import is_test
from dpr.reviews.record_lists import has_file_field, personal_model, route_lists
from dpr.reviews.request_values import PERSONAL_KEY, reads, request_names, trace
from dpr.reviews.unscoped import route_unscoped, sequential_id
from dpr.rules import Context, make_finding, rule

TOKEN_CHECK = re.compile(r"check_token\(|signing\.loads\(|\.unsign\(|verify_token|verify_signature")
READ_CALL = re.compile(
    r"(?:^|\.)(?:get|filter|exclude|first|Q|get_object_or_404|get_list_or_404)$"
    r"|(?i:lookup|search|find|fetch|retrieve|query)"
)
FILE_CALL = re.compile(
    r"(?:^|\.)(?:FileResponse|send_file|StreamingHttpResponse|send_from_directory)$"
)
FILE_TYPE = re.compile(
    r"^(?:application/(?:pdf|zip|x-zip\S*|octet-stream|vnd\.\S+|msword|x-pdf)|text/csv)"
)
JOB_CALL = re.compile(
    r"\.(?:delay|apply_async|submit)$|(?:^|\.)(?:run_in_background|Thread|Process|start_new_thread)$"
)
WRITE_CALL = re.compile(r"\.(?:create|bulk_create|bulk_update|update|delete|update_or_create)$")
LLM_CALL = re.compile(
    r"(?:^|\.)(?:messages|completions|responses|embeddings)\.create$|\.generate_content$"
)
STORED_READ = re.compile(
    r"\bopen\(|\.read_bytes\(|\b(?:db|session|conn|cursor)\.(?:execute|query|scalars?|fetch\w*)\("
)
INPUT = (
    r"(?:GET|POST|FGET|FPOST|data|query_params|body|FILES|headers|META|json|args|form|values"
    r"|get_json)\b"
)
RANDOM_KEY = re.compile(r"(?i)uuid|guid|token|secret|signature|nonce")
ACTIONS = {
    "password": "sets a user's password",
    "account": "changes a user account",
    "personal": "looks up personal data by {label}",
    "file": "returns a file",
    "list": "lists stored {model} records",
    "lookup": "looks up a {found} record by {key}",
    "job": "starts a background job",
    "write": "runs a back-office write that takes no input",
}
ORDER = tuple(ACTIONS)


@dataclass(frozen=True)
class Sensitive:
    route: Route
    kinds: dict[str, Location]
    label: str
    exact: bool
    model: str = ""
    lookup: Lookup | None = None  # an unscoped lookup this finding carries
    sequential: Location | None = None


def _records(fn: ast.AST) -> dict[str, str]:
    """Names holding records loaded from the database, with the model they came from."""
    found: dict[str, str] = {}
    nodes = sorted(
        (n for n in ast.walk(fn) if isinstance(n, ast.Assign | ast.For)),
        key=lambda n: (n.lineno, n.col_offset),
    )
    for node in nodes:
        value = node.iter if isinstance(node, ast.For) else node.value
        targets = [node.target] if isinstance(node, ast.For) else node.targets
        names = [n.id for t in targets for n in ast.walk(t) if isinstance(n, ast.Name)]
        text = ast.unparse(value)
        model = re.search(r"(\w+)\.objects\.|get_object_or_404\(\s*(\w+)", text)
        source = next((found[n] for n in pyast.names_in(value) if n in found), None)
        if PY_ORM.search(text) and model:
            source = next(g for g in model.groups() if g)
        for name in names if source is not None else []:
            found[name] = source
    return found


def _nodes(fn: ast.AST) -> list[ast.AST]:
    return [node for stmt in reachable(fn) for node in ast.walk(stmt)]


def _receiver(call: ast.Call) -> str:
    if not isinstance(call.func, ast.Attribute):
        return ""
    return pyast.name_root(call.func.value) or ""


def _own_kinds(fn: ast.AST, framework: str, keys: set[str]) -> tuple[dict[str, int], str]:
    """Sensitive actions read in one handler function, and the personal key it looks up by."""
    lines: dict[str, int] = {}
    label = ""
    records = _records(fn)
    taint = trace(fn, {k: k for k in keys}, framework)
    text = ast.unparse(fn)
    for node in _nodes(fn):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value.lower() == "content-disposition":
                lines.setdefault("file", node.lineno)
        if not isinstance(node, ast.Call):
            continue
        name = pyast.dotted(node.func) or ""
        receiver = records.get(_receiver(node), "")
        if name.endswith(".set_password") and user_model(receiver) and not TOKEN_CHECK.search(text):
            lines.setdefault("password", node.lineno)
        if name.endswith("SetPasswordForm") and ".save(" in text:
            lines.setdefault("password", node.lineno)
        if name.endswith((".save", ".update")) and user_model(receiver):
            if not TOKEN_CHECK.search(text):
                lines.setdefault("account", node.lineno)
        if FILE_CALL.search(name):
            lines.setdefault("file", node.lineno)
            lines.setdefault("stored-file", node.lineno)
        for keyword in node.keywords:
            value = pyast.constant(keyword.value, None)
            if keyword.arg in ("content_type", "mimetype") and isinstance(value, str):
                if FILE_TYPE.match(value):
                    lines.setdefault("file", node.lineno)
            parts = (keyword.arg or "").split("__")
            personal = next((p for p in parts if PERSONAL_KEY.fullmatch(p)), None)
            if personal and READ_CALL.search(name) and reads(keyword.value, taint):
                lines.setdefault("personal", node.lineno)
                label = label or personal
        if JOB_CALL.search(name):
            lines.setdefault("job", node.lineno)
    return lines, label


def _takes_input(fn: ast.AST, framework: str) -> bool:
    """The handler reads something the caller sends: a parameter, the query string, a form,
    the body, uploaded files or headers."""
    django = framework in ("django", "drf", "ninja")
    names = "|".join(re.escape(n) for n in request_names(fn, django))
    params = [a.arg for a in fn.args.args if a.arg not in ("self", "cls")]
    params += [a.arg for a in fn.args.kwonlyargs]
    if framework == "fastapi" and params:
        return True  # every FastAPI parameter is a path, query, body, header or file value
    return len(params) > 1 or bool(re.search(rf"\b(?:{names})\.{INPUT}", ast.unparse(fn)))


def _helper_kinds(ctx: Context, rel: str, fn: ast.AST) -> dict[str, Location]:
    """Background jobs and record writes in the helpers the handler calls, one level down."""
    found: dict[str, Location] = {}
    for call in (n for n in _nodes(fn) if isinstance(n, ast.Call)):
        target = py_target(ctx, rel, call, fn)
        if target is None or not target[2]:
            continue
        for inner in (n for n in ast.walk(target[1]) if isinstance(n, ast.Call)):
            name = pyast.dotted(inner.func) or ""
            if JOB_CALL.search(name):
                found.setdefault("job", Location(target[0], inner.lineno))
            elif LLM_CALL.search(name):
                continue
            elif WRITE_CALL.search(name) or name.endswith(".objects.create"):
                found.setdefault("write", Location(target[0], inner.lineno))
    return found


def _stored_text(text: str) -> bool:
    return bool(PY_ORM.search(text) or STORED_READ.search(text))


def _reads_stored(ctx: Context, route: Route) -> bool:
    """The handler, or a helper it calls, reads a stored record or file."""
    for fn in handler_functions(route.handler):
        if _records(fn) or _stored_text(ast.unparse(fn)):
            return True
        for call in (n for n in _nodes(fn) if isinstance(n, ast.Call)):
            target = py_target(ctx, route.file, call, fn)
            if target is not None and _stored_text(ast.unparse(target[1])):
                return True
    return False


def _record_list(ctx: Context, route: Route) -> tuple[Location, str, bool] | None:
    """The first list of records sent by the handler whose model holds personal data, files or
    records owned by users, and whether the model surely holds personal data or files."""
    for item in route_lists(ctx, route):
        sure = personal_model(ctx, item.model) or has_file_field(ctx, item.model)
        if sure or owned(ctx, item.model):
            return Location(route.file, item.line), item.model, sure
    return None


def _sensitive(ctx: Context, route: Route, level: Access) -> Sensitive | None:
    kinds: dict[str, Location] = {}
    label = ""
    listed = _record_list(ctx, route)
    if listed is not None:
        kinds["list"] = listed[0]
    keys = set(path_params(route))
    takes_input = stored_file = False
    for fn in handler_functions(route.handler):
        own, found = _own_kinds(fn, route.framework, keys)
        stored_file = stored_file or "stored-file" in own
        for kind, line in own.items():
            if kind != "stored-file":
                kinds.setdefault(kind, Location(route.file, line))
        label = label or found
        takes_input = takes_input or bool(keys) or _takes_input(fn, route.framework)
        for kind, location in _helper_kinds(ctx, route.file, fn).items():
            if kind == "job" or not takes_input:
                kinds.setdefault(kind, location)
        writes = [n for n in _nodes(fn) if isinstance(n, ast.Call)]
        for call in writes if not takes_input else []:
            name = pyast.dotted(call.func) or ""
            if LLM_CALL.search(name):
                continue
            if WRITE_CALL.search(name) and ".objects." in ast.unparse(call.func):
                kinds.setdefault("write", Location(route.file, call.lineno))
    if "file" in kinds and not stored_file and not _reads_stored(ctx, route):
        del kinds["file"]  # rendered from the request alone, no stored record behind it
    if route in callback_routes(ctx):
        kinds = {k: v for k, v in kinds.items() if k not in ("job", "write")}
    if not kinds:
        return None
    lookups = [lookup for lookup, _check in route_lookups(ctx, route, level)]
    keyed = bool(lookups) and not any(RANDOM_KEY.search(k) for k in lookups[0].keys)
    exact = unread_guard(level) is None and (
        "password" in kinds
        or ("personal" in kinds or "file" in kinds)
        and keyed
        or listed is not None
        and listed[2]
    )
    carried = next(iter(route_unscoped(ctx, route)), None)
    if carried is not None and "personal" not in kinds:
        kinds["lookup"] = carried.location
    sequential = sequential_id(ctx, carried) if carried is not None else None
    return Sensitive(route, kinds, label, exact, listed[1] if listed else "", carried, sequential)


def public_sensitive(ctx: Context) -> list[Sensitive]:
    """Public routes with a sensitive action, one per file and path, read once per run."""
    if "public_sensitive" not in ctx.facts:
        found, seen = [], set()
        for route in ctx.detection.routes:
            if not isinstance(route.handler, ast.AST) or is_test(route.file):
                continue
            level = access(ctx, route)
            if level.level != PUBLIC or (route.file, route.path) in seen:
                continue
            item = _sensitive(ctx, route, level)
            if item is not None:
                seen.add((route.file, route.path))
                found.append(item)
        ctx.facts["public_sensitive"] = found
    return ctx.facts["public_sensitive"]


def public_sensitive_routes(ctx: Context) -> set[Route]:
    """Routes this rule reports: their unscoped lookup is part of that finding."""
    return {item.route for item in public_sensitive(ctx)}


@rule(
    "OWASP-A01-PUBLIC-SENSITIVE",
    review="owasp",
    severity="critical",
    exploitability="high",
    owasp="A01",
)
def public_sensitive_actions(ctx: Context) -> Iterator[Finding]:
    for item in public_sensitive(ctx):
        route = item.route
        kinds = sorted(item.kinds, key=ORDER.index)
        lookup = item.lookup
        actions = [
            ACTIONS[k].format(
                label=item.label or "a request value",
                model=item.model,
                found=lookup.model or "stored" if lookup else "",
                key=", ".join(lookup.keys) if lookup else "",
            )
            for k in kinds
        ]
        proofs = []
        guard = unread_guard(access(ctx, route))
        if guard:
            proofs.append(guard)
        if not item.exact:
            proofs.append(
                "Confirm the action is not meant for anyone: a random link key, a job that "
                "only reads, or a file with no personal data would make it safe."
            )
        first = item.kinds[kinds[0]]
        locations = [first] + [item.kinds[k] for k in kinds[1:] if item.kinds[k] != first]
        locations += [item.sequential] if item.sequential is not None else []
        severity = None if item.exact else "high"
        if item.sequential is not None:
            severity = "critical"
        yield make_finding(
            "OWASP-A01-PUBLIC-SENSITIVE",
            tag=Tag.CONFIRMED if item.exact else Tag.INFERRED,
            locations=locations,
            snippet=snippet(ctx.index.text(first.file), first.line),
            severity=severity,
            proof_needed=" ".join(proofs) or None,
            method=route.method,
            path=route.path,
            action=actions[0],
            actions="; ".join(actions),
        )
