"""Review 3: email change, unique emails, signup no screen uses, and second factors."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.discovery.approots import root_of
from dpr.model import Finding, Location, Tag
from dpr.parsing import jsts, pyast
from dpr.redact import snippet
from dpr.reviews.auth_flows import (
    PARAM_SEGMENT,
    Code,
    Flow,
    flows_of,
    managed_provider,
    record_pass,
    user_models,
    user_models_in,
)
from dpr.reviews.deploy_env import applies, declared_for
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule

VERIFY_WORDS = re.compile(
    r"(?i)verif|confirm|pending_?email|new_?email|email_?change|change_?token|current_?password"
    r"|check_?password|re_?authenticat"
)
EMAIL_FIELDS = ("email", "email_address", "emailAddress")
UNIQUE_TEXT = re.compile(
    r"UniqueConstraint\([^)]*email|Index\([^)]*email[^)]*unique\s*=\s*True|unique_together[^\n]*email"
    r"|@@unique\(\[\s*email|uniqueIndex\([^)]*\)\.on\([^)]*email"
)
UI_SUFFIXES = (".tsx", ".jsx", ".vue", ".svelte")
MFA_PACKAGES = {
    "pyotp", "django-otp", "django-two-factor-auth", "otplib", "speakeasy",
    "@simplewebauthn/server", "fido2", "webauthn", "py-webauthn", "flask-security-too",
}  # fmt: skip
MFA_WORDS = re.compile(r"(?i)totp|mfa|two_?factor|2fa|otp_?secret|webauthn|second_?factor|passkey")


def _py_identifiers(code: Code) -> list[str]:
    names = []
    for node in ast.walk(code.node):
        if isinstance(node, ast.Name):
            names.append(node.id)
        elif isinstance(node, ast.Attribute):
            names.append(node.attr)
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            names += [a.arg for a in node.args.args]
    return names


def _identifiers(code: Code) -> list[str]:
    if code.python:
        return _py_identifiers(code)
    kinds = {"identifier", "property_identifier", "shorthand_property_identifier"}
    return [jsts.node_text(n) for n in jsts.walk(code.node, kinds)]


def _email_list(node: ast.AST | None) -> bool:
    """A set, list or tuple of two or more field names that includes an email field."""
    if not isinstance(node, ast.Set | ast.List | ast.Tuple) or len(node.elts) < 2:
        return False
    values = [pyast.constant(e, None) for e in node.elts]
    return all(isinstance(v, str) for v in values) and any(v in EMAIL_FIELDS for v in values)


def _writes(nodes: list[ast.stmt]) -> bool:
    """The statements set an attribute on an object (setattr or `x.field = value`)."""
    return any(
        (isinstance(n, ast.Call) and pyast.dotted(n.func) == "setattr")
        or (isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Attribute))
        for stmt in nodes
        for n in ast.walk(stmt)
    )


def _refuses(nodes: list[ast.stmt]) -> bool:
    return any(isinstance(n, ast.Raise | ast.Continue) for stmt in nodes for n in ast.walk(stmt))


def _named(node: ast.AST, names: set[str]) -> bool:
    return isinstance(node, ast.Name) and node.id in names


def _allow_list_uses(root: ast.AST, names: set[str]) -> set[str]:
    """Names used as an allow-list of updatable fields: in a set difference, as
    `model_dump(include=...)`, in an `in` test that guards a write or filters a comprehension, in
    a `not in` test that refuses or skips, or as the fields a loop writes."""
    used = set()
    for node in ast.walk(root):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Sub):
            used |= {n.id for n in (node.left, node.right) if _named(n, names)}
        elif isinstance(node, ast.keyword) and node.arg == "include" and _named(node.value, names):
            used.add(node.value.id)
        elif isinstance(node, ast.If | ast.comprehension):
            tests = [node.test] if isinstance(node, ast.If) else node.ifs
            for compare in (c for t in tests for c in ast.walk(t) if isinstance(c, ast.Compare)):
                if len(compare.ops) != 1 or not _named(compare.comparators[0], names):
                    continue
                allowing = isinstance(compare.ops[0], ast.In) and (
                    isinstance(node, ast.comprehension) or _writes(node.body)
                )
                refusing = isinstance(compare.ops[0], ast.NotIn) and (
                    isinstance(node, ast.If) and _refuses(node.body)
                )
                if allowing or refusing:
                    used.add(compare.comparators[0].id)
        elif isinstance(node, ast.For) and _named(node.iter, names) and _writes(node.body):
            used.add(node.iter.id)
    return used


def _py_email_writes(code: Code) -> list[tuple[Location, bool]]:
    """(location, direct) for each place the code writes an email field: `x.email = value` is
    direct; a field allow-list that names email is not. A collection passed as `exclude` is
    never a write."""
    found, lists = [], {}
    for node in ast.walk(code.node):
        if isinstance(node, ast.Assign | ast.AnnAssign) and _email_list(node.value):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            lists.update({t.id: node.lineno for t in targets if isinstance(t, ast.Name)})
        elif isinstance(node, ast.keyword) and node.arg == "include" and _email_list(node.value):
            found.append((Location(code.rel, node.value.lineno), False))
        elif isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Attribute):
            if node.targets[0].attr in EMAIL_FIELDS and not isinstance(node.value, ast.Constant):
                found.append((Location(code.rel, node.lineno), True))
    for name in sorted(_allow_list_uses(code.node, set(lists)), key=lists.get):
        found.append((Location(code.rel, lists[name]), False))
    return sorted(found, key=lambda item: (not item[1], item[0].line))


def _js_email_writes(code: Code) -> list[tuple[Location, bool]]:
    found = []
    for pair in jsts.walk(code.node, {"pair"}):
        if jsts.node_text(pair.child_by_field_name("key")) != "data":
            continue
        for key, value in jsts.object_pairs(pair.child_by_field_name("value")).items():
            if key in EMAIL_FIELDS and value is not None and value.type != "string":
                found.append((Location(code.rel, jsts.line(code.tree, value)), True))
    for node in jsts.walk(code.node, {"assignment_expression"}):
        left = jsts.node_text(node.child_by_field_name("left"))
        if left.split(".")[-1] in EMAIL_FIELDS:
            found.append((Location(code.rel, jsts.line(code.tree, node)), True))
    return found


@rule(
    "AUTH-EMAIL-CHANGE-UNVERIFIED",
    review="auth",
    severity="medium",
    exploitability="medium",
    owasp="A07",
)
def email_change_unverified(ctx: Context) -> Iterator[Finding]:
    """CONFIRMED needs a direct write of email on a self route (no path parameter, so the caller
    edits their own account). An allow-list naming email, or a route that takes an id and may be
    an admin editing another user, is INFERRED."""
    for flow in flows_of(ctx, "update_self"):
        found = [
            item
            for code in flow.code
            for item in (_py_email_writes(code) if code.python else _js_email_writes(code))
        ]
        if not found:
            continue
        writes = list(dict.fromkeys(loc for loc, _ in found))
        own = not any(PARAM_SEGMENT.fullmatch(s) for s in flow.route.path.split("/") if s)
        guarded = any(
            VERIFY_WORDS.search(name) for code in flow.code for name in _identifiers(code)
        )
        if guarded:
            record_pass(
                ctx,
                9,
                Tag.INFERRED,
                "Changing the email goes through a verification or password step",
                writes[0],
            )
            continue
        yield make_finding(
            "AUTH-EMAIL-CHANGE-UNVERIFIED",
            tag=Tag.CONFIRMED if own and any(direct for _, direct in found) else Tag.INFERRED,
            locations=[*writes, flow.location],
            snippet=snippet(ctx.index.text(writes[0].file), writes[0].line),
            route=f"{flow.route.method} {flow.route.path}",
        )


def _declared_unique(ctx: Context, model) -> bool:
    text = ctx.index.text(model.location.file)
    return bool(UNIQUE_TEXT.search(text))


@rule("AUTH-EMAIL-NOT-UNIQUE", review="auth", severity="medium", exploitability="low", owasp="A07")
def email_not_unique(ctx: Context) -> Iterator[Finding]:
    """A user model is judged only when a register flow sits in an app root it applies to: its
    own root, or any root when the model is shared (see `auth_flows.user_models_in`)."""
    registers = [f.route.file for f in flows_of(ctx, "register")]
    for model in user_models(ctx):
        field = next((f for f in model.fields if f.name in EMAIL_FIELDS), None)
        if field is None or not any(applies(ctx, model.location.file, r) for r in registers):
            continue
        if field.unique or _declared_unique(ctx, model):
            record_pass(
                ctx, 8, Tag.CONFIRMED, f"The email column of {model.name} is unique", field.location
            )
            continue
        yield make_finding(
            "AUTH-EMAIL-NOT-UNIQUE",
            tag=Tag.CONFIRMED,
            locations=[field.location],
            snippet=snippet(ctx.index.text(field.location.file), field.location.line),
            model=model.name,
        )


def _frontend_files(ctx: Context) -> list[str]:
    web_roots = [r.path for r in ctx.detection.app_roots if r.kind == "web"]
    found = []
    for entry in ctx.index.js_files:
        if is_test(entry.rel):
            continue
        home = root_of(ctx.detection.app_roots, entry.rel)
        in_web = home is not None and home.path in web_roots
        if in_web or entry.rel.endswith(UI_SUFFIXES):
            found.append(entry.rel)
    return found


def _definition_name(node) -> str | None:
    current = node.parent
    while current is not None:
        if current.type == "pair":
            return jsts.node_text(current.child_by_field_name("key"))
        if current.type in ("variable_declarator", "function_declaration", "method_definition"):
            return jsts.node_text(current.child_by_field_name("name"))
        if current.type in ("jsx_element", "jsx_self_closing_element", "program"):
            return None
        current = current.parent
    return None


def _references(ctx: Context, files: list[str], path: str) -> list[tuple[str, int, str | None]]:
    found = []
    for rel in files:
        if path.rsplit("/", 1)[-1] not in ctx.index.text(rel):
            continue
        for tree in jsts.parse_file(ctx.index, rel):
            for node in jsts.walk(tree.root, {"string", "template_string"}):
                value = jsts.node_text(node).strip("'\"`").split("?")[0]
                if len(value) > 1 and value.startswith("/") and path.endswith(value):
                    found.append((rel, jsts.line(tree, node), _definition_name(node)))
    return found


def _called(ctx: Context, files: list[str], name: str, home: tuple[str, int]) -> bool:
    pattern = re.compile(rf"(?<![\w$]){re.escape(name)}\s*\(")
    for rel in files:
        text = ctx.index.text(rel)
        for number, line in enumerate(text.splitlines(), start=1):
            if (rel, number) != home and pattern.search(line):
                return True
    return False


@rule("AUTH-SIGNUP-NO-UI", review="auth", severity="medium", exploitability="medium", owasp="A04")
def signup_no_ui(ctx: Context) -> Iterator[Finding]:
    files = _frontend_files(ctx)
    if not files:
        return
    for flow in flows_of(ctx, "register"):
        refs = _references(ctx, [f for f in files if f != flow.route.file], flow.route.path)
        if any(name is None or _called(ctx, files, name, (rel, line)) for rel, line, name in refs):
            record_pass(
                ctx,
                "signup-no-ui",
                Tag.INFERRED,
                "A screen calls the signup endpoint",
                flow.location,
            )
            continue
        if refs:
            rel, line, name = refs[0]
            what = f"The frontend defines {name}() for this path at {rel}:{line}; nothing calls it."
        else:
            what = "No frontend source refers to this path."
        yield make_finding(
            "AUTH-SIGNUP-NO-UI",
            tag=Tag.INFERRED,
            locations=[flow.location, *(Location(r, n) for r, n, _ in refs[:3])],
            snippet=snippet(ctx.index.text(flow.route.file), flow.route.line),
            route=f"{flow.route.method} {flow.route.path}",
            what=what,
        )


@rule("AUTH-NO-MFA", review="auth", severity="low", exploitability="low", owasp="A07")
def no_mfa(ctx: Context) -> Iterator[Finding]:
    # managed_provider reads repository-wide signals (dpr.discovery.detect); scoping it to one
    # app root would need per-root provider detection, which is a larger change than this fix.
    if managed_provider(ctx):
        return
    by_root: dict[str, list[Flow]] = {}
    for flow in flows_of(ctx, "login"):
        home = root_of(ctx.detection.app_roots, flow.route.file)
        by_root.setdefault(home.path if home else "", []).append(flow)
    for root, login_flows in sorted(by_root.items()):
        home = login_flows[0].route.file
        model_fields = [f.name for m in user_models_in(ctx, home) for f in m.fields]
        if declared_for(ctx, home, MFA_PACKAGES):
            record_pass(
                ctx,
                "mfa",
                Tag.INFERRED,
                "A manifest for this app declares an MFA package",
                login_flows[0].location,
            )
            continue
        names = [n for flow in login_flows for code in flow.code for n in _identifiers(code)]
        if any(MFA_WORDS.search(n) for n in [*names, *model_fields]):
            record_pass(
                ctx, "mfa", Tag.INFERRED, "Sign-in checks a second factor", login_flows[0].location
            )
            continue
        yield make_finding(
            "AUTH-NO-MFA",
            tag=Tag.INFERRED,
            locations=[f.location for f in login_flows],
            snippet=snippet(ctx.index.text(login_flows[0].route.file), login_flows[0].route.line),
            app=root or "this repository",
        )
