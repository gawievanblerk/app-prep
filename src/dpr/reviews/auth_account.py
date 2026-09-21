"""Review 3: email change, unique emails, signup no screen uses, and second factors."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.discovery.approots import root_of
from dpr.discovery.packages import manifest_packages_by_file
from dpr.model import Finding, Location, Tag
from dpr.parsing import jsts, pyast
from dpr.redact import snippet
from dpr.reviews.auth_flows import Code, Flow, flows_of, managed_provider, record_pass, user_models
from dpr.reviews.deploy_env import applies
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


def _py_email_writes(code: Code) -> list[Location]:
    found = []
    for node in ast.walk(code.node):
        if isinstance(node, ast.Set | ast.List | ast.Tuple) and len(node.elts) >= 2:
            values = [pyast.constant(e, None) for e in node.elts]
            if all(isinstance(v, str) for v in values) and any(v in EMAIL_FIELDS for v in values):
                found.append(Location(code.rel, node.lineno))
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Attribute):
            if node.targets[0].attr in EMAIL_FIELDS and not isinstance(node.value, ast.Constant):
                found.append(Location(code.rel, node.lineno))
    return found


def _js_email_writes(code: Code) -> list[Location]:
    found = []
    for pair in jsts.walk(code.node, {"pair"}):
        if jsts.node_text(pair.child_by_field_name("key")) != "data":
            continue
        for key, value in jsts.object_pairs(pair.child_by_field_name("value")).items():
            if key in EMAIL_FIELDS and value is not None and value.type != "string":
                found.append(Location(code.rel, jsts.line(code.tree, value)))
    for node in jsts.walk(code.node, {"assignment_expression"}):
        left = jsts.node_text(node.child_by_field_name("left"))
        if left.split(".")[-1] in EMAIL_FIELDS:
            found.append(Location(code.rel, jsts.line(code.tree, node)))
    return found


@rule(
    "AUTH-EMAIL-CHANGE-UNVERIFIED",
    review="auth",
    severity="medium",
    exploitability="medium",
    owasp="A07",
)
def email_change_unverified(ctx: Context) -> Iterator[Finding]:
    for flow in flows_of(ctx, "update_self"):
        writes = [
            loc
            for code in flow.code
            for loc in (_py_email_writes(code) if code.python else _js_email_writes(code))
        ]
        if not writes:
            continue
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
            tag=Tag.CONFIRMED,
            locations=[*writes, flow.location],
            snippet=snippet(ctx.index.text(writes[0].file), writes[0].line),
            route=f"{flow.route.method} {flow.route.path}",
        )


def _declared_unique(ctx: Context, model) -> bool:
    text = ctx.index.text(model.location.file)
    return bool(UNIQUE_TEXT.search(text))


@rule("AUTH-EMAIL-NOT-UNIQUE", review="auth", severity="medium", exploitability="low", owasp="A07")
def email_not_unique(ctx: Context) -> Iterator[Finding]:
    if not flows_of(ctx, "register"):
        return
    for model in user_models(ctx):
        field = next((f for f in model.fields if f.name in EMAIL_FIELDS), None)
        if field is None:
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


def _mfa_package_declared(ctx: Context, rel: str) -> bool:
    """True when a manifest that applies to `rel`'s app root declares an MFA package.

    A manifest applies when it sits inside the same app root as `rel`, or is shared (its own
    root is unset, the repository root, or a library root); see `deploy_env.applies`."""
    key = ("manifest-packages-by-file", "")
    if key not in ctx.index.cache:
        ctx.index.cache[key] = manifest_packages_by_file(ctx.index)
    by_file = ctx.index.cache[key]
    return any(
        MFA_PACKAGES & packages
        for manifest_rel, packages in by_file.items()
        if applies(ctx, manifest_rel, rel)
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
    model_fields = [f.name for m in user_models(ctx) for f in m.fields]
    for root, login_flows in sorted(by_root.items()):
        if _mfa_package_declared(ctx, login_flows[0].route.file):
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
