"""Review 3: one-time tokens for reset and email verification."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Tag
from dpr.parsing import jsts, pyast
from dpr.redact import snippet
from dpr.reviews.auth_flows import Code, Flow, flows_of, record_pass
from dpr.reviews.leaks_logs import words
from dpr.rules import Context, make_finding, rule

PURPOSE = {
    "reset", "verify", "verification", "confirm", "confirmation", "invite", "invitation",
    "activation", "magic", "recovery",
}  # fmt: skip
HASHED = {"hash", "hashed", "digest", "sha256"}
HASH_CALL = re.compile(r"(?i)hash|digest|sha\d+|hmac")
EXPIRY_WORDS = re.compile(
    r"(?i)expir|sent_at|sentAt|created_at|createdAt|issued_at|max_age|lifetime|ttl"
)
TIME_CALLS = re.compile(
    r"datetime\.now|utcnow|timezone\.now|time\.time|Date\.now|new Date|timedelta"
)
USED_WORDS = re.compile(r"(?i)used_?at|consumed|redeemed")


def token_column(name: str) -> bool:
    parts = set(words(name))
    return "token" in parts and bool(parts & PURPOSE) and not parts & HASHED


def _py_compares(code: Code) -> Iterator[tuple[str, int, ast.AST]]:
    """(column, line, enclosing call or compare) where a token column is matched to a raw value."""
    for node in ast.walk(code.node):
        if isinstance(node, ast.Compare) and isinstance(node.left, ast.Attribute):
            if token_column(node.left.attr) and not HASH_CALL.search(
                ast.unparse(node.comparators[0])
            ):
                yield node.left.attr, node.lineno, node
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                if (
                    keyword.arg
                    and token_column(keyword.arg)
                    and not HASH_CALL.search(ast.unparse(keyword.value))
                ):
                    if isinstance(keyword.value, ast.Name | ast.Attribute | ast.Subscript):
                        yield keyword.arg, node.lineno, node


def _js_where_pairs(code: Code) -> Iterator[tuple[str, str, int, object]]:
    """(key, value text, line, where object) for pairs inside `where: { ... }` objects."""
    for pair in jsts.walk(code.node, {"pair"}):
        if jsts.node_text(pair.child_by_field_name("key")) != "where":
            continue
        where = pair.child_by_field_name("value")
        for key, value in jsts.object_pairs(where).items():
            yield key, jsts.node_text(value), jsts.line(code.tree, pair), where


def plaintext_matches(flow: Flow) -> list[tuple[str, Location]]:
    found = []
    for code in flow.code:
        if code.python:
            found += [(col, Location(code.rel, line)) for col, line, _ in _py_compares(code)]
        else:
            for key, value, line, _ in _js_where_pairs(code):
                if token_column(key) and not HASH_CALL.search(value):
                    found.append((key, Location(code.rel, line)))
    return found


def _label(flow: Flow) -> str:
    return "Reset" if flow.kind == "reset" else "Verification"


@rule("AUTH-TOKEN-PLAINTEXT", review="auth", severity="low", exploitability="low", owasp="A02")
def token_plaintext(ctx: Context) -> Iterator[Finding]:
    for flow in flows_of(ctx, "reset", "verify"):
        matches = plaintext_matches(flow)
        if not matches:
            continue
        locations = sorted({loc for _, loc in matches}, key=lambda loc: (loc.file, loc.line))
        yield make_finding(
            "AUTH-TOKEN-PLAINTEXT",
            tag=Tag.CONFIRMED,
            locations=[*locations, flow.location],
            snippet=snippet(ctx.index.text(locations[0].file), locations[0].line),
            kind=_label(flow),
            column=", ".join(sorted({col for col, _ in matches})),
            route=f"{flow.route.method} {flow.route.path}",
        )


def expiry_checks(flow: Flow) -> list[Location]:
    found = []
    for code in flow.code:
        if code.python:
            for node in ast.walk(code.node):
                if isinstance(node, ast.Compare):
                    text = ast.unparse(node)
                    if (
                        EXPIRY_WORDS.search(text)
                        or TIME_CALLS.search(text)
                        or "total_seconds" in text
                    ):
                        found.append(Location(code.rel, node.lineno))
        else:
            for node in jsts.walk(code.node, {"binary_expression", "pair"}):
                text = jsts.node_text(node)
                comparison = node.type == "binary_expression" and re.search(r"[<>]", text)
                prisma_gt = node.type == "pair" and re.match(
                    r"\w*(?:expir|sent|created)\w*\s*:\s*\{\s*gte?:", text, re.I
                )
                if (
                    comparison and (EXPIRY_WORDS.search(text) or TIME_CALLS.search(text))
                ) or prisma_gt:
                    found.append(Location(code.rel, jsts.line(code.tree, node)))
    return found


def _no_expiry(ctx: Context, kind: str, rule_id: str, case: int) -> Iterator[Finding]:
    for flow in flows_of(ctx, kind):
        checks = expiry_checks(flow)
        if checks:
            record_pass(
                ctx,
                case,
                Tag.CONFIRMED,
                f"The {_label(flow).lower()} flow compares a timestamp before accepting the token",
                checks[0],
            )
            continue
        yield make_finding(
            rule_id,
            tag=Tag.INFERRED,
            locations=[flow.location, *(Location(c.rel, c.line) for c in flow.code[1:3])],
            snippet=snippet(ctx.index.text(flow.route.file), flow.route.line),
            route=f"{flow.route.method} {flow.route.path}",
        )


@rule("AUTH-VERIFY-NO-EXPIRY", review="auth", severity="low", exploitability="low", owasp="A07")
def verify_no_expiry(ctx: Context) -> Iterator[Finding]:
    yield from _no_expiry(ctx, "verify", "AUTH-VERIFY-NO-EXPIRY", 3)


@rule(
    "AUTH-RESET-NO-EXPIRY", review="auth", severity="medium", exploitability="medium", owasp="A07"
)
def reset_no_expiry(ctx: Context) -> Iterator[Finding]:
    yield from _no_expiry(ctx, "reset", "AUTH-RESET-NO-EXPIRY", 6)


def _email_keyed(flow: Flow) -> list[Location]:
    """Lookups or writes keyed by email alone inside a token reset flow."""
    found = []
    for code in flow.code:
        if code.python:
            simple = (ast.Assign, ast.AnnAssign, ast.Expr, ast.Return)
            for stmt in [n for n in ast.walk(code.node) if isinstance(n, simple)]:
                text = ast.unparse(stmt)
                if not re.search(r"\.email\s*==|\bemail\s*=(?!=)", text):
                    continue
                if not re.search(r"select|filter|where|get\(|update", text):
                    continue
                statement = Code(code.rel, stmt, code.tree)
                if not any(token_column(col) for col, _, _ in _py_compares(statement)):
                    found.append(Location(code.rel, stmt.lineno))
        else:
            for key, _value, line, where in _js_where_pairs(code):
                keys = jsts.object_pairs(where)
                if key == "email" and not any(token_column(k) for k in keys):
                    found.append(Location(code.rel, line))
    return found


@rule("AUTH-RESET-TRUSTS-EMAIL", review="auth", severity="high", exploitability="high", owasp="A07")
def reset_trusts_email(ctx: Context) -> Iterator[Finding]:
    for flow in flows_of(ctx, "reset"):
        tokens = plaintext_matches(flow) or [(None, loc) for loc in _hashed_lookups(flow)]
        if not tokens:
            continue
        keyed = _email_keyed(flow)
        if not keyed:
            record_pass(
                ctx,
                7,
                Tag.CONFIRMED,
                "The reset flow finds the account by its token, not by an email field",
                tokens[0][1],
            )
            continue
        yield make_finding(
            "AUTH-RESET-TRUSTS-EMAIL",
            tag=Tag.INFERRED,
            locations=[*keyed, tokens[0][1], flow.location],
            snippet=snippet(ctx.index.text(keyed[0].file), keyed[0].line),
            route=f"{flow.route.method} {flow.route.path}",
        )


def _hashed_lookups(flow: Flow) -> list[Location]:
    found = []
    for code in flow.code:
        text_lines = code.text().splitlines()
        for offset, line in enumerate(text_lines):
            if re.search(r"(?i)token\w*_?hash\w*\s*==|token_?hash\w*\s*:", line):
                found.append(Location(code.rel, code.line + offset))
    return found


def _consumed(flow: Flow) -> list[Location]:
    found = []
    for code in flow.code:
        if code.python:
            for node in ast.walk(code.node):
                if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Attribute):
                    attr = node.targets[0].attr
                    cleared = pyast.constant(node.value, "x") in (None, "")
                    if (cleared and "token" in words(attr)) or USED_WORDS.search(attr):
                        found.append(Location(code.rel, node.lineno))
                if isinstance(node, ast.Call) and (pyast.dotted(node.func) or "").endswith(
                    "delete"
                ):
                    found.append(Location(code.rel, node.lineno))
        else:
            for pair in jsts.walk(code.node, {"pair"}):
                key = jsts.node_text(pair.child_by_field_name("key"))
                value = jsts.node_text(pair.child_by_field_name("value"))
                if (
                    "token" in words(key) and value in ("null", "undefined", '""', "''")
                ) or USED_WORDS.search(key):
                    found.append(Location(code.rel, jsts.line(code.tree, pair)))
            for call in jsts.walk(code.node, {"call_expression"}):
                if jsts.callee(call).endswith((".delete", ".deleteMany", ".destroy")):
                    found.append(Location(code.rel, jsts.line(code.tree, call)))
    return found


@rule("AUTH-VERIFY-REUSABLE", review="auth", severity="low", exploitability="low", owasp="A07")
def verify_reusable(ctx: Context) -> Iterator[Finding]:
    for flow in flows_of(ctx, "verify"):
        consumed = _consumed(flow)
        if consumed:
            record_pass(
                ctx,
                3,
                Tag.CONFIRMED,
                "The verification flow clears or consumes the token after use",
                consumed[0],
            )
            continue
        yield make_finding(
            "AUTH-VERIFY-REUSABLE",
            tag=Tag.INFERRED,
            locations=[flow.location],
            snippet=snippet(ctx.index.text(flow.route.file), flow.route.line),
            route=f"{flow.route.method} {flow.route.path}",
        )
