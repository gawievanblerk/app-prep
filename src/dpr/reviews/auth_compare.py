"""Review 3: request tokens compared with a secret by `==`, `!=` or `in`.

A value read from the request (headers, `META`, cookies, query string, form or body) is
compared with a secret: a settings or environment value whose name says token, secret, key,
password or signature, or a computed digest (`hexdigest()`, `digest()`), directly or through
local names. Such a comparison stops at the first differing character, so its timing leaks how
much of a guess is right; `hmac.compare_digest` does not.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Tag
from dpr.parsing import pyast
from dpr.redact import snippet
from dpr.reviews.app_code import app_py_files
from dpr.rules import Context, make_finding, rule

REQUEST = re.compile(
    r"\b(?:request|req|self\.request)\.(?:headers|META|COOKIES|GET|POST|data|query_params|body)\b"
)
SECRET_NAME = r"\w*(?:TOKEN|SECRET|KEY|PASSWORD|PASSCODE|SIGNATURE|HMAC)\w*"
SECRET = re.compile(
    rf"\bsettings\.{SECRET_NAME}|\b(?:os\.environ|os\.getenv|config|env)\b.*['\"]{SECRET_NAME}['\"]"
    r"|\.(?:hex)?digest\(\)"
)
OPS = (ast.Eq, ast.NotEq, ast.In, ast.NotIn)


def _held(fn: ast.AST, pattern: re.Pattern[str]) -> set[str]:
    """Local names whose value matches the pattern, directly or through other such names."""
    names: set[str] = set()
    assigns = sorted((n for n in ast.walk(fn) if isinstance(n, ast.Assign)), key=lambda n: n.lineno)
    for node in assigns:
        text = ast.unparse(node.value)
        if pattern.search(text) or pyast.names_in(node.value) & names:
            names |= {t.id for t in node.targets if isinstance(t, ast.Name)}
    return names


def _matches(node: ast.AST, pattern: re.Pattern[str], names: set[str]) -> bool:
    return bool(pattern.search(ast.unparse(node)) or pyast.names_in(node) & names)


def compares(fn: ast.AST) -> list[int]:
    """Lines where the function compares a request value with a secret by equality."""
    requested, secrets = _held(fn, REQUEST), _held(fn, SECRET)
    found = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.Compare) or not isinstance(node.ops[0], OPS):
            continue
        sides = [node.left, node.comparators[0]]
        if any(isinstance(s, ast.Constant) for s in sides):
            continue
        for left, right in (sides, sides[::-1]):
            if _matches(left, REQUEST, requested) and _matches(right, SECRET, secrets):
                found.append(node.lineno)
                break
    return sorted(set(found))


@rule("AUTH-TOKEN-COMPARE", review="auth", severity="low", exploitability="low", owasp="A07")
def token_compare(ctx: Context) -> Iterator[Finding]:
    for rel, text, tree in app_py_files(ctx, "request"):
        if "compare_digest" in text and "==" not in text and "!=" not in text:
            continue
        lines = sorted({line for fn in pyast.functions(tree) for line in compares(fn)})
        if lines:
            yield make_finding(
                "AUTH-TOKEN-COMPARE",
                tag=Tag.CONFIRMED,
                locations=[Location(rel, line) for line in lines],
                snippet=snippet(text, lines[0]),
                file=rel,
            )
