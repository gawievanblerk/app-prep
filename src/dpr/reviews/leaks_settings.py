"""Review 6, leak hunt: secrets that fall back to committed values, and literal credentials on
outbound HTTP calls. Findings name the setting and the line, never the value."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from dataclasses import dataclass

from dpr.facts import fact
from dpr.model import Finding, Location, Tag
from dpr.parsing import pyast
from dpr.parsing.pyenv import env_read, module_assignments
from dpr.reviews.settings_files import (
    production_file,
    secret_name,
    settings_module,
    signing_name,
)
from dpr.rules import Context, make_finding, rule

# Values that stand in for a secret rather than being one. Empty and None-like values are not
# fallbacks at all; the rest are reported as low.
EMPTY = re.compile(r"(?i)^\s*(?:none|null)?\s*$")
PLACEHOLDER = re.compile(
    r"(?i)^(?:dummy[\w-]{0,8}|test[\w-]{0,8}|x+|\*+|\.{3}|changeme|change[_-]me|placeholder"
    r"|example|redacted|secret|password|pass|your[\w-]{0,24}|<.*>|\$\{.*\}|\{\{.*\}\}|%\(.*\)s)$"
)
HASHIDS = r"(?:hashids\.)?Hashids"
BASIC_AUTH = r"(?:[\w.]+\.)?(?:HTTPBasicAuth|HTTPDigestAuth|HTTPProxyAuth|BasicAuth|DigestAuth)"
AUTH_HEADER = re.compile(r"(?i)^(?:basic|bearer|token|apikey|key)\s+\S{4,}")
# Django signing calls whose `salt=` only namespaces a signature made with SECRET_KEY.
SIGNING_CALL = re.compile(
    r"(?:^|\.)(?:Signer|TimestampSigner|dumps|loads|get_signed_cookie|set_signed_cookie"
    r"|get_cookie_signer)$"
)


@dataclass(frozen=True)
class Fallback:
    name: str
    line: int
    placeholder: bool
    signing: bool


def _kind(value: object) -> str | None:
    """ "secret", "placeholder" or None when the value is not a usable string fallback."""
    if not isinstance(value, str) or EMPTY.match(value) or "://" in value:
        return None
    return "placeholder" if PLACEHOLDER.match(value.strip()) else "secret"


def _targets(tree: ast.Module) -> dict[int, str]:
    """The assigned name for every node inside an assignment's value, by node id."""
    found: dict[int, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            found.update({id(sub): node.targets[0].id for sub in ast.walk(node.value)})
    return found


def _env_fallbacks(tree: ast.Module) -> Iterator[tuple[str, str, ast.AST, object]]:
    """(env name, assigned name, node, fallback value) for env reads with a literal default,
    including `os.environ.get("X") or "value"`."""
    targets = _targets(tree)
    for node in ast.walk(tree):
        read = env_read(node)
        if read is not None and read.default is not None:
            yield read.name, targets.get(id(node), ""), node, pyast.constant(read.default)
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
            reads = [env_read(v) for v in node.values]
            first = next((r for r in reads if r is not None), None)
            last = pyast.constant(node.values[-1])
            if first is not None and reads[-1] is None:
                yield first.name, targets.get(id(node), ""), node, last


def _salts(tree: ast.Module) -> Iterator[tuple[int, object]]:
    for call in pyast.calls(tree, HASHIDS):
        salt = pyast.kwarg(call, "salt") or (call.args[0] if call.args else None)
        yield call.lineno, pyast.constant(salt)


def _salt_uses(ctx: Context) -> dict[str, bool]:
    """Salt-named settings read in code: True while every read is the `salt=` of a Django
    signing call (`Signer(salt=settings.X)`, `signing.dumps(value, salt=X)`)."""
    uses: dict[str, bool] = {}
    for entry in ctx.index.py_files:
        if "SALT" not in ctx.index.text(entry.rel):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        signing = set()
        for call in [n for n in ast.walk(tree) if isinstance(n, ast.Call)] if tree else []:
            salt = pyast.kwarg(call, "salt")
            if salt is not None and SIGNING_CALL.search(pyast.dotted(call.func) or ""):
                signing.add(id(salt))
        for node in ast.walk(tree) if tree else []:
            name = node.attr if isinstance(node, ast.Attribute) else getattr(node, "id", None)
            if isinstance(node, ast.Name | ast.Attribute) and name and "SALT" in name:
                if isinstance(node.ctx, ast.Load):
                    uses[name] = uses.get(name, True) and id(node) in signing
    return uses


def signing_salts(ctx: Context) -> set[str]:
    return {name for name, only in fact(ctx, "salt_uses", _salt_uses).items() if only}


def file_fallbacks(ctx: Context, rel: str) -> list[Fallback]:
    text = ctx.index.text(rel)
    tree = pyast.parse_file(ctx.index, rel)
    if tree is None:
        return []
    found: dict[tuple[str, int], Fallback] = {}
    salts = signing_salts(ctx)

    def add(name: str, line: int, value: object) -> None:
        kind = _kind(value)
        if name in salts:
            return  # a Django signing salt namespaces signatures; SECRET_KEY is the secret
        if kind is not None:
            fallback = Fallback(name, line, kind == "placeholder", signing_name(name))
            found.setdefault((name, line), fallback)

    for env, target, node, value in _env_fallbacks(tree):
        if target in salts:
            continue
        name = env if secret_name(env) else target if secret_name(target) else ""
        if name:
            add(target if signing_name(target) else name, node.lineno, value)
    for line, value in _salts(tree):
        add("Hashids salt", line, value)
    if settings_module(rel, text):
        for name, value, line in module_assignments(tree):
            if secret_name(name) and isinstance(value, ast.Constant):
                add(name, line, value.value)
    return sorted(found.values(), key=lambda f: (not f.signing, f.line))


def _all_fallbacks(ctx: Context) -> dict[str, list[Fallback]]:
    found = {}
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if not re.search(r"(?i)environ|getenv|config\(|env\(|env\.|hashids|settings", text):
            continue
        if not production_file(ctx, entry.rel):
            continue
        fallbacks = file_fallbacks(ctx, entry.rel)
        if fallbacks:
            found[entry.rel] = fallbacks
    return found


def secret_fallbacks(ctx: Context) -> dict[str, list[Fallback]]:
    """Committed secret fallbacks by file. Shared with the baseline review (Pickle sessions)."""
    return fact(ctx, "secret_fallbacks", _all_fallbacks)


def signing_key_fallbacks(ctx: Context) -> list[Location]:
    return [
        Location(rel, f.line)
        for rel, items in secret_fallbacks(ctx).items()
        for f in items
        if f.signing and not f.placeholder
    ]


@rule(
    "LEAK-SECRET-ENV-DEFAULT", review="leaks", severity="high", exploitability="medium", owasp="A07"
)
def secret_env_default(ctx: Context) -> Iterator[Finding]:
    for rel, items in sorted(secret_fallbacks(ctx).items()):
        real = [f for f in items if not f.placeholder]
        severity = "critical" if any(f.signing for f in real) else None if real else "low"
        names = ", ".join(dict.fromkeys(f.name for f in items))
        stand_ins = [f.name for f in items if f.placeholder]
        extra = (
            f" The value for {', '.join(dict.fromkeys(stand_ins))} looks like a placeholder, "
            "which a deployment that misses the variable still accepts."
            if stand_ins
            else ""
        )
        yield make_finding(
            "LEAK-SECRET-ENV-DEFAULT",
            tag=Tag.CONFIRMED,
            locations=[Location(rel, f.line) for f in items][:10],
            severity=severity,
            file=rel,
            names=names,
            fall="falls" if len(names.split(", ")) == 1 else "fall",
            extra=extra,
        )


def _constant_text(node: ast.AST | None, consts: dict[str, ast.expr]) -> object:
    if isinstance(node, ast.Name) and node.id in consts:
        node = consts[node.id]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _constant_text(node.left, consts), _constant_text(node.right, consts)
        return left + right if isinstance(left, str) and isinstance(right, str) else None
    return pyast.constant(node, None)


def _auth_hits(tree: ast.Module) -> Iterator[tuple[int, str]]:
    consts = pyast.assignments(tree.body)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            pair = pyast.kwarg(node, "auth")
            if isinstance(pair, ast.Tuple | ast.List) and len(pair.elts) == 2:
                if _kind(_constant_text(pair.elts[1], consts)) == "secret":
                    yield node.lineno, "a user name and password passed as auth="
            name = pyast.dotted(node.func) or ""
            if re.fullmatch(BASIC_AUTH, name):
                secret = pyast.kwarg(node, "password") or (
                    node.args[1] if len(node.args) > 1 else None
                )
                if _kind(_constant_text(secret, consts)) == "secret":
                    yield node.lineno, f"a password passed to {name.split('.')[-1]}"
        pairs: list[tuple[ast.AST | None, ast.AST | None]] = []
        if isinstance(node, ast.Dict):
            pairs = list(zip(node.keys, node.values, strict=True))
        elif isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Subscript):
            pairs = [(node.targets[0].slice, node.value)]
        for key, value in pairs:
            header = pyast.constant(key, None)
            if not isinstance(header, str) or header.lower() != "authorization":
                continue
            literal = _constant_text(value, consts)
            if isinstance(literal, str) and AUTH_HEADER.match(literal):
                token = literal.split(None, 1)[1]
                if _kind(token) == "secret":
                    yield (value or node).lineno, "an Authorization header written as a literal"


@rule("LEAK-LITERAL-HTTP-AUTH", review="leaks", severity="high", exploitability="high", owasp="A07")
def literal_http_auth(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if not re.search(r"auth=|Auth\(|[Aa]uthorization", text):
            continue
        if not production_file(ctx, entry.rel):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        hits = sorted(set(_auth_hits(tree))) if tree else []
        if hits:
            yield make_finding(
                "LEAK-LITERAL-HTTP-AUTH",
                tag=Tag.CONFIRMED,
                locations=[Location(entry.rel, line) for line, _ in hits][:10],
                file=entry.rel,
                kinds=", ".join(dict.fromkeys(kind for _, kind in hits)),
            )
