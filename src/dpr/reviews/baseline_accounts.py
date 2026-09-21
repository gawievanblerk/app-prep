"""Review 4, baseline: committed account passwords, seeding on start, password length, CSRF."""

from __future__ import annotations

import ast
import hashlib
import json
import re
from collections.abc import Iterator
from pathlib import PurePosixPath

from dpr.model import Finding, Location, Tag
from dpr.parsing import jsts, pyast, pyvalues
from dpr.redact import redact, snippet
from dpr.reviews.deploy_env import non_production, secret_reference, start_stage
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule
from dpr.walk import line_of

PY_HASH = re.compile(
    r"(?:[\w()]+\.)*(get_password_hash|hash_password|make_password|generate_password_hash"
    r"|hashpw|hash)"
)
HASHER_OWNER = re.compile(r"(?i)pwd|password|context|bcrypt|argon|hasher|crypt")
JS_HASH = re.compile(r"(?:\w+\.)*(hash|hashSync|hashPassword)")
START_FILES = (
    "startup.sh",
    "start.sh",
    "entrypoint.sh",
    "docker-entrypoint.sh",
    "run.sh",
    "boot.sh",
    "prestart.sh",
    "Procfile",
    "Dockerfile",
    "render.yaml",
    "fly.toml",
    "railway.json",
    "railway.toml",
    "app.yaml",
    "package.json",
    "docker-compose.yml",
    "docker-compose.yaml",
)
SEED_COMMAND = re.compile(
    r"(?i)(?:^|[\s/.:_-])seed(?:s|_\w+|\.py|\.js|\.ts)?(?=$|[\s.:_)\"'-])|\bloaddata\b"
)
START_LINE = re.compile(
    r"(?i)^\s*(?:-\s*)?(?:CMD|ENTRYPOINT|startCommand|releaseCommand|release_command|command|cmd"
    r"|\"(?:start|prestart|poststart|predeploy|postdeploy)\")\b"
)
TOKEN = re.compile(r"[^\s\"'`,;()\[\]{}<>]+")
SAMESITE_NONE = re.compile(r"""(?i)\b\w*same_?site\w*["']?\s*[:=]\s*["']none["']""")
CSRF_PACKAGES = {
    "fastapi-csrf-protect",
    "starlette-csrf",
    "csurf",
    "csrf-csrf",
    "lusca",
    "flask-wtf",
    "@edge-csrf/nextjs",
}
CONFIG_SUFFIXES = (".tf", ".yaml", ".yml", ".json", ".toml", ".py", ".ts", ".js", ".mjs", ".cjs")


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _py_hash_sites(tree: ast.Module) -> Iterator[tuple[ast.Call, pyvalues.Literal]]:
    for call in pyast.calls(tree, PY_HASH):
        name = pyast.dotted(call.func) or ""
        if name.split(".")[-1] == "hash" and not HASHER_OWNER.search(name):
            continue
        literal = pyvalues.resolve(tree, call.args[0] if call.args else None, call.lineno)
        if literal is not None:
            yield call, literal


def _js_hash_sites(ctx: Context, rel: str) -> Iterator[tuple[int, pyvalues.Literal]]:
    for tree in jsts.parse_file(ctx.index, rel):
        for call in jsts.calls(tree, JS_HASH):
            name = jsts.callee(call)
            if name.split(".")[-1] != "hashPassword" and not HASHER_OWNER.search(name):
                continue
            args = jsts.arguments(call)
            value = jsts.string_value(args[0]) if args else None
            if value is None and args and jsts.unwrap(args[0]).type == "identifier":
                resolved = jsts.resolve_identifier(jsts.unwrap(args[0]))
                value = jsts.string_value(resolved) if resolved is not None else None
            if value:
                yield jsts.line(tree, call), pyvalues.Literal(value)


def literal_password_sites(ctx: Context) -> dict[str, list[tuple[int, pyvalues.Literal]]]:
    """Files whose password hashing calls receive text written in the repository."""
    if "literal_password_sites" in ctx.facts:
        return ctx.facts["literal_password_sites"]
    sites: dict[str, list[tuple[int, pyvalues.Literal]]] = {}
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel) or not re.search(r"hash|password", text):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for call, literal in _py_hash_sites(tree) if tree else []:
            sites.setdefault(entry.rel, []).append((call.lineno, literal))
    for entry in ctx.index.js_files:
        if is_test(entry.rel) or "hash" not in ctx.index.text(entry.rel).lower():
            continue
        for line, literal in _js_hash_sites(ctx, entry.rel):
            sites.setdefault(entry.rel, []).append((line, literal))
    ctx.facts["literal_password_sites"] = sites
    return sites


def _copies(ctx: Context, owner: str, literals: list[pyvalues.Literal]) -> list[Location]:
    digests = {_digest(lit.value) for lit in literals}
    lengths = {len(lit.value) for lit in literals}
    found = []
    for entry in ctx.index.files:
        if entry.rel == owner:
            continue
        text = ctx.index.text(entry.rel)
        for match in TOKEN.finditer(text):
            token = match.group(0)
            if len(token) in lengths and _digest(token) in digests:
                found.append(Location(entry.rel, line_of(text, match.start())))
    return found


def _char_column(source_line: str, byte_column: int) -> int:
    return len(source_line.encode("utf-8")[:byte_column].decode("utf-8", errors="ignore"))


def _literal_spans(text: str, line: int, values: set[str]) -> list[tuple[int, int]]:
    """Character ranges on `line` covered by Python string literals whose value is one of
    `values`, however the literal is spelled (adjacent parts, escapes, triple quotes)."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    lines = text.split("\n")
    spans = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and node.value in values):
            continue
        end_line = node.end_lineno or node.lineno
        if not node.lineno <= line <= end_line or node.end_col_offset is None:
            continue
        source = lines[line - 1]
        start = _char_column(source, node.col_offset) if node.lineno == line else 0
        end = _char_column(source, node.end_col_offset) if end_line == line else len(source)
        spans.append((start, end))
    return spans


def _masked(text: str, line: int, literals: list[pyvalues.Literal]) -> str:
    """The snippet of `line` with every literal masked on the whole line before it is cut.

    Python literals are masked by their source range, so a value spelled differently in the
    source (adjacent parts, escaped quotes, a triple-quoted block) never survives; other files
    fall back to the value's text forms."""
    lines = text.split("\n")
    full = lines[line - 1].removesuffix("\r") if 0 < line <= len(lines) else ""
    values = {lit.value for lit in literals}
    for start, end in sorted(_literal_spans(text, line, values), reverse=True):
        full = full[:start] + "<redacted:password>" + full[end:]
    forms = {f for v in values for f in (v, repr(v)[1:-1], json.dumps(v)[1:-1])}
    forms |= {part for form in forms for part in form.split("\n") if len(part) >= 4}
    for form in sorted(forms, key=len, reverse=True):
        full = full.replace(form, "<redacted:password>")
    value = snippet(full, 1)
    if len(value) < len(redact(full)):
        for form in forms:
            for size in range(len(form) - 1, 0, -1):
                if value.endswith(form[:size]):
                    return value[: len(value) - size] + "<redacted:password>"
    return value


def _seed_target(ctx: Context, start: str, line: str) -> list[str]:
    module = re.search(r"-m\s+([\w.]*seed\w*)", line)
    script = re.search(r"([\w./-]*seed\w*\.(?:py|js|ts|mjs))", line)
    suffix = (
        module.group(1).replace(".", "/") + ".py" if module else (script.group(1) if script else "")
    )
    if not suffix:
        return []
    matches = [f.rel for f in ctx.index.files if f.rel.endswith(suffix.lstrip("./"))]
    folder = str(PurePosixPath(start).parent)
    local = [m for m in matches if folder == "." or m.startswith(folder + "/")]
    return local or matches


@rule("BASE-SEED-ON-START", review="baseline", severity="high", exploitability="high", owasp="A05")
def seed_on_start(ctx: Context) -> Iterator[Finding]:
    sites = literal_password_sites(ctx)
    for entry in ctx.index.named(*START_FILES):
        text = ctx.index.text(entry.rel)
        shell = entry.name.endswith(".sh") or entry.name == "Procfile"
        for number, raw in enumerate(text.splitlines(), start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith(("#", "echo ", "//")):
                continue
            if not shell and not START_LINE.search(raw):
                continue
            if not SEED_COMMAND.search(stripped):
                continue
            yield _seed_finding(ctx, entry.rel, number, text, sites)


def _seed_finding(ctx: Context, rel: str, number: int, text: str, sites: dict) -> Finding:
    targets = _seed_target(ctx, rel, text.splitlines()[number - 1].strip())
    direct = [t for t in targets if any(not lit.env_fallback for _, lit in sites.get(t, []))]
    fallback = [lit for t in targets for _, lit in sites.get(t, []) if lit.env_fallback]
    stage = start_stage(ctx, rel, number)
    severity, detail, proof, locations = "high", "", None, [Location(rel, number)]
    if direct:
        severity = "high" if non_production(stage) else "critical"
        detail = f" The seed file {direct[0]} hashes passwords written in the repository."
    elif fallback and fallback[0].env_name:
        secret = secret_reference(ctx, fallback[0].env_name)
        if secret is not None:
            severity = "medium"
            locations.append(secret)
            detail = (
                f" The seed falls back to a committed password only when "
                f"{fallback[0].env_name} is unset, and {secret.file} supplies that variable "
                "from a secret store."
            )
            proof = f"Check that the secret reference for {fallback[0].env_name} resolves."
    if stage:
        detail += f" This start command runs with the {stage} environment setting."
    return make_finding(
        "BASE-SEED-ON-START",
        tag=Tag.INFERRED,
        locations=locations,
        severity=severity,
        snippet=snippet(text, number),
        proof_needed=proof,
        refs=("BASE-LITERAL-PASSWORD-HASH",) if direct else (),
        start=rel,
        extra=detail,
    )


def _py_short_minimums(tree: ast.Module) -> Iterator[tuple[int, int]]:
    for fn in pyast.functions(tree):
        decorators = " ".join(ast.unparse(d) for d in fn.decorator_list)
        if "password" not in (fn.name + decorators).lower():
            continue
        for node in ast.walk(fn):
            if not (isinstance(node, ast.Compare) and len(node.ops) == 1):
                continue
            left, right = node.left, node.comparators[0]
            if not (isinstance(left, ast.Call) and pyast.dotted(left.func) == "len"):
                continue
            limit = pyast.constant(right, None)
            if not isinstance(limit, int):
                continue
            minimum = limit if isinstance(node.ops[0], ast.Lt) else limit + 1
            if isinstance(node.ops[0], ast.Lt | ast.LtE) and 2 <= minimum < 8:
                yield node.lineno, minimum
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if "password" in node.target.id.lower():
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Call):
                        value = pyast.constant(pyast.kwarg(sub, "min_length"), None)
                        if isinstance(value, int) and 2 <= value < 8:
                            yield node.lineno, value
        if isinstance(node, ast.Dict):
            text = ast.unparse(node)
            match = re.search(r"MinimumLengthValidator.*'min_length':\s*(\d+)", text)
            if match and 2 <= int(match.group(1)) < 8:
                yield node.lineno, int(match.group(1))


@rule(
    "BASE-SHORT-PASSWORD-MIN", review="baseline", severity="low", exploitability="low", owasp="A07"
)
def short_password_minimum(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel) or "password" not in text.lower():
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for line, minimum in sorted(set(_py_short_minimums(tree))) if tree else []:
            yield make_finding(
                "BASE-SHORT-PASSWORD-MIN",
                tag=Tag.CONFIRMED,
                locations=[Location(entry.rel, line)],
                snippet=snippet(text, line),
                minimum=minimum,
            )
    for entry in ctx.index.js_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel):
            continue
        for match in re.finditer(r"(?i)password\w*['\"]?\s*:\s*[\w.()]*?\.min\(\s*(\d+)", text):
            if 2 <= int(match.group(1)) < 8:
                line = line_of(text, match.start())
                yield make_finding(
                    "BASE-SHORT-PASSWORD-MIN",
                    tag=Tag.CONFIRMED,
                    locations=[Location(entry.rel, line)],
                    snippet=snippet(text, line),
                    minimum=int(match.group(1)),
                )


def _has_csrf_defence(ctx: Context) -> bool:
    if CSRF_PACKAGES & ctx.detection.packages or "django" in ctx.detection.frameworks:
        return True
    return any(
        "csrf" in ctx.index.text(f.rel).lower()
        for f in [*ctx.index.js_files, *ctx.index.py_files]
        if not is_test(f.rel)
    )


@rule(
    "BASE-SAMESITE-NONE-NO-CSRF",
    review="baseline",
    severity="low",
    exploitability="medium",
    owasp="A01",
)
def samesite_none_without_csrf(ctx: Context) -> Iterator[Finding]:
    found = []
    for entry in ctx.index.files:
        if not entry.rel.endswith(CONFIG_SUFFIXES) or is_test(entry.rel):
            continue
        text = ctx.index.text(entry.rel)
        found += [
            Location(entry.rel, line_of(text, m.start())) for m in SAMESITE_NONE.finditer(text)
        ]
    if found and not _has_csrf_defence(ctx):
        yield make_finding(
            "BASE-SAMESITE-NONE-NO-CSRF",
            tag=Tag.INFERRED,
            locations=found[:5],
            snippet=snippet(ctx.index.text(found[0].file), found[0].line),
        )
