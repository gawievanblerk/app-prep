"""Review 4, baseline: committed account passwords, seeding on start, password length, CSRF."""

from __future__ import annotations

import ast
import posixpath
import re
from collections.abc import Iterator
from pathlib import PurePosixPath

from dpr.discovery.approots import root_of, same_root
from dpr.model import Finding, Location, Tag
from dpr.parsing import jsts, pyast, pyvalues
from dpr.redact import snippet
from dpr.reviews.deploy_env import (
    compose_build_dir,
    non_production,
    secret_reference,
    service_root_dir,
    start_stage,
)
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
CD_PREFIX = re.compile(r"""(?:^|[\s;&("'])cd\s+["']?([^\s;&|"')]+)["']?\s*(?:&&|;)""")
SEED_COMMAND = re.compile(
    r"(?i)(?:^|[\s/.:_-])seed(?:s|_\w+|\.py|\.js|\.ts)?(?=$|[\s.:_)\"'-])|\bloaddata\b"
)
START_LINE = re.compile(
    r"(?i)^\s*(?:-\s*)?(?:CMD|ENTRYPOINT|startCommand|releaseCommand|release_command|command|cmd"
    r"|\"(?:start|prestart|poststart|predeploy|postdeploy)\")\b"
)
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


def _named_dir(ctx: Context, start: str, number: int, line: str, at: int) -> str | None:
    """The folder a start command runs in when it names one: a Render rootDir, a compose build
    context, then a `cd <dir>` before the seed command. None when nothing names a folder."""
    base = service_root_dir(ctx, start, number)
    if base is None:
        base = compose_build_dir(ctx, start, number)
    moves = [m.group(1) for m in CD_PREFIX.finditer(line[:at]) if not m.group(1).startswith("/")]
    if base is None and not moves:
        return None
    folder = base if base is not None else str(PurePosixPath(start).parent)
    if moves:
        folder = posixpath.normpath(posixpath.join(folder, moves[-1]))
    return "" if folder == "." else folder


def _seed_target(ctx: Context, start: str, number: int, line: str) -> tuple[list[str], list[str]]:
    """(seed files the start command runs, files with the same name that it does not run).

    The name resolves under the folder the command names (Render rootDir, compose build
    context, `cd <dir>`), or else next to the start file; a file at that exact path wins, then
    any file in the same app root. A shared start file (outside every app root, in the
    repository-root entry or in a library root) that names no folder runs the seed of the one
    app root that has it. A start file in any other app root never runs another root's seed."""
    module = re.search(r"-m\s+([\w.]*seed\w*)", line)
    script = re.search(r"([\w./-]*seed\w*\.(?:py|js|ts|mjs))", line)
    found = module or script
    if found is None:
        return [], []
    suffix = (module.group(1).replace(".", "/") + ".py" if module else script.group(1)).lstrip("./")
    matches = [f.rel for f in ctx.index.files if f.rel == suffix or f.rel.endswith("/" + suffix)]
    roots = ctx.detection.app_roots
    own = root_of(roots, start)
    shared = own is None or not own.path or own.kind == "library"
    pool = matches if shared else [m for m in matches if same_root(roots, m, start)]
    folder = _named_dir(ctx, start, number, line, found.start())
    base = folder if folder is not None else str(PurePosixPath(start).parent)
    anchor = str(PurePosixPath(base) / suffix) if base not in ("", ".") else suffix
    local = [m for m in pool if m == anchor] or [m for m in pool if same_root(roots, m, anchor)]
    if not local and shared and folder is None:
        homes = {getattr(root_of(roots, m), "path", None) for m in pool}
        local = pool if len(homes) == 1 else []
    return local, [m for m in matches if m not in local]


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
    targets, elsewhere = _seed_target(ctx, rel, number, text.splitlines()[number - 1].strip())
    direct = [t for t in targets if any(not lit.env_fallback for _, lit in sites.get(t, []))]
    other = [t for t in elsewhere if any(not lit.env_fallback for _, lit in sites.get(t, []))]
    fallback = [lit for t in targets for _, lit in sites.get(t, []) if lit.env_fallback]
    stage = start_stage(ctx, rel, number)
    severity, detail, proof, locations = "high", "", None, [Location(rel, number)]
    if direct:
        severity = "high" if non_production(stage) else "critical"
        detail = f" The seed file {direct[0]} hashes passwords written in the repository."
        locations.append(Location(direct[0], sites[direct[0]][0][0]))
    elif fallback and fallback[0].env_name:
        target = next(t for t in targets if any(lit.env_fallback for _, lit in sites.get(t, [])))
        locations.append(Location(target, sites[target][0][0]))
        secret = secret_reference(ctx, fallback[0].env_name, rel)
        if secret is not None:
            severity = "medium"
            locations.append(secret)
            detail = (
                f" The seed falls back to a committed password only when "
                f"{fallback[0].env_name} is unset, and {secret.file} supplies that variable "
                "from a secret store."
            )
            proof = f"Check that the secret reference for {fallback[0].env_name} resolves."
    elif not targets and other:
        proof = (
            f"Check which seed file this start command runs: {other[0]}, in another app root, "
            "hashes passwords written in the repository."
        )
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
