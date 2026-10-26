"""Review 5, OWASP A05, A08 and A09: supply chain, deserialisation, CI, XML and auth logging."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from pathlib import PurePosixPath

from dpr.model import Finding, Location, Tag
from dpr.parsing import jsts, pyast
from dpr.redact import snippet
from dpr.reviews.baseline_accounts import START_FILES
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule
from dpr.vendored import is_vendored
from dpr.walk import line_of

SCRIPT_TAG = re.compile(r"<script\b[^>]*\bsrc\s*=\s*[\"']https?://[^>]*>", re.IGNORECASE)
MARKUP = (".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte", ".j2", ".jinja", ".jinja2")
PY_DESERIALISE = re.compile(
    r"(?:pickle|cPickle|dill|marshal)\.loads?|jsonpickle\.decode|yaml\.unsafe_load|yaml\.load"
)
SAFE_LOADER = re.compile(r"Safe|CSafe|BaseLoader")
HEAD_CHECKOUT = re.compile(
    r"github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref", re.IGNORECASE
)
CI_FILES = (
    "azure-pipelines.yml",
    ".gitlab-ci.yml",
    "bitbucket-pipelines.yml",
    "Jenkinsfile",
    "cloudbuild.yaml",
)
LOCK_FILES = {"requirements.lock", "poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock"}
JS_LOCKS = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lockb",
    "bun.lock",
    "npm-shrinkwrap.json",
}
PIP_INSTALL = re.compile(r"\bpip3?\s+install\s+(.*)$")
NPX_SCOPED = re.compile(r"\bnpx\s+(?:--?\w+\s+)*(@[\w.-]+/[\w.-]+)(?!@)(?=\s|$)")
NPM_INSTALL = re.compile(r"\bnpm\s+(?:install|i)\b(.*)$")
LOGIN_ROUTE = re.compile(r"(?i)log-?in|sign-?in|/token$")
FAIL_STATUS = re.compile(r"\b401\b|HTTP_401|UNAUTHORIZED|Unauthorized")
LOG_CALL = re.compile(
    r"\b(?:logger|logging|log|console)\.(?:warn|warning|error|info|log|exception)"
)
XML_CALLS = re.compile(
    r"(?:xml\.etree\.)?(?:ElementTree|ET|etree|cElementTree)\.(?:parse|fromstring|XML|iterparse)"
    r"|(?:xml\.dom\.)?minidom\.parse(?:String)?|xml\.sax\.parse(?:String)?|openpyxl\.load_workbook"
    r"|load_workbook"
)


@rule("OWASP-A08-NO-SRI", review="owasp", severity="low", exploitability="low", owasp="A08")
def no_sri(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.files:
        if not entry.rel.lower().endswith(MARKUP) or is_test(entry.rel):
            continue
        if is_vendored(ctx.index, entry.rel):  # saved pages of a copied library or docs site
            continue
        text = ctx.index.text(entry.rel)
        lines = [
            line_of(text, m.start())
            for m in SCRIPT_TAG.finditer(text)
            if "integrity" not in m.group(0).lower()
        ]
        if lines:
            yield make_finding(
                "OWASP-A08-NO-SRI",
                tag=Tag.CONFIRMED,
                locations=[Location(entry.rel, n) for n in lines[:5]],
                snippet=snippet(text, lines[0]),
                count=len(lines),
            )


@rule(
    "OWASP-A08-UNSAFE-DESERIALISE",
    review="owasp",
    severity="high",
    exploitability="medium",
    owasp="A08",
)
def unsafe_deserialise(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.py_files:
        if is_test(entry.rel) or is_vendored(ctx.index, entry.rel):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for call in pyast.calls(tree, PY_DESERIALISE) if tree else []:
            name = pyast.dotted(call.func)
            loader = pyast.kwarg(call, "Loader")
            if name == "yaml.load" and (
                (loader is not None and SAFE_LOADER.search(ast.unparse(loader)))
                or (len(call.args) > 1 and SAFE_LOADER.search(ast.unparse(call.args[1])))
            ):
                continue
            yield make_finding(
                "OWASP-A08-UNSAFE-DESERIALISE",
                tag=Tag.INFERRED,
                locations=[Location(entry.rel, call.lineno)],
                snippet=snippet(ctx.index.text(entry.rel), call.lineno),
                call=name,
            )
    for entry in ctx.index.js_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel) or is_vendored(ctx.index, entry.rel) or "node-serialize" not in text:
            continue
        for match in re.finditer(r"\bunserialize\s*\(", text):
            line = line_of(text, match.start())
            yield make_finding(
                "OWASP-A08-UNSAFE-DESERIALISE",
                tag=Tag.INFERRED,
                locations=[Location(entry.rel, line)],
                snippet=snippet(text, line),
                call="node-serialize unserialize",
            )


@rule(
    "OWASP-A08-CI-UNTRUSTED", review="owasp", severity="high", exploitability="medium", owasp="A08"
)
def ci_untrusted(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.glob(".github/workflows/*"):
        text = ctx.index.text(entry.rel)
        if "pull_request_target" not in text:
            continue
        for match in HEAD_CHECKOUT.finditer(text):
            line = line_of(text, match.start())
            yield make_finding(
                "OWASP-A08-CI-UNTRUSTED",
                tag=Tag.CONFIRMED,
                locations=[Location(entry.rel, line)],
                snippet=snippet(text, line),
            )


def _folder_files(ctx: Context) -> set[str]:
    return {f.rel for f in ctx.index.files}


@rule("OWASP-A08-UNPINNED-DEPS", review="owasp", severity="low", exploitability="low", owasp="A08")
def unpinned_deps(ctx: Context) -> Iterator[Finding]:
    names = _folder_files(ctx)
    for entry in ctx.index.named("requirements*.txt"):
        folder = PurePosixPath(entry.rel).parent
        prefix = "" if str(folder) == "." else f"{folder}/"
        text = ctx.index.text(entry.rel)
        if "--hash" in text or any(f"{prefix}{lock}" in names for lock in LOCK_FILES):
            continue
        specs = []
        for number, raw in enumerate(text.splitlines(), start=1):
            line = raw.split("#", 1)[0].strip()
            if line and not line.startswith("-"):
                specs.append((number, "==" in line))
        unpinned = [n for n, pinned in specs if not pinned]
        if specs and len(unpinned) * 2 >= len(specs):
            yield make_finding(
                "OWASP-A08-UNPINNED-DEPS",
                tag=Tag.CONFIRMED,
                locations=[Location(entry.rel, unpinned[0])],
                snippet=snippet(text, unpinned[0]),
                what=f"{len(unpinned)} of {len(specs)} requirements in {entry.name} have no exact "
                "version and no lock file or hashes sit next to it.",
            )
    for entry in ctx.index.named("package.json"):
        parts = PurePosixPath(entry.rel).parent.parts
        folders = ["/".join(parts[:i]) for i in range(len(parts), -1, -1)]
        locked = any(f"{f}/{lock}".lstrip("/") in names for f in folders for lock in JS_LOCKS)
        if not locked and '"dependencies"' in ctx.index.text(entry.rel):
            yield make_finding(
                "OWASP-A08-UNPINNED-DEPS",
                tag=Tag.CONFIRMED,
                locations=[Location(entry.rel, 1)],
                what="No npm, yarn, pnpm or bun lock file covers this package.json.",
            )


SHELL_STOP = re.compile(r"^(?:&&|\|\||;|\||\d*>.*|<.*|#.*)$")


def command_args(text: str) -> list[str]:
    """Arguments up to the first shell operator, redirect or comment."""
    args = []
    for token in text.split():
        if SHELL_STOP.match(token):
            break
        args.append(token.rstrip(";"))
    return args


def _install_problems(line: str, runtime: bool) -> str | None:
    pip = PIP_INSTALL.search(line)
    if pip:
        tokens = command_args(pip.group(1))
        args = [a for a in tokens if not a.startswith("-")]
        if "-r" in tokens or "-e" in tokens:
            return None
        packages = [a for a in args if a not in (".", "pip") and "==" not in a]
        if packages:
            where = "at start-up" if runtime else "in CI"
            return f"pip installs {', '.join(packages[:3])} without a pinned version {where}."
    npx = NPX_SCOPED.search(line)
    if npx:
        return f"npx runs {npx.group(1)} without a pinned version."
    npm = NPM_INSTALL.search(line)
    if npm and not runtime:
        tokens = command_args(npm.group(1))
        extra = [a for a in tokens if not a.startswith("-")]
        if not extra:
            return "npm install in CI can rewrite the lock file; npm ci installs what is locked."
        if "-g" in tokens and not any("@" in a[1:] for a in extra):
            return f"npm installs {extra[0]} globally without a pinned version."
    return None


@rule(
    "OWASP-A08-UNPINNED-INSTALL", review="owasp", severity="low", exploitability="low", owasp="A08"
)
def unpinned_install(ctx: Context) -> Iterator[Finding]:
    starts = [
        e for e in ctx.index.named(*START_FILES) if e.name.endswith(".sh") or e.name == "Procfile"
    ]
    ci = [*ctx.index.glob(".github/workflows/*"), *ctx.index.named(*CI_FILES)]
    for entries, runtime in ((starts, True), (ci, False)):
        for entry in entries:
            text = ctx.index.text(entry.rel)
            problems = []
            for number, raw in enumerate(text.splitlines(), start=1):
                if raw.strip().startswith(("#", "echo ")):
                    continue
                problem = _install_problems(raw, runtime)
                if problem:
                    problems.append((number, problem))
            if problems:
                yield make_finding(
                    "OWASP-A08-UNPINNED-INSTALL",
                    tag=Tag.CONFIRMED,
                    locations=[Location(entry.rel, n) for n, _ in problems[:10]],
                    snippet=snippet(text, problems[0][0]),
                    file=entry.rel,
                    what=" ".join(dict.fromkeys(p for _, p in problems[:3])),
                )


@rule(
    "OWASP-A09-NO-AUTH-FAIL-LOG", review="owasp", severity="low", exploitability="low", owasp="A09"
)
def no_auth_fail_log(ctx: Context) -> Iterator[Finding]:
    for route in ctx.detection.routes:
        handler = route.handler
        name = getattr(handler, "name", "")
        if not LOGIN_ROUTE.search(route.path) and not LOGIN_ROUTE.search(str(name)):
            continue
        if route.method not in ("POST", "ANY", "ACTION") or is_test(route.file):
            continue
        if isinstance(handler, ast.AST):
            text = ast.unparse(handler)
        elif handler is not None and hasattr(handler, "type"):
            text = jsts.node_text(handler)
        else:
            continue
        if FAIL_STATUS.search(text) and not LOG_CALL.search(text):
            yield make_finding(
                "OWASP-A09-NO-AUTH-FAIL-LOG",
                tag=Tag.INFERRED,
                locations=[Location(route.file, route.line)],
                snippet=snippet(ctx.index.text(route.file), route.line),
                path=route.path,
            )


@rule("OWASP-A05-XML-PARSER", review="owasp", severity="low", exploitability="low", owasp="A05")
def xml_parser(ctx: Context) -> Iterator[Finding]:
    if "defusedxml" in ctx.detection.packages:
        return
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel) or not re.search(r"xml|openpyxl|load_workbook", text):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        lines = [c.lineno for c in pyast.calls(tree, XML_CALLS)] if tree else []
        if lines:
            yield make_finding(
                "OWASP-A05-XML-PARSER",
                tag=Tag.INFERRED,
                locations=[Location(entry.rel, n) for n in lines[:5]],
                snippet=snippet(text, lines[0]),
            )
