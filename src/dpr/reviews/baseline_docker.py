"""Review 4, baseline: container images and file permissions.

`BASE-DOCKER-ROOT`: a Dockerfile whose final stage never switches to a non-root `USER` (low
when it is only for development; a stock nginx final stage is skipped).
`BASE-WORLD-WRITABLE`: `chmod` to world-writable modes in Dockerfiles, shell and Python scripts.
`BASE-DOCKERIGNORE-THIN`: a `COPY . ` that ends in the image while the build context's
`.dockerignore` is missing or lets the git history, env files, database dumps, uploads or
ignored local settings in.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterator
from pathlib import PurePosixPath

from dpr.model import Finding, Location, Tag
from dpr.redact import snippet
from dpr.reviews.docker_builds import builds_of, dev_only, shipped_copies, stages, stock_nginx
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule
from dpr.vendored import is_vendored

DOCKERFILES = ("Dockerfile", "Dockerfile.*", "*.dockerfile", "Containerfile")
USER = re.compile(r"^\s*USER\s+(\S+)", re.I)
OCTAL = r"0?[0-7]?[0-7][0-7][2367]"
SYMBOLIC = r"[ugoa]*[oa][ugoa]*[+=][rwxXst]*w[rwxXst]*"
CHMOD = re.compile(rf"""\bchmod\b["',\s]+(?:-[A-Za-z]+["',\s]+)*(?:({OCTAL})|({SYMBOLIC}))\b""")
OS_CHMOD = re.compile(r"os\.chmod\([^)]*,\s*(0o[0-7]*[0-7][0-7][2367])\b|stat\.S_IWOTH")
SCRIPT_SUFFIXES = (".sh", ".bash", ".py")
COPY_ALL = re.compile(r"^\s*(?:COPY|ADD)\s+(?:--\S+\s+)*\.\s+\S", re.I | re.M)
# What the build context must keep out, with a sample path each pattern should match.
MUST_EXCLUDE = (
    ("the git history (.git)", ".git"),
    ("environment files (.env*)", ".env.production"),
    ("database dumps (*.sql, *.dump)", "backup/dump.sql"),
)
UPLOAD_DIRS = ("media", "uploads", "upload")
DEV_DETAIL = (
    " It is named for development or built only by a development compose file, so it is not "
    "expected to run in production."
)
SECRET_IGNORED = re.compile(
    r"(?:^|/)(?:local_settings\.py|[\w.-]*\.pem|[\w.-]*\.key|secrets?[\w.-]*)$"
)


def _dockerfiles(ctx: Context) -> list[str]:
    return [
        e.rel
        for e in ctx.index.named(*DOCKERFILES)
        if not is_test(e.rel) and not is_vendored(ctx.index, e.rel)
    ]


@rule("BASE-DOCKER-ROOT", review="baseline", severity="medium", exploitability="low", owasp="A05")
def docker_root(ctx: Context) -> Iterator[Finding]:
    for rel in _dockerfiles(ctx):
        all_stages = stages(ctx.index.text(rel))
        if not all_stages:
            continue
        final = all_stages[-1]
        if "nonroot" in final.base.lower() or stock_nginx(final):
            continue
        users = [m.group(1) for _, row in final.rows if (m := USER.match(row))]
        if users and users[-1].split(":")[0] not in ("root", "0"):
            continue
        dev = dev_only(ctx, rel)
        now = "switches back to root" if users else "has no USER instruction"
        yield make_finding(
            "BASE-DOCKER-ROOT",
            tag=Tag.CONFIRMED,
            locations=[Location(rel, final.line)],
            severity="low" if dev else None,
            snippet=snippet(ctx.index.text(rel), final.line),
            now=now,
            dev=DEV_DETAIL if dev else "",
        )


def _chmod_lines(text: str, python: bool) -> list[tuple[int, str]]:
    found = []
    for number, row in enumerate(text.splitlines(), start=1):
        if row.lstrip().startswith("#"):
            continue
        match = CHMOD.search(row)
        mode = (match.group(1) or match.group(2)) if match else None
        if mode and mode.startswith("1") and len(mode) == 4:
            mode = None  # sticky shared folders such as /tmp
        if python and not mode and (os_match := OS_CHMOD.search(row)):
            mode = os_match.group(1) or "S_IWOTH"
        if mode:
            found.append((number, mode))
    return found


@rule(
    "BASE-WORLD-WRITABLE", review="baseline", severity="high", exploitability="medium", owasp="A05"
)
def world_writable(ctx: Context) -> Iterator[Finding]:
    files = set(_dockerfiles(ctx)) | {
        e.rel
        for e in ctx.index.files
        if e.suffix in SCRIPT_SUFFIXES and not is_test(e.rel) and not is_vendored(ctx.index, e.rel)
    }
    for rel in sorted(files):
        text = ctx.index.text(rel)
        if "chmod" not in text:
            continue
        hits = _chmod_lines(text, rel.endswith(".py"))
        if hits:
            yield make_finding(
                "BASE-WORLD-WRITABLE",
                tag=Tag.CONFIRMED,
                locations=[Location(rel, line) for line, _ in hits],
                snippet=snippet(text, hits[0][0]),
                modes=", ".join(dict.fromkeys(mode for _, mode in hits)),
            )


def _ignore_patterns(text: str) -> list[str]:
    rows = [r.strip() for r in text.splitlines()]
    return [r for r in rows if r and not r.startswith("#")]


def _ignored(patterns: list[str], path: str) -> bool:
    """Whether .dockerignore patterns keep a path out of the build context (last match wins)."""
    result = False
    for pattern in patterns:
        negate = pattern.startswith("!")
        glob = pattern.lstrip("!").lstrip("/").rstrip("/")
        glob = glob[3:] if glob.startswith("**/") else glob
        parts = PurePosixPath(path).parts
        prefixes = ["/".join(parts[:i]) for i in range(1, len(parts) + 1)]
        tails = ["/".join(parts[i:]) for i in range(len(parts))]
        if any(fnmatch.fnmatch(p, glob) for p in prefixes) or (
            "/" not in glob and any(fnmatch.fnmatch(t.split("/")[0], glob) for t in tails)
        ):
            result = not negate
    return result


def _required(ctx: Context, folder: str) -> list[tuple[str, str]]:
    """(what, a sample path) the build context should keep out of the image."""
    root = ctx.index.root / folder if folder != "." else ctx.index.root
    # Only a context that holds the repository's .git folder can copy the history.
    needed = [item for item in MUST_EXCLUDE if item[1] != ".git" or (root / ".git").exists()]
    for name in UPLOAD_DIRS:
        found = [p for p in (root / name, *sorted(root.glob(f"*/{name}"))) if p.is_dir()]
        if found:
            sample = found[0].relative_to(root).as_posix()
            needed.append((f"uploaded files ({sample}/)", f"{sample}/file.pdf"))
            break
    if (root / "package.json").exists() or any(root.glob("*/package.json")):
        needed.append(("node_modules", "node_modules/pkg/index.js"))
    gitignore = root / ".gitignore"
    rows = _ignore_patterns(gitignore.read_text(errors="replace")) if gitignore.is_file() else []
    for row in rows:
        clean = row.lstrip("/").removeprefix("**/")
        sample = f"certs/server{clean[1:]}" if clean in ("*.pem", "*.key") else clean
        if "*" not in sample and SECRET_IGNORED.search(sample):
            needed.append((f"{clean}, which git ignores but the build host may hold", sample))
    return needed


@rule(
    "BASE-DOCKERIGNORE-THIN",
    review="baseline",
    severity="high",
    exploitability="medium",
    owasp="A05",
)
def dockerignore_thin(ctx: Context) -> Iterator[Finding]:
    for rel in _dockerfiles(ctx):
        text = ctx.index.text(rel)
        lines = shipped_copies(text, COPY_ALL)
        if not lines:
            continue
        line = lines[0]
        folder = PurePosixPath(rel).parent.as_posix()
        # The build context is the compose service's, else the Dockerfile's folder.
        contexts = sorted({b.context for b in builds_of(ctx, rel)}) or [folder]
        for context in contexts:
            candidate = f"{context}/.dockerignore" if context != "." else ".dockerignore"
            ignore = candidate if (ctx.index.root / candidate).is_file() else None
            patterns = []
            if ignore is not None:
                patterns = _ignore_patterns((ctx.index.root / ignore).read_text(errors="replace"))
            missing = [
                label for label, sample in _required(ctx, context) if not _ignored(patterns, sample)
            ]
            if not missing:
                continue
            where = [Location(rel, line)] + ([Location(ignore, 1)] if ignore else [])
            yield make_finding(
                "BASE-DOCKERIGNORE-THIN",
                tag=Tag.CONFIRMED,
                locations=where,
                snippet=snippet(text, line),
                state=f"{ignore} does not exclude"
                if ignore
                else "there is no .dockerignore, so nothing excludes",
                missing="; ".join(missing),
            )
            break
