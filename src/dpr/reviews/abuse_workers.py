"""Review 7, abuse: evidence that more than one process or instance serves requests."""

from __future__ import annotations

import re
from collections.abc import Iterator

from dpr.data import load
from dpr.model import Location
from dpr.reviews.baseline_accounts import START_FILES
from dpr.reviews.deploy_env import applies
from dpr.rules import Context

WORKERS = re.compile(
    r"(?:--workers|-w)[ =](\d+)|WEB_CONCURRENCY=(\d+)|^\s*workers\s*=\s*(\d+)"
    r"|replicas:\s*(\d+)|-i\s+(max|\d+)|instances:\s*(max|\d+)"
)
RUNNER_NAMES = re.compile(r"(?i)gunicorn|uvicorn|hypercorn|daphne|granian")
PM2_NAME = re.compile(r"(?i)pm2")


def _strip_comment(line: str) -> str:
    """Drop text after an unquoted ' #', so a trailing comment is not read as evidence."""
    quote = None
    for index, char in enumerate(line[:-1]):
        if quote:
            if char == quote:
                quote = None
        elif char in "'\"":
            quote = char
        elif char == " " and line[index + 1] == "#":
            return line[:index]
    return line


def _continues(line: str) -> bool:
    return line.rstrip().endswith("\\")


def _unwrap_continuation(line: str) -> str:
    stripped = line.rstrip()
    return stripped[:-1] if stripped.endswith("\\") else line


def _logical_lines(text: str) -> Iterator[list[tuple[int, str]]]:
    """Physical lines grouped by trailing-backslash continuation.

    Blank and comment lines are dropped, and never joined into a continuation: a comment line
    where a continued shell command expected its next line ends that continuation.
    """
    physical = text.splitlines()
    index = 0
    total = len(physical)
    while index < total:
        stripped = physical[index].strip()
        if not stripped or stripped.startswith(("#", "//")):
            index += 1
            continue
        group = [(index + 1, _strip_comment(physical[index]))]
        index += 1
        while _continues(group[-1][1]) and index < total:
            next_stripped = physical[index].strip()
            if not next_stripped or next_stripped.startswith(("#", "//")):
                break
            group.append((index + 1, _strip_comment(physical[index])))
            index += 1
        yield group


def _worker_location(group: list[tuple[int, str]]) -> int | None:
    """The physical line in a logical line whose worker flag or value is live evidence."""
    whole = " ".join(_unwrap_continuation(text) for _, text in group)
    for number, line in group:
        match = WORKERS.search(line)
        if match is None:
            continue
        groups = match.groups()
        matched = next(i for i, g in enumerate(groups) if g is not None)
        if matched == 0 and not RUNNER_NAMES.search(whole):
            continue
        if matched == 4 and not PM2_NAME.search(whole):
            continue
        value = groups[matched]
        if value == "max" or int(value) > 1:
            return number
    return None


def _hosting_file(ctx: Context, near: str) -> Location | None:
    """The config file of the serverless host, closest to `near`."""
    stack = load("stack.yaml")
    patterns = [
        pattern
        for host in ctx.detection.hosting
        if host in stack["serverless_hosting"]
        for pattern in stack["hosting"].get(host, {}).get("files", [])
    ]
    files = [entry.rel for entry in ctx.index.named(*patterns)] if patterns else []
    if not files:
        return None
    return Location(max(files, key=lambda rel: (len(_common(rel, near)), -len(rel))), 1)


def multi_process(ctx: Context, near: str = "") -> Location | None:
    """Evidence that more than one process or instance serves requests, closest to `near`.

    For serverless hosting the evidence is the host's config file (for example vercel.json).
    With `near`, only files that apply to its app root count: its own root, or shared
    repository-level infra such as a root docker-compose.yml (see `deploy_env.applies`).
    """
    if ctx.detection.serverless:
        hosting = _hosting_file(ctx, near)
        if hosting is not None and (not near or applies(ctx, hosting.file, near)):
            return hosting
    names = (*START_FILES, "gunicorn.conf.py", "*.yaml", "*.yml", "ecosystem.config.js")
    found = []
    for entry in ctx.index.named(*names):
        text = ctx.index.text(entry.rel)
        for group in _logical_lines(text):
            number = _worker_location(group)
            if number is not None:
                found.append(Location(entry.rel, number))
                break
    if near:
        found = [loc for loc in found if applies(ctx, loc.file, near)]
    if not found:
        return None
    return max(found, key=lambda loc: len(_common(loc.file, near)))


def _common(a: str, b: str) -> list[str]:
    shared = []
    for left, right in zip(a.split("/"), b.split("/"), strict=False):
        if left != right:
            break
        shared.append(left)
    return shared
