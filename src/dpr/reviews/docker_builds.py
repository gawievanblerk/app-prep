"""Dockerfile stages and the compose services that build them. Shared by the container rules."""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

import yaml

from dpr.facts import fact
from dpr.rules import Context

COMPOSE_FILES = ("docker-compose*.yml", "docker-compose*.yaml", "compose*.yml", "compose*.yaml")
DEV_WORD = re.compile(r"(?i)(?:^|[._-])(?:dev|development|local|override)(?:[._-]|$)")
PROD_WORD = re.compile(r"(?i)(?:^|[._-])(?:prod|production)(?:[._-]|$)")
FROM = re.compile(r"^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", re.I)
WORKDIR = re.compile(r"^\s*WORKDIR\s+(\S+)", re.I)
COPY = re.compile(r"^\s*(?:COPY|ADD)\s+((?:--\S+\s+)*)(.+)$", re.I)
FROM_FLAG = re.compile(r"--from=(\S+)", re.I)
STOCK_NGINX = re.compile(r"^(?:docker\.io/)?(?:library/)?nginx(?:[:@]|$)", re.I)


@dataclass(frozen=True)
class Build:
    compose: str
    context: str
    dockerfile: str


@dataclass
class Stage:
    base: str
    name: str | None
    line: int
    rows: list[tuple[int, str]] = field(default_factory=list)


def _norm(path: str) -> str:
    return posixpath.normpath(path) if path else "."


def _builds(ctx: Context) -> list[Build]:
    found = []
    for entry in ctx.index.named(*COMPOSE_FILES):
        try:
            data = yaml.safe_load(ctx.index.text(entry.rel))
        except yaml.YAMLError:
            continue
        services = data.get("services") if isinstance(data, dict) else None
        for service in services.values() if isinstance(services, dict) else []:
            build = service.get("build") if isinstance(service, dict) else None
            if isinstance(build, str):
                context, dockerfile = build, "Dockerfile"
            elif isinstance(build, dict):
                context = str(build.get("context") or ".")
                dockerfile = str(build.get("dockerfile") or "Dockerfile")
            else:
                continue
            if "://" in context or context.startswith("git@"):
                continue
            folder = _norm(posixpath.join(posixpath.dirname(entry.rel), context))
            if folder.startswith(".."):
                continue
            found.append(Build(entry.rel, folder, _norm(posixpath.join(folder, dockerfile))))
    return found


def compose_builds(ctx: Context) -> list[Build]:
    return fact(ctx, "compose_builds", _builds)


def builds_of(ctx: Context, dockerfile: str) -> list[Build]:
    return [b for b in compose_builds(ctx) if b.dockerfile == dockerfile]


def _dev_compose(ctx: Context, rel: str) -> bool:
    """A compose file for development: its name says so, or it has no production word while a
    compose file beside it does (docker-compose.yml next to docker-compose.prod.yml)."""
    name = PurePosixPath(rel).name
    if DEV_WORD.search(name):
        return True
    if PROD_WORD.search(name):
        return False
    folder = posixpath.dirname(rel)
    return any(
        PROD_WORD.search(b.name) and posixpath.dirname(b.rel) == folder
        for b in ctx.index.named(*COMPOSE_FILES)
    )


def dev_only(ctx: Context, dockerfile: str) -> bool:
    """Named for development (Dockerfile.dev, dev.Dockerfile), or built only by dev compose
    files."""
    name = PurePosixPath(dockerfile).name
    if re.search(r"(?i)\.(?:dev|development)$|^(?:dev|development)\.", name):
        return True
    builds = builds_of(ctx, dockerfile)
    return bool(builds) and all(_dev_compose(ctx, b.compose) for b in builds)


def stages(text: str) -> list[Stage]:
    found: list[Stage] = []
    for number, row in enumerate(text.splitlines(), start=1):
        match = FROM.match(row)
        if match:
            found.append(Stage(match.group(1), match.group(2), number))
        elif found:
            found[-1].rows.append((number, row))
    return found


def stock_nginx(stage: Stage) -> bool:
    """The stock nginx image: its master runs as root and its workers drop to `nginx`."""
    return bool(STOCK_NGINX.match(stage.base))


def _index(all_stages: list[Stage], ref: str, before: int) -> int | None:
    names = {s.name.lower(): i for i, s in enumerate(all_stages) if s.name}
    j = int(ref) if ref.isdigit() else names.get(ref.lower())
    return j if j is not None and j < before else None


def _workdirs(all_stages: list[Stage], i: int) -> set[str]:
    dirs = {m.group(1).rstrip("/") for _, row in all_stages[i].rows if (m := WORKDIR.match(row))}
    base = _index(all_stages, all_stages[i].base, i)
    return dirs | (_workdirs(all_stages, base) if base is not None else set())


def _sources(rest: str) -> list[str]:
    rest = rest.strip()
    if rest.startswith("["):
        parts = re.findall(r'"([^"]*)"', rest)
    else:
        parts = rest.split()
    return parts[:-1]


def shipped_copies(text: str, copy_all: re.Pattern[str]) -> list[int]:
    """Lines of `COPY . <dest>` whose files end in the image: in the final stage, in a stage it
    is built `FROM`, or in a stage whose whole root or work folder it copies with `--from`. A
    final stage that copies only named build output from earlier stages ships none."""
    all_stages = stages(text)
    lines: set[int] = set()
    seen: set[int] = set()

    def visit(i: int) -> None:
        if i in seen:
            return
        seen.add(i)
        stage = all_stages[i]
        for number, row in stage.rows:
            match = COPY.match(row)
            if match and FROM_FLAG.search(match.group(1)):
                j = _index(all_stages, FROM_FLAG.search(match.group(1)).group(1), i)
                if j is None:
                    continue
                whole = {"", "."} | _workdirs(all_stages, j)
                if any(s.rstrip("/") in whole for s in _sources(match.group(2))):
                    visit(j)
            elif copy_all.match(row):
                lines.add(number)
        base = _index(all_stages, stage.base, i)
        if base is not None:
            visit(base)

    if all_stages:
        visit(len(all_stages) - 1)
    return sorted(lines)
