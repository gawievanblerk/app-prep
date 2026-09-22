"""Environment settings written in deploy configuration: values, secret references, stages."""

from __future__ import annotations

import re
from dataclasses import dataclass

from dpr.discovery.approots import DEPLOY_FILES, root_of
from dpr.discovery.packages import manifest_packages_by_file
from dpr.model import Location
from dpr.rules import Context
from dpr.walk import line_of

SECRET_MARKERS = re.compile(
    r"@Microsoft\.KeyVault|key_vault_secret|secretsmanager|ssm_parameter|secret_manager"
    r"|secretKeyRef|valueFrom|\$\{\{\s*secrets\.|sync:\s*false|generateValue:\s*true",
    re.IGNORECASE,
)
NON_PRODUCTION = re.compile(
    r"^(?:staging|stage|preview|demo|dev|development|test|testing|qa|uat|sandbox|local)$",
    re.IGNORECASE,
)
STAGE_NAMES = ("ENVIRONMENT", "APP_ENV", "NODE_ENV", "ENV", "RAILS_ENV", "FLASK_ENV", "STAGE")
FALSE_WORDS = ("false", "0", "no", "off")


@dataclass(frozen=True)
class Setting:
    name: str
    value: str
    location: Location
    secret: bool


def applies(ctx: Context, deploy_rel: str, rel: str | None) -> bool:
    """A start or deploy file applies to `rel`'s app root when it is shared or belongs to it.

    Shared: the file's own root is None, the repository root (path ""), or a "library" kind.
    Repository-level infra configures every app and always applies. Any other start or deploy
    file (inside a different app root) applies only when it shares that root with `rel`."""
    if rel is None:
        return True
    deploy_root = root_of(ctx.detection.app_roots, deploy_rel)
    if deploy_root is None or not deploy_root.path or deploy_root.kind == "library":
        return True
    finding_root = root_of(ctx.detection.app_roots, rel)
    return finding_root is not None and finding_root.path == deploy_root.path


def declared_for(ctx: Context, rel: str, names: set[str] | frozenset[str]) -> bool:
    """True when a manifest that applies to `rel`'s app root declares one of `names`: a manifest
    inside the same root, or a shared one (see `applies`)."""
    key = ("manifest-packages-by-file", "")
    if key not in ctx.index.cache:
        ctx.index.cache[key] = manifest_packages_by_file(ctx.index)
    return any(
        names & packages
        for manifest_rel, packages in ctx.index.cache[key].items()
        if applies(ctx, manifest_rel, rel)
    )


def deploy_files(ctx: Context, ci: bool = True, rel: str | None = None) -> list[str]:
    """Files that configure a deployed environment. Local compose files are not included.

    With `rel`, only files that apply to that finding's app root are returned (see `applies`)."""
    names = [f.rel for f in ctx.index.named(*DEPLOY_FILES, "Dockerfile")]
    names += [f.rel for f in ctx.index.with_suffix(".tf")]
    names += list(ctx.detection.ci) if ci else []
    names = list(dict.fromkeys(names))
    return [n for n in names if applies(ctx, n, rel)]


def _assignment(name: str) -> re.Pattern[str]:
    return re.compile(
        rf"""^\s*(?:-\s*)?(?:ENV\s+|export\s+)?["']?{re.escape(name)}["']?\s*[:= ]\s*(.*)$""",
        re.MULTILINE,
    )


def _render_pairs(text: str, name: str) -> list[tuple[int, str, str]]:
    """Render style `- key: NAME` followed by `value:`, `sync:` or `generateValue:` lines."""
    found = []
    lines = text.splitlines()
    for number, line in enumerate(lines, start=1):
        if not re.match(rf"""^\s*-\s*key:\s*["']?{re.escape(name)}["']?\s*$""", line):
            continue
        tail = " ".join(lines[number : number + 2])
        value = re.search(r"""value:\s*["']?([^"'\s#]*)""", tail)
        found.append((number, value.group(1) if value else "", tail))
    return found


def settings_named(
    ctx: Context, name: str, ci: bool = True, rel: str | None = None
) -> list[Setting]:
    found = []
    for deploy_rel in deploy_files(ctx, ci, rel):
        text = ctx.index.text(deploy_rel)
        if name not in text:
            continue
        for number, value, tail in _render_pairs(text, name):
            secret = bool(SECRET_MARKERS.search(tail))
            found.append(Setting(name, value, Location(deploy_rel, number), secret))
        for match in _assignment(name).finditer(text):
            raw = match.group(1).strip()
            if raw.startswith("-") or not raw:
                continue
            value = raw.strip().strip("\"'").split('"')[0].split("'")[0]
            secret = bool(SECRET_MARKERS.search(raw))
            location = Location(deploy_rel, line_of(text, match.start()))
            found.append(Setting(name, value, location, secret))
    return found


def secret_reference(ctx: Context, name: str, rel: str | None = None) -> Location | None:
    """Where a deploy config supplies the variable from a secret store, if it does.

    With `rel`, only a deploy file that applies to that finding's app root counts."""
    return next((s.location for s in settings_named(ctx, name, rel=rel) if s.secret), None)


def all_false(ctx: Context, name: str, rel: str | None = None) -> list[Location]:
    """Locations when every applicable deploy config (not CI) that sets the variable sets it
    false, and at least one does. With `rel`, only deploy files that apply to that finding's app
    root count."""
    values = settings_named(ctx, name, ci=False, rel=rel)
    if values and all(s.value.lower() in FALSE_WORDS for s in values):
        return [s.location for s in values]
    return []


def service_block(ctx: Context, rel: str, line: int) -> str:
    """The service block (render style `- type:` items) that holds `line`, or the whole file."""
    lines = ctx.index.text(rel).splitlines()
    start, end = 0, len(lines)
    if rel.endswith((".yaml", ".yml")):
        heads = [i for i, raw in enumerate(lines) if re.match(r"^\s*-\s*type:", raw)]
        start = max([i for i in heads if i < line] or [0])
        end = min([i for i in heads if i >= line] or [len(lines)])
    return "\n".join(lines[start:end])


def service_root_dir(ctx: Context, rel: str, line: int) -> str | None:
    """The `rootDir` of the service block that holds `line`, as a repository-relative folder
    ("" for the repository root), or None when the block names none."""
    if not rel.endswith((".yaml", ".yml")):
        return None
    block = service_block(ctx, rel, line)
    match = re.search(r"""^\s*rootDir:\s*["']?([^"'\s#]+)""", block, re.MULTILINE)
    if match is None:
        return None
    folder = match.group(1).removeprefix("./").strip("/")
    return "" if folder == "." else folder


def start_stage(ctx: Context, rel: str, line: int) -> str | None:
    """The stage a start command runs in when its own file names one (render service blocks)."""
    block = service_block(ctx, rel, line)
    for name in STAGE_NAMES:
        for _number, value, _tail in _render_pairs(block, name):
            if value:
                return value
        match = re.search(rf"""\b{name}\s*=\s*["']?(\w+)""", block)
        if match:
            return match.group(1)
    return None


def non_production(stage: str | None) -> bool:
    return bool(stage and NON_PRODUCTION.match(stage))
