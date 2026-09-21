"""Environment settings written in deploy configuration: values, secret references, stages."""

from __future__ import annotations

import re
from dataclasses import dataclass

from dpr.discovery.approots import DEPLOY_FILES
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


def deploy_files(ctx: Context, ci: bool = True) -> list[str]:
    """Files that configure a deployed environment. Local compose files are not included."""
    names = [f.rel for f in ctx.index.named(*DEPLOY_FILES, "Dockerfile")]
    names += [f.rel for f in ctx.index.with_suffix(".tf")]
    names += list(ctx.detection.ci) if ci else []
    return list(dict.fromkeys(names))


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


def settings_named(ctx: Context, name: str, ci: bool = True) -> list[Setting]:
    found = []
    for rel in deploy_files(ctx, ci):
        text = ctx.index.text(rel)
        if name not in text:
            continue
        for number, value, tail in _render_pairs(text, name):
            secret = bool(SECRET_MARKERS.search(tail))
            found.append(Setting(name, value, Location(rel, number), secret))
        for match in _assignment(name).finditer(text):
            raw = match.group(1).strip()
            if raw.startswith("-") or not raw:
                continue
            value = raw.strip().strip("\"'").split('"')[0].split("'")[0]
            secret = bool(SECRET_MARKERS.search(raw))
            found.append(Setting(name, value, Location(rel, line_of(text, match.start())), secret))
    return found


def secret_reference(ctx: Context, name: str) -> Location | None:
    """Where a deploy config supplies the variable from a secret store, if it does."""
    return next((s.location for s in settings_named(ctx, name) if s.secret), None)


def all_false(ctx: Context, name: str) -> list[Location]:
    """Locations when every deploy config (not CI) that sets the variable sets it false."""
    values = settings_named(ctx, name, ci=False)
    if values and all(s.value.lower() in FALSE_WORDS for s in values):
        return [s.location for s in values]
    return []


def start_stage(ctx: Context, rel: str, line: int) -> str | None:
    """The stage a start command runs in when its own file names one (render service blocks)."""
    text = ctx.index.text(rel)
    lines = text.splitlines()
    start, end = 0, len(lines)
    if rel.endswith((".yaml", ".yml")):
        heads = [i for i, raw in enumerate(lines) if re.match(r"^\s*-\s*type:", raw)]
        start = max([i for i in heads if i < line] or [0])
        end = min([i for i in heads if i >= line] or [len(lines)])
    block = "\n".join(lines[start:end])
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
