"""Review 6, leak hunt: browser-shipped gate keys and committed default credentials."""

from __future__ import annotations

import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Tag
from dpr.redact import public_prefix
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule
from dpr.walk import line_of

GATE_WORDS = re.compile(
    r"BYPASS|UNLOCK|OVERRIDE|BACKDOOR|MASTER_?KEY|ACCESS_?CODE|INVITE_?CODE|STAFF_?KEY"
    r"|MAINTENANCE_?KEY|PREVIEW_?KEY|DEBUG_?KEY"
)
CONFIG_SUFFIXES = (".yml", ".yaml", ".toml", ".json", ".tf")
SECRET_KEY_NAME = re.compile(r"(?i)password|passwd|secret|token|api_?key|private_?key|jwt")
COMPOSE = re.compile(r"(?:^|/)(?:docker-)?compose[\w.-]*\.ya?ml$")
ENV_ENTRY = re.compile(r"""^\s*(?:-\s*)?["']?(\w+)["']?\s*[:=]\s*["']?([^"'\s#]+)""")
SHELL_DEFAULT = re.compile(r"\$\{(\w+):?-([^}]+)\}")
CLI_PASSWORD = re.compile(r"--[\w-]*pass(?:word|wd)?[ =](?![<$*{\[])([^\s\\'\"]+)", re.IGNORECASE)
URL_CREDENTIALS = re.compile(r"://[\w.-]+:(?![$<{*])([^@\s/'\"]+)@")
SCRIPT_SUFFIXES = (".sh", ".py", ".md", ".txt", ".ps1", ".bash")


def _literal_assignments(ctx: Context, name: str) -> list[Location]:
    found = []
    pattern = re.compile(rf"""\b{re.escape(name)}["']?\s*[:=]\s*["']?(?![$({{])[^\s"'#]+""")
    for entry in ctx.index.files:
        if not entry.rel.endswith(CONFIG_SUFFIXES) and entry.name != "Dockerfile":
            continue
        text = ctx.index.text(entry.rel)
        found += [Location(entry.rel, line_of(text, m.start())) for m in pattern.finditer(text)]
    return found


@rule("LEAK-PUBLIC-GATE-KEY", review="leaks", severity="low", exploitability="medium", owasp="A05")
def public_gate_key(ctx: Context) -> Iterator[Finding]:
    for env in ctx.detection.env_vars:
        prefix = public_prefix(env.name)
        if not prefix or not GATE_WORDS.search(env.name[len(prefix) :]):
            continue
        committed = _literal_assignments(ctx, env.name)
        where = (
            f" A value for it is committed at {committed[0]}."
            if committed
            else " No committed value was found."
        )
        yield make_finding(
            "LEAK-PUBLIC-GATE-KEY",
            tag=Tag.CONFIRMED,
            locations=[*committed, *env.locations][:10],
            name=env.name,
            prefix=prefix,
            where=where,
        )


PLACEHOLDER = re.compile(
    r"(?i)^(?:x+|\*+|\.{3}|changeme|change_me|password|pass|secret|your[\w-]*|placeholder"
    r"|example|redacted|<.*>)$"
)


def _is_default_credential(entry_rel: str, line: str) -> str | None:
    compose = bool(COMPOSE.search(entry_rel))
    if compose:
        entry = ENV_ENTRY.match(line)
        if entry and SECRET_KEY_NAME.search(entry.group(1)):
            value = entry.group(2)
            if not value.startswith("$") and not PLACEHOLDER.match(value):
                return f"a literal value for {entry.group(1)}"
    for match in SHELL_DEFAULT.finditer(line):
        if SECRET_KEY_NAME.search(match.group(1)) and not PLACEHOLDER.match(match.group(2)):
            return f"a default value for {match.group(1)}"
    url = URL_CREDENTIALS.search(line)
    local = re.search(r"@(?:localhost|127\.0\.0\.1)\b", line)
    documentation = entry_rel.endswith((".md", ".txt"))
    if url and not PLACEHOLDER.match(url.group(1)) and not documentation:
        if compose or not local:
            return "a connection URL with an inline password"
    cli = CLI_PASSWORD.search(line)
    if cli and not compose and not PLACEHOLDER.match(cli.group(1)):
        return "a password passed on a command line"
    return None


@rule("LEAK-DEFAULT-CREDENTIAL", review="leaks", severity="low", exploitability="low", owasp="A07")
def default_credential(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.files:
        if is_test(entry.rel):
            continue
        relevant = COMPOSE.search(entry.rel) or entry.rel.endswith(SCRIPT_SUFFIXES)
        if not relevant:
            continue
        text = ctx.index.text(entry.rel)
        if not re.search(r"(?i)pass|secret|token|key|jwt|://", text):
            continue
        hits = []
        for number, line in enumerate(text.splitlines(), start=1):
            kind = _is_default_credential(entry.rel, line)
            if kind:
                hits.append((number, kind))
        if hits:
            kinds = ", ".join(dict.fromkeys(kind for _, kind in hits))
            yield make_finding(
                "LEAK-DEFAULT-CREDENTIAL",
                tag=Tag.CONFIRMED,
                locations=[Location(entry.rel, n) for n, _ in hits[:10]],
                file=entry.rel,
                kinds=kinds,
            )
