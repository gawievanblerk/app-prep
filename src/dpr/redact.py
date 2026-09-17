"""Find key-shaped strings and mask them. No function here returns a key value."""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from functools import cache

from dpr.data import load

JWT = re.compile(r"eyJ[0-9A-Za-z_-]{8,}\.(eyJ[0-9A-Za-z_-]{8,})\.[0-9A-Za-z_-]{8,}")
URL_CREDS = re.compile(r"((?<=[a-zA-Z0-9+.-])://[^\s/:@'\"]*:)([^\s/@'\"]+)(@)")
CLI_PASSWORD = re.compile(r"--[\w-]*pass(?:word|wd)?[ =](?![<$*{\[])([^\s\\'\"]+)", re.IGNORECASE)
CLI_SECRET = re.compile(
    r"""(--[\w-]*(?:pass(?:word|wd)?|secret|token|api[_-]?key)[ =]\s*)"""
    r"""(?:(["'])([^"'\n]+)\2|(?![<$*{\[])([^\s\\'"]+))""",
    re.IGNORECASE,
)
SECRET_PARAM_NAMES = "password|passwd|pwd|apikey|api_key|secret|client_secret|access_token|token"
SECRET_QUERY = re.compile(rf"""([?&](?:{SECRET_PARAM_NAMES})=)(?![$<{{%'"`])([^&#\s'"`]+)""")
SECRET_WORD = r"(?:password|passwd|pwd|secret|token|api[_-]?key)"
SECRET_LITERAL = re.compile(
    rf"""(?i)({SECRET_WORD}[\w.-]*["']?\s*"""
    r"""(?:(?::\s*[A-Za-z_][\w.\[\]|, ]*?)?\s*(?:={1,3}|!==?|:=|=>)|:)\s*[rbfu]{0,2})"""
    r"""(["'`])((?:\\.|(?!\2)[^\\\n])+)\2"""
)
SECRET_ENV = re.compile(
    r"(\b[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY)[A-Z0-9_]*=)([^\s'\"`;&|]+)"
)
CODE_VALUE = re.compile(r"^(?:[$<{(\[]|(?:os|process|env|settings|config|self)\b)")


@dataclass(frozen=True)
class KeyHit:
    kind: str
    live: bool
    line: int


def secret_config() -> dict:
    return load("secrets.yaml")


@cache
def _patterns() -> list[tuple[str, bool, re.Pattern[str]]]:
    return [(p["kind"], p["live"], re.compile(p["regex"])) for p in secret_config()["key_patterns"]]


def public_prefix(name: str) -> str | None:
    for prefix in secret_config()["public_prefixes"]:
        if name.startswith(prefix):
            return prefix
    return None


def is_secret_name(name: str) -> bool:
    return any(word in name for word in secret_config()["secret_name_words"])


def _jwt_role(payload: str) -> str | None:
    try:
        decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        data = json.loads(decoded)
    except ValueError:
        return None
    role = data.get("role") if isinstance(data, dict) else None
    return role if isinstance(role, str) else None


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def find_keys(text: str) -> list[KeyHit]:
    hits: list[KeyHit] = []
    for kind, live, pattern in _patterns():
        hits.extend(KeyHit(kind, live, _line(text, m.start())) for m in pattern.finditer(text))
    for match in JWT.finditer(text):
        if _jwt_role(match.group(1)) == "service_role":
            hits.append(KeyHit("supabase-service-role-jwt", True, _line(text, match.start())))
    return sorted(hits, key=lambda h: (h.line, h.kind))


def _cli_secret(match: re.Match[str]) -> str:
    if match.group(2):
        return f"{match.group(1)}{match.group(2)}<redacted:password>{match.group(2)}"
    return f"{match.group(1)}<redacted:password>"


def _env_secret(match: re.Match[str]) -> str:
    if CODE_VALUE.match(match.group(2)):
        return match.group(0)
    return f"{match.group(1)}<redacted:secret>"


def redact(text: str) -> str:
    """Mask key patterns, service JWTs and credential shapes: URL passwords (with or without a
    user name), password flags on command lines, secret query parameter values, and literals
    assigned to password, secret, token or API key names."""
    for kind, _live, pattern in _patterns():
        text = pattern.sub(f"<redacted:{kind}>", text)
    text = JWT.sub("<redacted:jwt>", text)
    text = URL_CREDS.sub(r"\1<redacted:password>\3", text)
    text = CLI_SECRET.sub(_cli_secret, text)
    text = SECRET_QUERY.sub(r"\1<redacted:secret>", text)
    text = SECRET_LITERAL.sub(r"\1\2<redacted:secret>\2", text)
    return SECRET_ENV.sub(_env_secret, text)


def snippet(text: str, line: int, before: int = 0, after: int = 0, width: int = 200) -> str:
    """Up to five lines around `line`, each masked in full before it is cut to `width`."""
    lines = [item.removesuffix("\r") for item in text.split("\n")]
    start = max(line - 1 - before, 0)
    end = min(line + after, len(lines))
    return "\n".join(redact(item)[:width] for item in lines[start:end][:5])
