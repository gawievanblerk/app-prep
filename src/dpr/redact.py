"""Find key-shaped strings and mask them. No function here returns a key value."""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from functools import cache

from dpr.data import load

JWT = re.compile(r"eyJ[0-9A-Za-z_-]{8,}\.(eyJ[0-9A-Za-z_-]{8,})\.[0-9A-Za-z_-]{8,}")
URL_CREDS = re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://[^\s/:@'\"]+:)([^\s/@'\"]+)(@)")


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


def redact(text: str) -> str:
    for kind, _live, pattern in _patterns():
        text = pattern.sub(f"<redacted:{kind}>", text)
    text = JWT.sub("<redacted:jwt>", text)
    return URL_CREDS.sub(r"\1<redacted:password>\3", text)


def snippet(text: str, line: int, before: int = 0, after: int = 0, width: int = 200) -> str:
    lines = text.splitlines()
    start = max(line - 1 - before, 0)
    end = min(line + after, len(lines))
    return "\n".join(redact(item)[:width] for item in lines[start:end][:5])
