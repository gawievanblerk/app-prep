"""Find key-shaped strings and mask them. No function here returns a key value."""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from functools import cache

from dpr.data import load

JWT = re.compile(r"eyJ[0-9A-Za-z_-]{8,}\.(eyJ[0-9A-Za-z_-]{8,})\.[0-9A-Za-z_-]{8,}")
URL_CREDS = re.compile(r"((?<=[a-zA-Z0-9+.-])://[^\s/:@'\"]*:)([^\s/'\"]+)(@)")
CLI_PASSWORD = re.compile(
    r"--[\w-]{0,40}?pass(?:word|wd)?[ =](?![<$*{\[])([^\s\\'\"]+)", re.IGNORECASE
)
CLI_SECRET = re.compile(
    r"(--[\w-]{0,40}?(?:pass(?:word|wd)?|secret|token|api[_-]?key)[ =][ \t]{0,8})"
    r"(?:([\"'])([^\"'\n]+)\2|(?![<$*{\[])([^\s\\'\"]+))",
    re.IGNORECASE,
)
SECRET_PARAM_NAMES = "password|passwd|pwd|apikey|api_key|secret|client_secret|access_token|token"
SECRET_QUERY = re.compile(rf"""([?&](?:{SECRET_PARAM_NAMES})=)(?![$<{{%'"`])([^&#\s'"`]+)""")
SECRET_WORD = r"(?:password|passwd|pwd|secret|token|api[_-]?key)"
# One string literal: triple quoted (possibly running on past the line), or single, double or
# backtick quoted with escapes. Every repetition consumes a character, so matching is linear.
LITERAL = (
    r"[rbfuRBFU]{0,2}(?:"
    r'"{3}(?:[^"\\]|\\.|"(?!""))*(?:"{3}|$)'
    r"|'{3}(?:[^'\\]|\\.|'(?!''))*(?:'{3}|$)"
    r'|"(?:[^"\\\n]|\\.)*"'
    r"|'(?:[^'\\\n]|\\.)*'"
    r"|`(?:[^`\\\n]|\\.)*`)"
)
SECRET_LITERAL = re.compile(
    r"(?i)(" + SECRET_WORD + r"[\w.-]{0,64}[\"']?[ \t]{0,8}"
    r"(?:(?::[ \t]{0,8}[A-Za-z_][\w.\[\]|, ]{0,64}?)?[ \t]{0,8}(?:={1,3}|!==?|:=|=>)|:)"
    r"[ \t]{0,8})(" + LITERAL + ")"
)
NEXT_LITERAL = re.compile(r"([ \t]{0,8}\+?[ \t]{0,8})(" + LITERAL + ")")
QUERY_QUOTED = re.compile(r"([?&](?:" + SECRET_PARAM_NAMES + r")=)(['\"])([^'\"\s&#+]+)\2")
QUERY_CONCAT = re.compile(
    r"([?&](?:" + SECRET_PARAM_NAMES + r")=[\"'`][ \t]{0,8}\+[ \t]{0,8})(" + LITERAL + ")"
)
QUOTE = re.compile(r"""^([rbfuRBFU]{0,2})("{3}|'{3}|["'`])""")
SECRET_ENV = re.compile(
    r"(\b[A-Z0-9_]{0,64}(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY)[A-Z0-9_]{0,64}=)"
    r"([^\s'\"`;&|]+)"
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
    """A secret word matches whole underscore-separated tokens: PASSWORD, not PASSWORDLESS."""
    tokens = name.upper().split("_")
    for word in secret_config()["secret_name_words"]:
        parts = word.split("_")
        size = len(parts)
        if any(tokens[i : i + size] == parts for i in range(len(tokens) - size + 1)):
            return True
    return False


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


def _masked_literal(literal: str, kind: str = "secret") -> str:
    """A literal with its content replaced, keeping prefix and quotes. Empty literals stay."""
    match = QUOTE.match(literal)
    prefix, quote = match.groups() if match else ("", "")
    body = literal[len(prefix) + len(quote) :]
    closed = len(body) >= len(quote) and body.endswith(quote)
    content = body[: len(body) - len(quote)] if closed else body
    if not content:
        return literal
    return f"{prefix}{quote}<redacted:{kind}>{quote if closed else ''}"


def _in_query(text: str, start: int) -> bool:
    """The secret name is a URL query or form parameter (?api_key=), which the query patterns
    handle (a bare, quoted or concatenated value)."""
    begin = start
    while (
        begin > 0 and start - begin < 64 and (text[begin - 1].isalnum() or text[begin - 1] in "_.-")
    ):
        begin -= 1
    return begin > 0 and text[begin - 1] in "?&"


def _mask_secret_literals(text: str) -> str:
    """Literals assigned to secret names, and each literal joined to them by adjacency or +."""
    out: list[str] = []
    position = 0
    for match in SECRET_LITERAL.finditer(text):
        if match.start() < position or _in_query(text, match.start()):
            continue
        out += [text[position : match.start()], match.group(1), _masked_literal(match.group(2))]
        position = match.end()
        following = NEXT_LITERAL.match(text, position)
        while following is not None and following.end() > position:
            out += [following.group(1), _masked_literal(following.group(2))]
            position = following.end()
            following = NEXT_LITERAL.match(text, position)
    return "".join(out) + text[position:]


def redact(text: str) -> str:
    """Mask key patterns, service JWTs and credential shapes: URL passwords (with or without a
    user name), password flags on command lines, secret query parameter values (also a value
    concatenated as a separate literal), and literals assigned to password, secret, token or
    API key names, including adjacent, concatenated and triple-quoted literals."""
    for kind, _live, pattern in _patterns():
        text = pattern.sub(f"<redacted:{kind}>", text)
    text = JWT.sub("<redacted:jwt>", text)
    text = URL_CREDS.sub(r"\1<redacted:password>\3", text)
    text = CLI_SECRET.sub(_cli_secret, text)
    text = SECRET_QUERY.sub(r"\1<redacted:secret>", text)
    text = QUERY_QUOTED.sub(r"\1\2<redacted:secret>\2", text)
    text = QUERY_CONCAT.sub(lambda m: m.group(1) + _masked_literal(m.group(2)), text)
    text = _mask_secret_literals(text)
    return SECRET_ENV.sub(_env_secret, text)


def snippet(text: str, line: int, before: int = 0, after: int = 0, width: int = 200) -> str:
    """Up to five lines around `line`, each masked in full before it is cut to `width`."""
    lines = [item.removesuffix("\r") for item in text.split("\n")]
    start = max(line - 1 - before, 0)
    end = min(line + after, len(lines))
    return "\n".join(redact(item)[:width] for item in lines[start:end][:5])
