"""Find key-shaped strings and mask them. No function here returns a key value."""

from __future__ import annotations

import base64
import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from functools import cache

from dpr.data import load
from dpr.pii_values import DIGITS13, IBAN, MOBILE_TEXT, iban_valid, sa_id_valid

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
SECRET_PARAM_NAMES = (
    "password|passwd|pwd|pass|apikey|api_key|secret|client_secret|access_token|token"
)
SECRET_QUERY = re.compile(rf"""([?&](?:{SECRET_PARAM_NAMES})=)(?![$<{{%'"`])([^&#\s'"`]+)""")
SECRET_WORD = r"(?:password|passwd|pwd|secret|token|api[_-]?key|salt)"
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
# A literal default of an environment read whose name holds a secret, as the second argument,
# default=, or an `or` fallback: os.environ.get("API_KEY", "..."), getenv("X_PASSWORD") or "...".
ENV_DEFAULT = re.compile(
    r"(?i)((?:environ\.get|getenv|setdefault|\benv(?:\.\w{1,16})?|\bconfig)\([ \t]{0,8}"
    r"[\"'][\w.-]{0,64}(?:pass|pwd|secret|token|key|salt|credential)[\w.-]{0,64}[\"'][ \t]{0,8}"
    r"(?:,[ \t]{0,8}(?:default[ \t]{0,8}=[ \t]{0,8})?|\)[ \t]{0,8}or[ \t]{0,8}))(" + LITERAL + ")"
)
# The password of an auth=("user", "...") pair, and the credential of a literal Basic, Bearer or
# Token authorization value.
AUTH_PAIR = re.compile(
    r"(\bauth[ \t]{0,8}=[ \t]{0,8}[(\[][ \t]{0,8}"
    + LITERAL
    + r"[ \t]{0,8},[ \t]{0,8})("
    + LITERAL
    + ")"
)
AUTH_VALUE = re.compile(r"(?i)([\"'`](?:basic|bearer|token)[ \t]{1,8})([^\s\"'`{}$]{4,})")
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
EMAIL = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})"
)
PATH_TOKEN = "<redacted:path-token>"
UUID_TOKEN = re.compile(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}")
HEX_TOKEN = re.compile(r"[0-9a-f]{16,}|[0-9A-F]{16,}")
B64_TOKEN = re.compile(r"[A-Za-z0-9_-]{16,}")
CASE_WORD = re.compile(r"[A-Z]?[a-z]+|[A-Z]+|[0-9]+|[_-]+")
# A whole URL path segment of 16 or more token characters in snippet text: after a slash or
# before one.
PATH_SEGMENT = re.compile(r"(?<![\w-])(?:(?<=/)[\w-]{16,}|[\w-]{16,}(?=/))(?![\w-])", re.ASCII)


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


@cache
def _public_values() -> list[re.Pattern[str]]:
    return [re.compile(p + r"\Z") for p in secret_config()["public_value_patterns"]]


def is_public_value(value: str) -> bool:
    """True for a value that is public by design: a publishable key or a Supabase anon JWT.
    Such a value is safe in a tracked file even when its name carries no public prefix."""
    value = value.strip()
    if not value:
        return False
    if any(pattern.match(value) for pattern in _public_values()):
        return True
    match = JWT.fullmatch(value)
    return bool(match) and _jwt_role(match.group(1)) == "anon"


def has_token_phrase(name: str, phrase: str) -> bool:
    """True when `phrase`'s underscore-separated tokens appear contiguously in `name`'s tokens,
    case-insensitively: PASSWORD matches PASSWORD but not PASSWORDLESS. Never raises on a
    one-token or empty name."""
    tokens = name.upper().split("_")
    parts = phrase.upper().split("_")
    size = len(parts)
    return any(tokens[i : i + size] == parts for i in range(len(tokens) - size + 1))


def is_secret_name(name: str) -> bool:
    """A secret word matches whole underscore-separated tokens: PASSWORD, not PASSWORDLESS."""
    return any(has_token_phrase(name, word) for word in secret_config()["secret_name_words"])


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


def _entropy(text: str) -> float:
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def is_path_token(segment: str) -> bool:
    """A literal URL path segment that reads as a random secret (a capability URL): 16 or more
    characters of hex, a UUID, or base64url that switches case in short runs. Words,
    versions, numeric ids, slugs and parameters (`<int:pk>`, `:id`, `{id}`) are not."""
    if len(segment) < 16 or segment.isdigit():
        return False
    if UUID_TOKEN.fullmatch(segment):
        return True
    if HEX_TOKEN.fullmatch(segment):
        return any(c.isdigit() for c in segment) and _entropy(segment) >= 2.5
    if not B64_TOKEN.fullmatch(segment):
        return False
    # Random base64url breaks into short case runs; camelCase words and slugs into long ones.
    words = [w for w in CASE_WORD.findall(segment) if w[0].isalpha()]
    return (
        any(c.isupper() for c in segment)
        and any(c.islower() for c in segment)
        and sum(map(len, words)) < 3 * len(words)
        and _entropy(segment) >= 3.5
    )


def mask_path(path: str) -> str:
    """A route path with every secret-looking literal segment replaced by PATH_TOKEN."""
    return "/".join(PATH_TOKEN if is_path_token(part) else part for part in path.split("/"))


def redact(text: str) -> str:
    """Mask key patterns, service JWTs and credential shapes: URL passwords (with or without a
    user name), password flags on command lines, secret query parameter values (also a value
    concatenated as a separate literal), literals assigned to password, secret, token, API key or
    salt names, including adjacent, concatenated and triple-quoted literals, literal defaults of
    secret-named environment reads, auth=("user", "...") passwords and literal Basic, Bearer or
    Token authorization values, and secret-looking URL path segments (capability URLs). Every
    email address, South African mobile number, IBAN and ID number that passes its checks is
    masked too: a personal value is never printed."""
    for kind, _live, pattern in _patterns():
        text = pattern.sub(f"<redacted:{kind}>", text)
    text = JWT.sub("<redacted:jwt>", text)
    text = URL_CREDS.sub(r"\1<redacted:password>\3", text)
    text = CLI_SECRET.sub(_cli_secret, text)
    text = SECRET_QUERY.sub(r"\1<redacted:secret>", text)
    text = QUERY_QUOTED.sub(r"\1\2<redacted:secret>\2", text)
    text = QUERY_CONCAT.sub(lambda m: m.group(1) + _masked_literal(m.group(2)), text)
    text = ENV_DEFAULT.sub(lambda m: m.group(1) + _masked_literal(m.group(2)), text)
    text = AUTH_PAIR.sub(lambda m: m.group(1) + _masked_literal(m.group(2)), text)
    text = AUTH_VALUE.sub(r"\1<redacted:secret>", text)
    text = _mask_secret_literals(text)
    text = SECRET_ENV.sub(_env_secret, text)
    text = DIGITS13.sub(lambda m: "<redacted:id-number>" if sa_id_valid(m[0]) else m[0], text)
    text = IBAN.sub(lambda m: "<redacted:iban>" if iban_valid(m[0]) else m[0], text)
    text = MOBILE_TEXT.sub("<redacted:phone>", text)
    text = PATH_SEGMENT.sub(lambda m: PATH_TOKEN if is_path_token(m[0]) else m[0], text)
    return EMAIL.sub("<redacted:email>", text)


def snippet(text: str, line: int, before: int = 0, after: int = 0, width: int = 200) -> str:
    """Up to five lines around `line`, each masked in full before it is cut to `width`."""
    lines = [item.removesuffix("\r") for item in text.split("\n")]
    start = max(line - 1 - before, 0)
    end = min(line + after, len(lines))
    return "\n".join(redact(item)[:width] for item in lines[start:end][:5])
