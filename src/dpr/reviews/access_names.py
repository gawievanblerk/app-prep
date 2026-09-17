"""Access levels, the Access record, and the name tests that decide what counts as auth."""

from __future__ import annotations

import re
from dataclasses import dataclass

PUBLIC, AUTHENTICATED, ADMIN = "public", "authenticated", "admin"
EXPLICIT, ABSENCE = "explicit", "absence"
AUTH_TOKEN = re.compile(
    r"auth[nz]?|authed|authenticated?|authentication|authenticator|authori[sz](?:e[ds]?|ation|er)"
    r"|users?|login|logged|sessions?|tokens?|principal|identity|staff|agents?|members?|accounts?"
    r"|verif(?:y|ied|ier|ication)|requires?|required|current|jwt|bearer|apikey|oauth"
    r"|protect(?:s|ed|ion|or)?|ensure[sd]?|passport"
)
ADMIN_WORD = re.compile(r"(?i)admin|superuser|super_user")
ROLE_WORDS = re.compile(
    r"admin|superuser|staff|manager|agent|member|client|customer|editor|viewer|owner|above|any"
)
DB_WORDS = frozenset({"db", "database", "session", "sessions", "conn", "connection"})
DB_FILLER = frozenset(
    {"get", "async", "sync", "sql", "orm", "dep", "local", "scoped", "yield", "new", "make",
     "create", "read", "write", "replica", "primary", "main", "default"}
)  # fmt: skip
PY_DEP = re.compile(r"(?:\w+\.)*(?:Depends|Security)")


@dataclass(frozen=True)
class Access:
    """How a route is guarded.

    `basis` is "explicit" when a marker was read (a guard, or a public marker such as AllowAny)
    and "absence" when the route is public only because no guard was found. `unread` names a
    global mechanism the classifier cannot read (an auth middleware class, a request hook,
    unknown app-level middleware) that may still guard a route whose answer rests on absence.
    """

    level: str
    subjects: tuple[str, ...] = ()
    evidence: str = ""
    basis: str = EXPLICIT
    unread: str = ""


def public(evidence: str, unread: str = "") -> Access:
    return Access(PUBLIC, (), evidence, ABSENCE, unread)


def unread_guard(level: Access) -> str | None:
    """proof_needed text when a public answer rests on absence and a global mechanism the
    classifier cannot read may still guard the route, else None."""
    if level.level != PUBLIC or level.basis != ABSENCE or not level.unread:
        return None
    return f"Confirm that {level.unread} does not already require a signed-in caller here."


def name_tokens(name: str) -> list[str]:
    """Lowercase snake and camel case words: getServerSession -> get, server, session."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    spaced = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", spaced)
    return [token.lower() for token in re.split(r"[^A-Za-z]+", spaced) if token]


def auth_name(name: str) -> bool:
    """True when a whole word of the name is an auth word (author and remember are not)."""
    tokens = name_tokens(name)
    if any(AUTH_TOKEN.fullmatch(token) for token in tokens):
        return True
    return any(a == "api" and b == "key" for a, b in zip(tokens, tokens[1:], strict=False))


def auth_middleware(name: str) -> bool:
    """A middleware class named for authentication. Session support alone is not a guard."""
    words = [t for t in name_tokens(name) if t not in ("middleware", "session", "sessions")]
    return auth_name(" ".join(words))


def database_dependency(name: str) -> bool:
    """Database session getters such as get_db, get_session or get_async_db_session."""
    tokens = set(name_tokens(name))
    return bool(tokens & DB_WORDS) and tokens <= DB_WORDS | DB_FILLER


def dep_level(name: str) -> str | None:
    if database_dependency(name):
        return None
    roles = set(ROLE_WORDS.findall(name.lower()))
    if roles and roles <= {"admin", "superuser", "staff"} and ADMIN_WORD.search(name):
        return ADMIN
    if auth_name(name) or ADMIN_WORD.search(name):
        return AUTHENTICATED
    return None


def strongest(levels: list[str]) -> str:
    if ADMIN in levels:
        return ADMIN
    return AUTHENTICATED if AUTHENTICATED in levels else PUBLIC
