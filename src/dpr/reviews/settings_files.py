"""Which Python files are settings that production loads, and which setting names hold secrets."""

from __future__ import annotations

import re

from dpr.reviews.access_frameworks import non_production_settings
from dpr.reviews.paths import is_test
from dpr.rules import Context

SETTINGS_PATH = re.compile(r"(?:^|/)[\w-]*settings[\w-]*(?:/|\.py$)")
SECRET_WORDS = frozenset(
    {"SECRET", "PASSWORD", "PASSWD", "PWD", "PASS", "TOKEN", "SALT", "CREDENTIAL", "CREDENTIALS"}
)
KEY_WORDS = frozenset({"KEY", "KEYS", "APIKEY", "MEMKEY", "PRIVKEY"})
# A key named for what it looks up or where it lives is not a secret: SITE_KEY, HOST_KEY, S3_KEY.
PUBLIC_KEY_OWNERS = frozenset(
    {
        "SITE", "PUBLIC", "PUB", "PUBLISHABLE", "HOST", "CACHE", "SORT", "PRIMARY", "FOREIGN",
        "PARTITION", "OBJECT", "S3", "BUCKET", "LOOKUP", "SESSION", "REDIS", "STORAGE",
        "IDEMPOTENCY", "ROUTING", "QUEUE", "FILE", "MAP", "TRANSLATION", "LANGUAGE", "CONTEXT",
    }
)  # fmt: skip
# Words after the secret word that make the name about the secret, not the secret itself.
NOT_THE_SECRET = frozenset(
    {
        "URL", "URI", "ENDPOINT", "ID", "NAME", "TIMEOUT", "EXPIRY", "EXPIRES", "LENGTH", "PATH",
        "FILE", "DIR", "HEADER", "PREFIX", "TYPE", "MODE", "ENABLED", "LIFETIME", "AGE", "TTL",
        "DAYS", "HOURS", "MINUTES", "SECONDS", "VALIDATORS", "ALGORITHM", "FIELD", "VERSION",
        "FORMAT", "COUNT", "LIMIT", "SIZE", "MIN", "MAX", "REQUIRED", "RESET", "POLICY", "HASHERS",
        "BACKEND", "CLASS", "LOCATION", "FALLBACKS", "NAMES", "PARAM", "COOKIE", "HOST", "PORT",
    }
)  # fmt: skip
SIGNING = re.compile(
    r"(?:\w+_)?SECRET_KEY(?:_BASE)?|(?:\w+_)?SIGNING_KEY|JWT_SECRET\w*|SESSION_SECRET"
)


def settings_module(rel: str, text: str) -> bool:
    """A Django-style settings module: it holds INSTALLED_APPS, or its name or folder says so."""
    return "INSTALLED_APPS" in text or bool(SETTINGS_PATH.search(rel))


def production_file(ctx: Context, rel: str) -> bool:
    """Code production may load: not a test, not vendored, not a test, CI or local settings
    module (refinement 27)."""
    return not is_test(rel) and not non_production_settings(ctx, rel)


def secret_name(name: str) -> bool:
    """A setting or variable name that holds a secret: PASSWORD, API_KEY, STRATCOL_MEMKEY,
    HASHIDS_SALT, but not PASSWORD_RESET_TIMEOUT, RECAPTCHA_SITE_KEY or AWS_ACCESS_KEY_ID."""
    tokens = [t for t in re.split(r"[^A-Z0-9]+", name.upper()) if t]
    for i in range(len(tokens) - 1, -1, -1):
        word = tokens[i]
        is_key = word in KEY_WORDS or (word.endswith("KEY") and word.startswith("API"))
        if word not in SECRET_WORDS and not is_key:
            continue
        if any(t in NOT_THE_SECRET for t in tokens[i + 1 :]):
            return False
        return not (is_key and i > 0 and tokens[i - 1] in PUBLIC_KEY_OWNERS)
    return False


def signing_name(name: str) -> bool:
    """A key that signs sessions, reset links or tokens: SECRET_KEY, SIGNING_KEY, JWT_SECRET."""
    return bool(SIGNING.fullmatch(name.upper()))
