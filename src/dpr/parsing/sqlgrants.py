"""GRANT and REVOKE statements on tables, schemas and sequences."""

from __future__ import annotations

import re
from dataclasses import dataclass

from dpr.model import Location
from dpr.parsing.sql import qualify, split_top_level

GRANT_PREFIX = re.compile(r"^(grant|revoke)\s+(?:grant\s+option\s+for\s+)?", re.S)
STANDALONE_ON = re.compile(r"(?<!\S)on(?!\S)", re.S)
STANDALONE_TO = re.compile(r"(?<!\S)to(?!\S)", re.S)
STANDALONE_FROM = re.compile(r"(?<!\S)from(?!\S)", re.S)
OBJECT_KIND = re.compile(
    r"^(?:(all\s+(?:tables|sequences|functions|routines)\s+in\s+schema)|table|schema|sequence"
    r"|database|function|procedure|routine|type|domain|foreign\s+table)?\s*(.*)$",
    re.S,
)
ROLE_TAIL = re.compile(
    r"\s+(?:with\s+(?:grant|admin)\s+option|granted\s+by\s+.*|cascade|restrict)\s*$"
)
PUBLIC_ROLES = ("anon", "authenticated", "public")


@dataclass(frozen=True)
class Grant:
    action: str  # "grant" | "revoke"
    privileges: tuple[str, ...]
    kind: str  # "table" | "all tables in schema" | "schema" | "sequence" | ...
    objects: tuple[str, ...]
    roles: tuple[str, ...]
    location: Location

    @property
    def to_public_role(self) -> bool:
        return any(role in PUBLIC_ROLES for role in self.roles)


def _last(pattern: re.Pattern[str], text: str) -> re.Match[str] | None:
    last = None
    for match in pattern.finditer(text):
        last = match
    return last


def parse_grant(norm: str, location: Location) -> Grant | None:
    """A grant or revoke on database objects. Role membership grants (no ON) return None.

    Runs in a single linear pass: an anchored prefix match, one forward scan for the first
    standalone ON, then one forward scan of the remainder for the last standalone TO/FROM.
    No nested unbounded quantifiers, so there is nothing to backtrack over.
    """
    prefix = GRANT_PREFIX.match(norm)
    if not prefix:
        return None
    action = prefix.group(1)
    after_action = norm[prefix.end() :]
    on_match = STANDALONE_ON.search(after_action)
    if not on_match:
        return None
    privileges = after_action[: on_match.start()]
    after_on = after_action[on_match.end() :]
    direction_pattern = STANDALONE_TO if action == "grant" else STANDALONE_FROM
    direction_match = _last(direction_pattern, after_on)
    if not direction_match:
        return None
    target = after_on[: direction_match.start()]
    roles = after_on[direction_match.end() :]
    if not target.strip() or not roles.strip():
        return None
    kind_match = OBJECT_KIND.match(target.strip())
    words = target.strip().split()
    kind = kind_match.group(1) if kind_match and kind_match.group(1) else ""
    if not kind:
        kind = (
            words[0]
            if words and words[0] in ("schema", "sequence", "database", "function")
            else "table"
        )
    rest = kind_match.group(2) if kind_match else target
    kind = re.sub(r"\s+", " ", kind)
    names = [n.strip() for n in split_top_level(rest) if n.strip()]
    objects = tuple(qualify(n) if kind == "table" else n.strip('"') for n in names)
    role_text = ROLE_TAIL.sub("", roles.strip())
    return Grant(
        action=action,
        privileges=tuple(p.strip() for p in privileges.split(",") if p.strip()),
        kind=kind,
        objects=objects,
        roles=tuple(r.strip().strip('"') for r in role_text.split(",") if r.strip()),
        location=location,
    )
