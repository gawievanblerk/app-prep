"""Tables, policies, views, functions and storage buckets read from SQL."""

from __future__ import annotations

from dataclasses import dataclass

from dpr.model import Location

TRUE_WORDS = ("true", "t", "1", "yes", "on")


@dataclass(frozen=True)
class Column:
    name: str
    type: str
    unique: bool = False
    autoincrement: bool = False


@dataclass
class TableDef:
    key: str
    columns: list[Column]
    location: Location
    rls: bool = False
    rls_location: Location | None = None

    @property
    def schema(self) -> str:
        return self.key.split(".")[0]

    @property
    def name(self) -> str:
        return self.key.split(".", 1)[1]

    def column_names(self) -> list[str]:
        return [c.name for c in self.columns]


@dataclass(frozen=True)
class Policy:
    name: str
    table: str
    command: str
    roles: tuple[str, ...]
    roles_explicit: bool
    using: str | None
    with_check: str | None
    permissive: bool
    location: Location


@dataclass(frozen=True)
class View:
    key: str
    security_invoker: bool
    sources: tuple[str, ...]
    location: Location


@dataclass(frozen=True)
class Function:
    key: str
    security_definer: bool
    sets_search_path: bool
    tables: tuple[str, ...]
    location: Location


@dataclass(frozen=True)
class Bucket:
    id: str
    public: bool
    location: Location
