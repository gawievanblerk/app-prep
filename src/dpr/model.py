"""Shared data types for dpr."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class ScanError(Exception):
    """The scan itself could not run. The CLI maps this to exit code 2."""


class Tag(StrEnum):
    CONFIRMED = "CONFIRMED"
    INFERRED = "INFERRED"
    UNVERIFIED = "UNVERIFIED"
    UNKNOWN = "UNKNOWN"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Exploitability(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


NO_JSON = {"json": False}


@dataclass(frozen=True)
class Location:
    file: str
    line: int
    end_line: int | None = None

    def __str__(self) -> str:
        return f"{self.file}:{self.line}"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    review: str
    title: str
    tag: Tag
    severity: Severity
    exploitability: Exploitability
    effort_minutes: int
    locations: tuple[Location, ...]
    detail: str
    fix: str
    snippet: str | None = None
    proof_needed: str | None = None
    attack: str | None = None
    blast: str | None = None
    verify: str | None = None
    owasp: str | None = None
    source: str = "dpr"
    refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "tag", Tag(self.tag))
        object.__setattr__(self, "severity", Severity(self.severity))
        object.__setattr__(self, "exploitability", Exploitability(self.exploitability))
        object.__setattr__(self, "locations", tuple(self.locations))
        object.__setattr__(self, "refs", tuple(self.refs))
        if self.tag is Tag.UNKNOWN:
            raise ValueError(f"{self.rule_id}: UNKNOWN is for questions, not findings")
        if self.tag is Tag.CONFIRMED and not self.locations:
            raise ValueError(f"{self.rule_id}: CONFIRMED needs at least one location")
        if self.tag is Tag.INFERRED and not self.proof_needed:
            raise ValueError(f"{self.rule_id}: INFERRED needs proof_needed")


@dataclass(frozen=True)
class Field:
    name: str
    type: str
    location: Location
    unique: bool = False
    autoincrement: bool = False


@dataclass(frozen=True)
class DataModel:
    name: str
    table: str
    source: str  # "prisma" | "sql" | "django" | "sqlalchemy" | "drizzle"
    location: Location
    fields: tuple[Field, ...] = ()

    def field_names(self) -> list[str]:
        return [f.name for f in self.fields]


@dataclass(frozen=True)
class Route:
    method: str
    path: str
    file: str
    line: int
    framework: str
    is_public_form: bool = False
    wrappers: tuple[str, ...] = ()
    handler: object = field(default=None, compare=False, repr=False, metadata=NO_JSON)
    tree: object = field(default=None, compare=False, repr=False, metadata=NO_JSON)


@dataclass(frozen=True)
class EnvVar:
    name: str
    public: bool
    locations: tuple[Location, ...]


@dataclass(frozen=True)
class SdkUse:
    name: str
    category: str
    recipient: bool
    paid: bool
    locations: tuple[Location, ...]


@dataclass(frozen=True)
class GitInfo:
    is_repo: bool
    revision: str


@dataclass
class Detection:
    languages: dict[str, int] = field(default_factory=dict)
    frameworks: list[str] = field(default_factory=list)
    databases: list[str] = field(default_factory=list)
    orms: list[str] = field(default_factory=list)
    auth_providers: list[str] = field(default_factory=list)
    hosting: list[str] = field(default_factory=list)
    ci: list[str] = field(default_factory=list)
    logging: list[str] = field(default_factory=list)
    header_config: list[str] = field(default_factory=list)
    rate_limiters: list[str] = field(default_factory=list)
    test_frameworks: list[str] = field(default_factory=list)
    env_vars: list[EnvVar] = field(default_factory=list)
    sdks: list[SdkUse] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)
    models: list[DataModel] = field(default_factory=list)
    git: GitInfo = field(default_factory=lambda: GitInfo(False, "uncommitted working tree"))
    serverless: bool = False
    public_supabase_key: bool = False
    packages: set[str] = field(default_factory=set, metadata=NO_JSON)
    schema: object = field(default=None, metadata=NO_JSON)


@dataclass(frozen=True)
class Question:
    id: str
    reviews: tuple[str, ...]
    text: str
    type: str  # "choice" | "multi" | "text"
    why: str
    who: str
    options_from: str | None = None
    static_options: tuple[str, ...] = ()
    honest_out: tuple[str, ...] = ("Not sure",)
    answered_by: str | None = None
    lawyer: bool = False


@dataclass(frozen=True)
class QuestionResult:
    question: Question
    answer: str | None
    source: str  # "detection" | "answers" | "interactive" | "none"
    open: bool


@dataclass(frozen=True)
class Part:
    kind: str  # "table" | "text" | "findings"
    title: str
    columns: tuple[str, ...] = ()
    rows: tuple[tuple[str, ...], ...] = ()
    body: str = ""


@dataclass
class ReviewSection:
    review: str
    parts: list[Part] = field(default_factory=list)


@dataclass(frozen=True)
class ReportMeta:
    project: str
    scope: str
    revision: str
    date: str
    reviews_run: tuple[str, ...]
    method: str
    applicability: tuple[tuple[str, str], ...]


@dataclass
class Report:
    meta: ReportMeta
    detection: Detection
    findings: list[Finding]
    sections: dict[str, ReviewSection]
    questions: list[QuestionResult]
    not_covered: list[str]
