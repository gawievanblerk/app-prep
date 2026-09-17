# dpr Milestone 1 Implementation Plan: core, leaks, RLS

> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `dpr` package core plus the leaks and RLS reviews, runnable as `import dpr` and as `dpr scan`, with no LLM and no network in a default run.

**Architecture:** One pass walks the repo into a `RepoIndex`. Discovery builds a `Detection` from manifests, imports, env names, schemas and routes. Each review is a set of small registered check functions that return frozen `Finding` objects with an evidence tag. Findings are deduped, ranked by risk removed per minute, and rendered to Markdown and JSON.

**Tech Stack:** Python 3.12, uv, hatchling, tree-sitter with `tree-sitter-javascript` and `tree-sitter-typescript`, stdlib `ast`, PyYAML, Jinja2, pytest, ruff.

**Spec:** `docs/superpowers/specs/2026-09-16-dpr-design.md`

## Global Constraints

- Python `>=3.12`, managed with `uv`. Run every command through `uv run`.
- Layout `src/dpr/`, build backend `hatchling`.
- Runtime dependencies are exactly: `tree-sitter>=0.25`, `tree-sitter-javascript>=0.23`, `tree-sitter-typescript>=0.23`, `pyyaml>=6.0`, `jinja2>=3.1`. Dev: `pytest>=8`, `pytest-cov>=5`, `ruff>=0.6`. Nothing else.
- Never use `tree-sitter-language-pack` (downloads grammars at runtime).
- A default run (`semgrep="off"`, no `url`, no audits) opens no network connection.
- Never store or print a secret value. `.env*` files are read for names only; the text after `=` is discarded while reading.
- `Finding` with tag CONFIRMED must have a location. INFERRED must have `proof_needed`. UNKNOWN is never a finding.
- No legal verdict phrases anywhere in output or rule text: `compliant with`, `complies with`, `satisfies Article`, `satisfies Section`, `lawful basis is`.
- No em dash characters in code, rule text, templates, docs or commit messages.
- `dpr.review()` writes no files. Only the CLI writes.
- Tests run with `DPR_STRICT=1` (set in `tests/conftest.py`) so a failing rule raises.
- Ruff line length 100. Keep each module under about 400 lines.
- Git: work on `feature/dpr-scanner`. Commit after each task. No remote, no push. Commit messages are plain imperative sentences with no AI attribution and no `Co-Authored-By` line.
- Key-shaped test strings are assembled at runtime (for example `"sk_" + "live_" + ...`). Never commit a literal key-shaped string.

## Roadmap

- [x] **Milestone 1: core, leaks, RLS** (this plan, Tasks 1 to 29)
- [ ] **Milestone 2: baseline, abuse, own OWASP rules, SARIF, Django and FastAPI fixtures** (separate plan, written after Milestone 1 is merged into `develop`)
- [ ] **Milestone 3: Semgrep and audit adapters, inventory, auth test plan, Semgrep CI job, CI example, smoke runs, project contributor notes** (separate plan)

Milestone 1 also adds a basic `.github/workflows/ci.yml` (lint and tests). The spec places CI in Milestone 3; it moves earlier because every passing test must also run in CI.

## File map for Milestone 1

| File | Responsibility |
|---|---|
| `pyproject.toml`, `.python-version`, `.gitignore`, `README.md` | Project setup |
| `src/dpr/__init__.py` | Public exports |
| `src/dpr/model.py` | All shared dataclasses and enums, `ScanError` |
| `src/dpr/data/__init__.py` | Cached YAML loader for package data |
| `src/dpr/data/weights.yaml` | Ranking weights |
| `src/dpr/data/rule_text/*.yaml` | Title, effort, fix, attack, blast, verify, proof text per rule, one file per review task |
| `src/dpr/data/secrets.yaml` | Public prefixes, secret name words, key patterns |
| `src/dpr/data/stack.yaml` | Framework, database, ORM, auth, hosting, logging, limiter, test signals |
| `src/dpr/data/sdks.yaml` | SDK catalogue |
| `src/dpr/data/pii_terms.yaml` | Sensitive column words used by leaks severity (inventory extends it in Milestone 3) |
| `src/dpr/data/questions.yaml` | Question catalogue |
| `src/dpr/rank.py` | Score, dedupe, ordering |
| `src/dpr/rules.py` | Rule registry, `Context`, `Options`, `make_finding`, `run_checks` |
| `src/dpr/walk.py` | `RepoIndex`, file walking, sanity check, `line_of` |
| `src/dpr/redact.py` | Key detection and redaction |
| `src/dpr/gitutil.py` | Safe `git` subprocess helper |
| `src/dpr/parsing/jsts.py` | tree-sitter parsing and node helpers |
| `src/dpr/parsing/pyast.py` | Python `ast` helpers |
| `src/dpr/parsing/sql.py` | SQL statement splitter and top-level clause helpers |
| `src/dpr/parsing/sqlschema.py` | `SchemaState` built from SQL statements, migration loading, psql dump loading |
| `src/dpr/parsing/prisma.py` | `schema.prisma` parser |
| `src/dpr/parsing/schemas.py` | `DataModel` extraction for Prisma, SQL, Django, SQLAlchemy, Drizzle |
| `src/dpr/parsing/routes_js.py` | Next.js, Express, Fastify routes |
| `src/dpr/parsing/routes_py.py` | Django, DRF, FastAPI, Flask routes |
| `src/dpr/parsing/routes.py` | Route aggregation and public form flag |
| `src/dpr/discovery/packages.py` | Dependency names, import sites, env var names |
| `src/dpr/discovery/detect.py` | `detect(index) -> Detection` |
| `src/dpr/questions/catalogue.py` | Load, select, resolve answers, answers template |
| `src/dpr/questions/prompt.py` | Interactive prompts |
| `src/dpr/reviews/__init__.py` | Review registry, numbers, slugs |
| `src/dpr/reviews/leaks.py` | Leaks key and config checks, section |
| `src/dpr/reviews/leaks_code.py` | Leaks git, response and logging checks |
| `src/dpr/reviews/rls_common.py` | RLS schema state, owner detection, policy SQL |
| `src/dpr/reviews/rls.py` | RLS table, view, function and bucket checks, section |
| `src/dpr/reviews/rls_policies.py` | RLS policy defect checks |
| `src/dpr/api.py` | `review()` and `discover()` pipeline |
| `src/dpr/report/markdown.py`, `src/dpr/report/templates/report.md.j2` | Markdown report |
| `src/dpr/report/json_out.py` | JSON report |
| `src/dpr/cli.py` | `dpr scan`, `dpr questions` |
| `tests/...` | Unit, rule, fixture, safety tests |
| `tests/fixtures/next-supabase-bad/`, `tests/fixtures/next-supabase-good/` | Fixture apps |
| `tests/fixture_builder.py` | Copies a fixture to `tmp_path`, adds runtime secrets and git history |
| `.github/workflows/ci.yml` | Lint and tests |

The spec's layout lists `parsing/sql.py`, `parsing/routes.py`, `reviews/leaks.py` and `reviews/rls.py` as single files. They are split here to keep each file under about 400 lines. Rule text lives in one YAML file per review task, so no task edits another task's data file. No behaviour changes.

## How this plan was checked

Every code block in this plan was extracted into a scratch project and run before the plan was handed over: 149 tests passed, `ruff check` and `ruff format --check` were clean after `ruff format`, coverage was 96%, the wheel contained all YAML and template files, and `dpr scan` on the bad fixture reported 22 findings with exit code 1. Two points were also proven on a throwaway PostgreSQL 14.17 server: an UPDATE policy with only `USING` blocks moving a row to another owner, and a table with only a select policy denies client writes. That is why `RLS-WEAK-WITH-CHECK` replaces the skill's "missing WITH CHECK" rule.

## Refinements to the spec found while planning

- `RLS-POLICY-TRUE` and `RLS-AUTHENTICATED-NOT-OWNER` skip tables that have known columns but no owner or tenant column, so intentionally shared lookup tables are not reported. Tables known only from a `--db-dump` are still checked.
- The report's applicability list reads `Review 2, Database lock check: runs`, because `- 2. ...` renders as a nested numbered list in Markdown.
- `dpr.review()` takes an extra optional `today` date so tests get stable output.

---

### Task 1: Project scaffold

**Files:**
- Create: `pyproject.toml`, `.python-version` (via uv), `.gitignore`, `README.md`, `src/dpr/__init__.py`, `tests/__init__.py` (empty), `tests/conftest.py`, `tests/test_package.py`

**Interfaces:**
- Consumes: nothing
- Produces: installable package `dpr` with `dpr.__version__ == "0.1.0"`; `DPR_STRICT=1` in every test run

- [ ] **Step 1: Pin Python and write `pyproject.toml`**

Run: `cd "/Users/gawie/Active Projects/app-prep" && uv python pin 3.12`

Create `pyproject.toml`:

```toml
[project]
name = "dpr"
version = "0.1.0"
description = "Deterministic data protection review for JS/TS and Python repositories"
readme = "README.md"
requires-python = ">=3.12"
dependencies = [
    "tree-sitter>=0.25",
    "tree-sitter-javascript>=0.23",
    "tree-sitter-typescript>=0.23",
    "pyyaml>=6.0",
    "jinja2>=3.1",
]

[project.scripts]
dpr = "dpr.cli:main"

[dependency-groups]
dev = ["pytest>=8", "pytest-cov>=5", "ruff>=0.6"]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/dpr"]

[tool.ruff]
line-length = 100
target-version = "py312"
extend-exclude = ["tests/fixtures"]

[tool.ruff.lint]
select = ["E", "F", "I", "B", "UP"]

[tool.ruff.lint.per-file-ignores]
"tests/**" = ["E501"]

[tool.pytest.ini_options]
testpaths = ["tests"]
markers = ["semgrep: needs the semgrep binary"]
addopts = "-ra"
```

- [ ] **Step 2: Write `.gitignore` and `README.md`**

`.gitignore`:

```
.venv/
__pycache__/
*.pyc
.pytest_cache/
.ruff_cache/
.coverage
htmlcov/
/dist/
/build/
.DS_Store
data-protection-review/
dpr-answers.yaml
```

`README.md`:

````markdown
# dpr

Deterministic data protection review for JS/TS and Python repositories. No LLM.

```bash
uv sync
uv run dpr scan /path/to/repo
```

The report maps where personal data and weaknesses are. Keep it out of git.
This is an inventory of what the code shows, not legal advice.
````

- [ ] **Step 3: Write the failing test**

`tests/__init__.py`: empty file. It lets tests import shared helpers as `tests.<package>.<module>`.

`tests/conftest.py`:

```python
import os

os.environ["DPR_STRICT"] = "1"
```

`tests/test_package.py`:

```python
import dpr


def test_version():
    assert dpr.__version__ == "0.1.0"
```

- [ ] **Step 4: Run test to verify it fails**

Run: `uv sync && uv run pytest tests/test_package.py -v`
Expected: FAIL (`ModuleNotFoundError: No module named 'dpr'` or build error because `src/dpr` is missing)

- [ ] **Step 5: Create the package**

`src/dpr/__init__.py`:

```python
"""dpr: deterministic data protection review."""

__version__ = "0.1.0"
```

- [ ] **Step 6: Run test to verify it passes**

Run: `uv sync && uv run pytest tests/test_package.py -v && uv run ruff check`
Expected: PASS, ruff reports no errors

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml uv.lock .python-version .gitignore README.md src tests
git commit -m "Scaffold dpr package with uv, pytest and ruff"
```

---

### Task 2: Data model

**Files:**
- Create: `src/dpr/model.py`
- Test: `tests/test_model.py`

**Interfaces:**
- Consumes: nothing
- Produces (exact names used by every later task): `ScanError`, `Tag`, `Severity`, `Exploitability`, `NO_JSON`, `Location(file, line, end_line=None)`, `Finding(rule_id, review, title, tag, severity, exploitability, effort_minutes, locations, detail, fix, snippet=None, proof_needed=None, attack=None, blast=None, verify=None, owasp=None, source="dpr", refs=())`, `Field(name, type, location, unique=False, autoincrement=False)`, `DataModel(name, table, source, location, fields=())`, `Route(method, path, file, line, framework, is_public_form=False, handler=None, tree=None)`, `EnvVar(name, public, locations)`, `SdkUse(name, category, recipient, paid, locations)`, `GitInfo(is_repo, revision)`, `Detection(...)`, `Question(...)`, `QuestionResult(question, answer, source, open)`, `Part(kind, title, columns=(), rows=(), body="")`, `ReviewSection(review, parts=[])`, `ReportMeta(...)`, `Report(...)`

- [ ] **Step 1: Write the failing test**

`tests/test_model.py`:

```python
import dataclasses

import pytest

from dpr.model import Exploitability, Finding, Location, Severity, Tag


def make(**over):
    base = dict(
        rule_id="X-1",
        review="leaks",
        title="t",
        tag=Tag.CONFIRMED,
        severity=Severity.HIGH,
        exploitability=Exploitability.HIGH,
        effort_minutes=5,
        locations=(Location("a.ts", 3),),
        detail="d",
        fix="f",
    )
    base.update(over)
    return Finding(**base)


def test_confirmed_requires_location():
    with pytest.raises(ValueError, match="CONFIRMED"):
        make(locations=())


def test_inferred_requires_proof_needed():
    with pytest.raises(ValueError, match="proof_needed"):
        make(tag=Tag.INFERRED)
    assert make(tag=Tag.INFERRED, proof_needed="p").tag is Tag.INFERRED


def test_unknown_is_not_a_finding():
    with pytest.raises(ValueError, match="UNKNOWN"):
        make(tag=Tag.UNKNOWN)


def test_strings_are_coerced_to_enums():
    f = make(tag="CONFIRMED", severity="critical", exploitability="low")
    assert f.tag is Tag.CONFIRMED
    assert f.severity is Severity.CRITICAL
    assert f.exploitability is Exploitability.LOW


def test_finding_is_frozen():
    f = make()
    with pytest.raises(dataclasses.FrozenInstanceError):
        f.tag = Tag.INFERRED


def test_location_str():
    assert str(Location("src/a.ts", 12)) == "src/a.ts:12"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_model.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'dpr.model'`

- [ ] **Step 3: Write the implementation**

`src/dpr/model.py`:

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_model.py -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/model.py tests/test_model.py
git commit -m "Add shared data model with evidence tag validation"
```

---

### Task 3: Package data loader and ranking

**Files:**
- Create: `src/dpr/data/__init__.py`, `src/dpr/data/weights.yaml`, `src/dpr/rank.py`
- Test: `tests/test_rank.py`

**Interfaces:**
- Consumes: `Finding`, `Location`, `Tag`, `Severity`, `Exploitability` from Task 2
- Produces: `dpr.data.load(name: str) -> object` (cached YAML read of `src/dpr/data/<name>`); `dpr.rank.score(f: Finding) -> float`; `dpr.rank.dedupe(findings: list[Finding]) -> list[Finding]`; `dpr.rank.rank(findings) -> list[Finding]`; `dpr.rank.order_for_section(review: str, findings) -> list[Finding]`

- [ ] **Step 1: Write the failing test**

`tests/test_rank.py`:

```python
from dpr.model import Finding, Location
from dpr.rank import dedupe, order_for_section, rank, score


def f(
    rule_id="R",
    sev="high",
    expl="high",
    tag="CONFIRMED",
    effort=10,
    file="a.ts",
    line=1,
    owasp=None,
    source="dpr",
    review="leaks",
):
    return Finding(
        rule_id=rule_id,
        review=review,
        title=rule_id,
        tag=tag,
        severity=sev,
        exploitability=expl,
        effort_minutes=effort,
        locations=(Location(file, line),),
        detail="d",
        fix="x",
        proof_needed="p" if tag == "INFERRED" else None,
        owasp=owasp,
        source=source,
    )


def test_score_formula():
    # 40 (high) * 3 (high) * 1.0 (CONFIRMED) / 10 minutes
    assert score(f()) == 12.0
    # A01 boost 1.5, INFERRED factor 0.6
    assert score(f(tag="INFERRED", owasp="A01")) == 40 * 3 * 0.6 * 1.5 / 10


def test_effort_zero_counts_as_one_minute():
    assert score(f(effort=0)) == 120.0


def test_rank_orders_by_score_then_rule_id():
    low = f(rule_id="B", sev="low")
    crit = f(rule_id="A", sev="critical")
    assert [x.rule_id for x in rank([low, crit])] == ["A", "B"]


def test_dedupe_same_rule_same_line():
    assert len(dedupe([f(), f()])) == 1


def test_dedupe_keeps_different_rules_on_same_line():
    assert len(dedupe([f(rule_id="A", owasp="A01"), f(rule_id="B", owasp="A01")])) == 2


def test_semgrep_dropped_when_dpr_has_same_owasp_and_line():
    own = f(rule_id="OWN", owasp="A03")
    sg = f(rule_id="sg", owasp="A03", source="semgrep:python.sqli", tag="INFERRED")
    out = dedupe([sg, own])
    assert [x.rule_id for x in out] == ["OWN"]
    assert out[0].refs == ("semgrep:python.sqli",)


def test_semgrep_kept_when_no_match():
    sg = f(rule_id="sg", owasp="A03", source="semgrep:x", tag="INFERRED", line=9)
    assert len(dedupe([f(owasp="A03"), sg])) == 2


def test_leaks_section_order_puts_credentials_first():
    logged = f(rule_id="LEAK-LOGGED-PII", sev="critical", effort=1)
    key = f(rule_id="LEAK-PUBLIC-SECRET", sev="low", effort=100)
    ordered = order_for_section("leaks", [logged, key])
    assert [x.rule_id for x in ordered] == ["LEAK-PUBLIC-SECRET", "LEAK-LOGGED-PII"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_rank.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'dpr.rank'`

- [ ] **Step 3: Write the implementation**

`src/dpr/data/__init__.py`:

```python
"""Package data files (YAML)."""

from functools import cache
from importlib.resources import files

import yaml


@cache
def load(name: str) -> object:
    text = files("dpr.data").joinpath(name).read_text(encoding="utf-8")
    return yaml.safe_load(text)
```

`src/dpr/data/weights.yaml`:

```yaml
severity: {critical: 100, high: 40, medium: 10, low: 3}
exploitability: {high: 3, medium: 2, low: 1}
tag_factor: {CONFIRMED: 1.0, INFERRED: 0.6, UNVERIFIED: 0.4}
boost: {A01: 1.5}
leaks_order:
  - LEAK-PUBLIC-SECRET
  - LEAK-HARDCODED-KEY
  - LEAK-KEY-IN-BUILD
  - LEAK-ENV-TRACKED
  - LEAK-ENV-IN-HISTORY
  - LEAK-BROAD-RESPONSE
  - LEAK-SSR-PROPS
  - LEAK-LOGGED-PII
```

`src/dpr/rank.py`:

```python
"""Risk removed per minute: scoring, dedupe and ordering."""

from __future__ import annotations

from dataclasses import replace

from dpr.data import load
from dpr.model import Finding


def score(f: Finding) -> float:
    w = load("weights.yaml")
    value = w["severity"][f.severity.value] * w["exploitability"][f.exploitability.value]
    value *= w["tag_factor"][f.tag.value]
    value *= w["boost"].get(f.owasp or "", 1.0)
    return value / max(f.effort_minutes, 1)


def _first(f: Finding) -> tuple[str, int]:
    if not f.locations:
        return ("", 0)
    return (f.locations[0].file, f.locations[0].line)


def dedupe(findings: list[Finding]) -> list[Finding]:
    own: list[Finding] = []
    seen: set[tuple[str, str, int]] = set()
    for item in findings:
        if item.source != "dpr":
            continue
        key = (item.rule_id, *_first(item))
        if key in seen:
            continue
        seen.add(key)
        own.append(item)

    by_owasp: dict[tuple[str, str, int], int] = {}
    for i, item in enumerate(own):
        if item.owasp:
            by_owasp.setdefault((item.owasp, *_first(item)), i)

    external: list[Finding] = []
    for item in findings:
        if item.source == "dpr":
            continue
        key = (item.owasp or "", *_first(item))
        if item.owasp and key in by_owasp:
            i = by_owasp[key]
            own[i] = replace(own[i], refs=own[i].refs + (item.source,))
            continue
        external.append(item)
    return own + external


def _key(f: Finding) -> tuple:
    return (-score(f), f.rule_id, *_first(f))


def rank(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=_key)


def order_for_section(review: str, findings: list[Finding]) -> list[Finding]:
    items = [f for f in findings if f.review == review]
    if review != "leaks":
        return rank(items)
    order = {rule_id: i for i, rule_id in enumerate(load("weights.yaml")["leaks_order"])}
    return sorted(items, key=lambda f: (order.get(f.rule_id, len(order)), *_key(f)))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_rank.py -v`
Expected: PASS (8 tests)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/data src/dpr/rank.py tests/test_rank.py
git commit -m "Add ranking by risk removed per minute and finding dedupe"
```

---

### Task 4: Rule registry and run context

**Files:**
- Create: `src/dpr/rules.py`
- Test: `tests/test_rules.py`

**Interfaces:**
- Consumes: `dpr.data.load`; model types from Task 2
- Produces:
  - `Options(url=None, owns_host=False, login_path=None, with_audit=False, semgrep="auto", db_dump=None)`
  - `Context(index, detection, answers={}, options=Options(), facts={}, not_covered=[])`
  - `RuleSpec(rule_id, review, severity, exploitability, owasp=None)`
  - `rule(rule_id, *, review, severity, exploitability, owasp=None)` decorator for `fn(ctx: Context) -> Iterable[Finding]`
  - `SPECS: dict[str, RuleSpec]`, `CHECKS: dict[str, list[tuple[str, Callable]]]`
  - `rule_text(rule_id) -> RuleText(title, effort_minutes, fix, detail="", proof_needed=None, attack=None, blast=None, verify=None)`. Text is merged from every `src/dpr/data/rule_text/*.yaml` file (one file per review task), so later tasks add a file instead of editing a shared one.
  - `make_finding(rule_id, *, tag, locations, detail=None, snippet=None, severity=None, exploitability=None, fix=None, proof_needed=None, attack=None, blast=None, verify=None, refs=(), **fmt) -> Finding`. Text fields use `string.Template` placeholders like `${name}` filled from `fmt` with `safe_substitute`. `proof_needed` is dropped unless the tag is INFERRED.
  - `run_checks(review: str, ctx: Context) -> list[Finding]`: runs every check of a review; an exception re-raises when `DPR_STRICT=1`, else appends `rule <id> failed: <ExceptionType>` to `ctx.not_covered`

- [ ] **Step 1: Write the failing test**

`tests/test_rules.py`:

```python
import pytest

from dpr import rules
from dpr.model import Detection, Location, Tag

TEXT = {
    "T-ONE": {
        "title": "Key ${name} exposed",
        "effort_minutes": 5,
        "detail": "Found ${name}.",
        "fix": "Rename ${name}. Keep $ANON_KEY as is.",
        "proof_needed": "Check it.",
    },
    "T-BOOM": {"title": "boom", "effort_minutes": 1, "fix": "none"},
}


@pytest.fixture
def registry(monkeypatch):
    monkeypatch.setattr(rules, "SPECS", {})
    monkeypatch.setattr(rules, "CHECKS", {})
    monkeypatch.setattr(rules, "_OWNERS", {})
    monkeypatch.setattr(rules, "_all_rule_text", lambda: TEXT)
    return rules


def ctx():
    return rules.Context(index=None, detection=Detection())


def test_make_finding_fills_text_and_defaults(registry):
    @registry.rule("T-ONE", review="leaks", severity="high", exploitability="medium")
    def check(c):
        yield registry.make_finding(
            "T-ONE", tag="CONFIRMED", locations=[Location("a.ts", 2)], name="NEXT_PUBLIC_X"
        )

    [finding] = registry.run_checks("leaks", ctx())
    assert finding.title == "Key NEXT_PUBLIC_X exposed"
    assert finding.detail == "Found NEXT_PUBLIC_X."
    assert finding.fix == "Rename NEXT_PUBLIC_X. Keep $ANON_KEY as is."
    assert finding.severity.value == "high"
    assert finding.effort_minutes == 5
    assert finding.proof_needed is None  # CONFIRMED drops proof text
    assert finding.review == "leaks"


def test_inferred_keeps_proof_needed(registry):
    registry.rule("T-ONE", review="leaks", severity="low", exploitability="low")(lambda c: [])
    finding = registry.make_finding("T-ONE", tag=Tag.INFERRED, locations=[], name="Y")
    assert finding.proof_needed == "Check it."


def test_severity_override(registry):
    registry.rule("T-ONE", review="leaks", severity="low", exploitability="low")(lambda c: [])
    finding = registry.make_finding(
        "T-ONE", tag="CONFIRMED", locations=[Location("a", 1)], severity="critical", name="Z"
    )
    assert finding.severity.value == "critical"


def test_duplicate_rule_id_from_other_function_raises(registry):
    registry.rule("T-ONE", review="leaks", severity="low", exploitability="low")(lambda c: [])
    with pytest.raises(ValueError, match="duplicate"):

        @registry.rule("T-ONE", review="leaks", severity="low", exploitability="low")
        def other(c):
            return []


def test_failing_rule_raises_in_strict_mode(registry):
    @registry.rule("T-BOOM", review="leaks", severity="low", exploitability="low")
    def boom(c):
        raise RuntimeError("x")

    with pytest.raises(RuntimeError):
        registry.run_checks("leaks", ctx())


def test_failing_rule_is_recorded_when_not_strict(registry, monkeypatch):
    monkeypatch.delenv("DPR_STRICT")

    @registry.rule("T-BOOM", review="leaks", severity="low", exploitability="low")
    def boom(c):
        raise RuntimeError("x")

    c = ctx()
    assert registry.run_checks("leaks", c) == []
    assert c.not_covered == ["rule T-BOOM failed: RuntimeError"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_rules.py -v`
Expected: FAIL with `ImportError: cannot import name 'rules' from 'dpr'`

- [ ] **Step 3: Write the implementation**

`src/dpr/rules.py`:

```python
"""Rule registry, rule text and the shared run context."""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from functools import cache
from importlib.resources import files
from string import Template

from dpr.data import load
from dpr.model import Detection, Exploitability, Finding, QuestionResult, Severity, Tag


@dataclass(frozen=True)
class RuleSpec:
    rule_id: str
    review: str
    severity: Severity
    exploitability: Exploitability
    owasp: str | None = None


@dataclass
class Options:
    url: str | None = None
    owns_host: bool = False
    login_path: str | None = None
    with_audit: bool = False
    semgrep: str = "auto"
    db_dump: str | None = None


@dataclass
class Context:
    index: object  # dpr.walk.RepoIndex
    detection: Detection
    answers: dict[str, QuestionResult] = field(default_factory=dict)
    options: Options = field(default_factory=Options)
    facts: dict[str, object] = field(default_factory=dict)
    not_covered: list[str] = field(default_factory=list)


CheckFn = Callable[[Context], Iterable[Finding]]
SPECS: dict[str, RuleSpec] = {}
CHECKS: dict[str, list[tuple[str, CheckFn]]] = {}
_OWNERS: dict[str, str] = {}


def rule(
    rule_id: str, *, review: str, severity: str, exploitability: str, owasp: str | None = None
) -> Callable[[CheckFn], CheckFn]:
    def wrap(fn: CheckFn) -> CheckFn:
        owner = f"{getattr(fn, '__module__', '')}.{getattr(fn, '__qualname__', '')}"
        if rule_id in _OWNERS:
            if _OWNERS[rule_id] != owner or owner.endswith("<lambda>"):
                raise ValueError(f"duplicate rule id {rule_id}")
            return fn
        _OWNERS[rule_id] = owner
        SPECS[rule_id] = RuleSpec(
            rule_id, review, Severity(severity), Exploitability(exploitability), owasp
        )
        CHECKS.setdefault(review, []).append((rule_id, fn))
        return fn

    return wrap


@dataclass(frozen=True)
class RuleText:
    title: str
    effort_minutes: int
    fix: str
    detail: str = ""
    proof_needed: str | None = None
    attack: str | None = None
    blast: str | None = None
    verify: str | None = None


@cache
def _all_rule_text() -> dict:
    merged: dict = {}
    folder = files("dpr.data").joinpath("rule_text")
    if folder.is_dir():
        for item in sorted(folder.iterdir(), key=lambda entry: entry.name):
            if item.name.endswith(".yaml"):
                merged.update(load(f"rule_text/{item.name}") or {})
    return merged


def rule_text(rule_id: str) -> RuleText:
    data = _all_rule_text()
    if rule_id not in data:
        raise KeyError(f"no rule text for {rule_id}")
    return RuleText(**data[rule_id])


def _fill(value: str | None, fmt: dict[str, object]) -> str | None:
    if value is None:
        return None
    return Template(value).safe_substitute({k: str(v) for k, v in fmt.items()})


def make_finding(
    rule_id: str,
    *,
    tag: Tag | str,
    locations: Iterable,
    detail: str | None = None,
    snippet: str | None = None,
    severity: str | None = None,
    exploitability: str | None = None,
    fix: str | None = None,
    proof_needed: str | None = None,
    attack: str | None = None,
    blast: str | None = None,
    verify: str | None = None,
    refs: Iterable[str] = (),
    **fmt: object,
) -> Finding:
    spec = SPECS[rule_id]
    text = rule_text(rule_id)
    tag = Tag(tag)
    proof = proof_needed if proof_needed is not None else _fill(text.proof_needed, fmt)
    return Finding(
        rule_id=rule_id,
        review=spec.review,
        title=_fill(text.title, fmt) or rule_id,
        tag=tag,
        severity=Severity(severity or spec.severity),
        exploitability=Exploitability(exploitability or spec.exploitability),
        effort_minutes=text.effort_minutes,
        locations=tuple(locations),
        detail=detail if detail is not None else (_fill(text.detail, fmt) or ""),
        fix=fix if fix is not None else (_fill(text.fix, fmt) or ""),
        snippet=snippet,
        proof_needed=proof if tag is Tag.INFERRED else None,
        attack=attack if attack is not None else _fill(text.attack, fmt),
        blast=blast if blast is not None else _fill(text.blast, fmt),
        verify=verify if verify is not None else _fill(text.verify, fmt),
        owasp=spec.owasp,
        refs=tuple(refs),
    )


def run_checks(review: str, ctx: Context) -> list[Finding]:
    found: list[Finding] = []
    for rule_id, fn in CHECKS.get(review, []):
        try:
            found.extend(fn(ctx))
        except Exception as exc:
            if os.environ.get("DPR_STRICT") == "1":
                raise
            ctx.not_covered.append(f"rule {rule_id} failed: {type(exc).__name__}")
    return found
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_rules.py -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/rules.py tests/test_rules.py
git commit -m "Add rule registry, rule text templates and strict-mode rule runner"
```

---

### Task 5: Repository walker

**Files:**
- Create: `src/dpr/walk.py`
- Test: `tests/test_walk.py`

**Interfaces:**
- Consumes: `ScanError` from Task 2
- Produces:
  - `SourceFile(rel: str, path: Path, size: int)` with properties `name`, `suffix`
  - `RepoIndex(root)` with attributes `root: Path`, `files`, `build_files`, `env_files` (lists of `SourceFile`), `skipped: list[str]`, `cache: dict[tuple[str, str], object]`
  - `RepoIndex.text(rel) -> str` (raises `ValueError` for env files), `with_suffix(*suffixes) -> list[SourceFile]`, `glob(*patterns) -> list[SourceFile]` (fnmatch on `rel`), `named(*patterns) -> list[SourceFile]` (fnmatch on basename), `js_files`, `py_files` (properties), `env_names(entry) -> list[tuple[str, int]]`, `language_counts() -> dict[str, int]`, `sanity_check() -> None`
  - `line_of(text: str, pos: int) -> int`, `is_env_file(name: str) -> bool`, constants `JS_EXTS`, `PY_EXTS`

- [ ] **Step 1: Write the failing test**

`tests/test_walk.py`:

```python
import os

import pytest

from dpr.model import ScanError
from dpr.walk import RepoIndex, is_env_file, line_of


def write(root, rel, text="x", mode="w"):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if mode == "wb":
        path.write_bytes(text)
    else:
        path.write_text(text)
    return path


def rels(entries):
    return sorted(e.rel for e in entries)


def test_skips_dependency_and_vcs_dirs(tmp_path):
    write(tmp_path, "src/app.ts", "const a = 1")
    write(tmp_path, "node_modules/lib/index.js")
    write(tmp_path, "packages/web/node_modules/x.js")
    write(tmp_path, ".git/config")
    write(tmp_path, ".venv/lib/site.py")
    index = RepoIndex(tmp_path)
    assert rels(index.files) == ["src/app.ts"]


def test_build_output_is_indexed_separately(tmp_path):
    write(tmp_path, "src/app.ts")
    write(tmp_path, "dist/main.js", "bundle")
    write(tmp_path, ".next/static/chunks/a.js", "chunk")
    write(tmp_path, ".next/cache/big.bin", "cache")
    index = RepoIndex(tmp_path)
    assert rels(index.files) == ["src/app.ts"]
    assert rels(index.build_files) == [".next/static/chunks/a.js", "dist/main.js"]


def test_env_files_are_listed_but_never_read_as_text(tmp_path):
    write(tmp_path, "a.py")
    write(tmp_path, ".env", "SECRET_THING=value-that-must-not-leak\n")
    write(tmp_path, "apps/web/.env.local", "export NEXT_PUBLIC_X = 1\n# comment\nBAD LINE\n")
    index = RepoIndex(tmp_path)
    assert rels(index.env_files) == [".env", "apps/web/.env.local"]
    assert rels(index.files) == ["a.py"]
    with pytest.raises(ValueError):
        index.text(".env")
    names = index.env_names(next(e for e in index.env_files if e.rel == "apps/web/.env.local"))
    assert names == [("NEXT_PUBLIC_X", 1)]
    assert "value-that-must-not-leak" not in repr(index.env_names(index.env_files[0]))


def test_large_and_binary_files(tmp_path):
    write(tmp_path, "a.py")
    write(tmp_path, "big.js", "a" * 1_000_001)
    write(tmp_path, "img.png", b"\x89PNG\x00\x00", mode="wb")
    index = RepoIndex(tmp_path)
    assert rels(index.files) == ["a.py"]
    assert index.skipped == ["big.js: larger than 1 MB"]


def test_symlinks_are_not_followed(tmp_path):
    outside = tmp_path / "outside"
    write(outside, "secret.py")
    repo = tmp_path / "repo"
    write(repo, "a.py")
    os.symlink(outside, repo / "linked")
    os.symlink(outside / "secret.py", repo / "link.py")
    index = RepoIndex(repo)
    assert rels(index.files) == ["a.py"]


def test_sanity_check_package_json_without_js(tmp_path):
    write(tmp_path, "package.json", "{}")
    write(tmp_path, "README.md")
    with pytest.raises(ScanError, match="package.json"):
        RepoIndex(tmp_path).sanity_check()
    write(tmp_path, "src/index.ts")
    RepoIndex(tmp_path).sanity_check()


def test_sanity_check_requirements_without_python(tmp_path):
    write(tmp_path, "requirements-dev.txt", "pytest")
    with pytest.raises(ScanError, match="Python"):
        RepoIndex(tmp_path).sanity_check()


def test_missing_root(tmp_path):
    with pytest.raises(ScanError):
        RepoIndex(tmp_path / "nope")


def test_helpers(tmp_path):
    write(tmp_path, "app/api/x/route.ts")
    write(tmp_path, "app/page.tsx")
    write(tmp_path, "svc/models.py")
    index = RepoIndex(tmp_path)
    assert rels(index.glob("app/api/*")) == ["app/api/x/route.ts"]
    assert rels(index.named("models.py")) == ["svc/models.py"]
    assert rels(index.with_suffix(".tsx")) == ["app/page.tsx"]
    assert index.language_counts() == {"javascript/typescript": 2, "python": 1}
    assert line_of("a\nb\nc", 2) == 2
    assert is_env_file(".env.production") and not is_env_file("env.ts")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_walk.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'dpr.walk'`

- [ ] **Step 3: Write the implementation**

`src/dpr/walk.py`:

```python
"""Walk a repository once into a RepoIndex."""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass
from pathlib import Path

from dpr.model import ScanError

SKIP_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        ".next",
        "dist",
        "build",
        "out",
        "vendor",
        ".venv",
        "venv",
        "__pycache__",
        ".turbo",
        "coverage",
        ".pytest_cache",
        ".mypy_cache",
        "data-protection-review",
    }
)
BUILD_DIR_NAMES = frozenset({"dist", "build", "out"})
SOURCE_MAX_BYTES = 1_000_000
BUILD_MAX_BYTES = 10_000_000
JS_EXTS = frozenset(
    {
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".mts",
        ".cts",
        ".vue",
        ".svelte",
    }
)
PY_EXTS = frozenset({".py"})
ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")


@dataclass(frozen=True)
class SourceFile:
    rel: str
    path: Path
    size: int

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def suffix(self) -> str:
        return self.path.suffix.lower()


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def is_env_file(name: str) -> bool:
    return name == ".env" or name.startswith(".env.")


def _is_binary(path: Path) -> bool:
    with path.open("rb") as fh:
        return b"\0" in fh.read(8192)


class RepoIndex:
    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            raise ScanError(f"path is not a directory: {root}")
        self.files: list[SourceFile] = []
        self.build_files: list[SourceFile] = []
        self.env_files: list[SourceFile] = []
        self.skipped: list[str] = []
        self.cache: dict[tuple[str, str], object] = {}
        self._text: dict[str, str] = {}
        self._walk()

    def _rel(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def _walk(self) -> None:
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            current = Path(dirpath)
            keep: list[str] = []
            for name in sorted(dirnames):
                sub = current / name
                if sub.is_symlink():
                    continue
                if name in BUILD_DIR_NAMES:
                    self._walk_build(sub)
                elif name == ".next":
                    if (sub / "static").is_dir():
                        self._walk_build(sub / "static")
                elif name not in SKIP_DIRS:
                    keep.append(name)
            dirnames[:] = keep
            for name in sorted(filenames):
                self._add(current / name)

    def _add(self, path: Path) -> None:
        if path.is_symlink():
            return
        rel = self._rel(path)
        size = path.stat().st_size
        entry = SourceFile(rel, path, size)
        if is_env_file(path.name):
            self.env_files.append(entry)
            return
        if size > SOURCE_MAX_BYTES:
            self.skipped.append(f"{rel}: larger than 1 MB")
            return
        if _is_binary(path):
            return
        self.files.append(entry)

    def _walk_build(self, top: Path) -> None:
        for dirpath, dirnames, filenames in os.walk(top, followlinks=False):
            current = Path(dirpath)
            dirnames[:] = sorted(
                d for d in dirnames if d != "node_modules" and not (current / d).is_symlink()
            )
            for name in sorted(filenames):
                path = current / name
                if path.is_symlink():
                    continue
                size = path.stat().st_size
                if size > BUILD_MAX_BYTES:
                    self.skipped.append(f"{self._rel(path)}: build file larger than 10 MB")
                    continue
                if not _is_binary(path):
                    self.build_files.append(SourceFile(self._rel(path), path, size))

    def text(self, rel: str) -> str:
        if is_env_file(Path(rel).name):
            raise ValueError("env files are read for variable names only")
        if rel not in self._text:
            self._text[rel] = (self.root / rel).read_text(encoding="utf-8", errors="replace")
        return self._text[rel]

    def with_suffix(self, *suffixes: str) -> list[SourceFile]:
        wanted = {s.lower() for s in suffixes}
        return [f for f in self.files if f.suffix in wanted]

    def glob(self, *patterns: str) -> list[SourceFile]:
        return [f for f in self.files if any(fnmatch.fnmatch(f.rel, p) for p in patterns)]

    def named(self, *patterns: str) -> list[SourceFile]:
        return [f for f in self.files if any(fnmatch.fnmatch(f.name, p) for p in patterns)]

    @property
    def js_files(self) -> list[SourceFile]:
        return [f for f in self.files if f.suffix in JS_EXTS]

    @property
    def py_files(self) -> list[SourceFile]:
        return [f for f in self.files if f.suffix in PY_EXTS]

    def env_names(self, entry: SourceFile) -> list[tuple[str, int]]:
        names: list[tuple[str, int]] = []
        with entry.path.open("r", encoding="utf-8", errors="replace") as fh:
            for number, raw in enumerate(fh, start=1):
                match = ENV_LINE.match(raw)
                if match:
                    names.append((match.group(1), number))
        return names

    def language_counts(self) -> dict[str, int]:
        counts = {"javascript/typescript": len(self.js_files), "python": len(self.py_files)}
        return {k: v for k, v in counts.items() if v}

    def sanity_check(self) -> None:
        names = {f.name for f in self.files}
        if "package.json" in names and not self.js_files:
            raise ScanError(
                "package.json found but no JS/TS files were indexed; the scan would read nothing"
            )
        has_py_manifest = "pyproject.toml" in names or any(
            fnmatch.fnmatch(n, "requirements*.txt") for n in names
        )
        if has_py_manifest and not self.py_files:
            raise ScanError(
                "Python manifest found but no .py files were indexed; the scan would read nothing"
            )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_walk.py -v`
Expected: PASS (9 tests)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/walk.py tests/test_walk.py
git commit -m "Add repository walker with build, env and empty-scan handling"
```

---

### Task 6: Key detection and redaction

**Files:**
- Create: `src/dpr/data/secrets.yaml`, `src/dpr/redact.py`
- Test: `tests/test_redact.py`

**Interfaces:**
- Consumes: `dpr.data.load`
- Produces:
  - `KeyHit(kind: str, live: bool, line: int)`. It has no field for the key value.
  - `find_keys(text: str) -> list[KeyHit]` (sorted by line, kind)
  - `redact(text: str) -> str` (masks key patterns, every JWT, and passwords in URLs)
  - `snippet(text: str, line: int, before=0, after=0, width=200) -> str` (redacted, at most 5 lines)
  - `secret_config() -> dict` returning the parsed `secrets.yaml` (`public_prefixes`, `secret_name_words`, `key_patterns`)
  - `public_prefix(name: str) -> str | None`, `is_secret_name(name: str) -> bool`

- [ ] **Step 1: Write the failing test**

`tests/test_redact.py`:

```python
import base64
import dataclasses
import json

from dpr.redact import KeyHit, find_keys, is_secret_name, public_prefix, redact, snippet

LIVE = "sk_" + "live_" + "a1B2c3D4e5F6g7H8i9J0k1L2"
TEST = "sk_" + "test_" + "a1B2c3D4e5F6g7H8i9J0k1L2"
AWS = "AKIA" + "ABCDEFGHIJKLMNOP"


def b64(obj):
    raw = json.dumps(obj).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def jwt(role):
    return ".".join([b64({"alg": "HS256", "typ": "JWT"}), b64({"role": role}), "s1gnature_part"])


def test_keyhit_has_no_value_field():
    assert [f.name for f in dataclasses.fields(KeyHit)] == ["kind", "live", "line"]


def test_find_keys_kinds_and_lines():
    text = f'const a = "{LIVE}"\nconst b = "{TEST}"\n\naws = "{AWS}"\n'
    hits = find_keys(text)
    assert [(h.kind, h.live, h.line) for h in hits] == [
        ("stripe-live-secret", True, 1),
        ("stripe-test-secret", False, 2),
        ("aws-access-key-id", True, 4),
    ]


def test_service_role_jwt_is_flagged_but_anon_is_not():
    text = f'const s = "{jwt("service_role")}"\nconst a = "{jwt("anon")}"\n'
    hits = find_keys(text)
    assert [(h.kind, h.line) for h in hits] == [("supabase-service-role-jwt", 1)]


def test_redact_masks_keys_jwts_and_url_passwords():
    text = f'k="{LIVE}" j="{jwt("anon")}" db="postgres://app:hunter2secret@db.local/x"'
    out = redact(text)
    assert LIVE not in out
    assert "hunter2secret" not in out
    assert "eyJ" not in out
    assert "<redacted:stripe-live-secret>" in out
    assert "postgres://app:<redacted:password>@db.local/x" in out


def test_snippet_is_redacted_capped_and_trimmed():
    lines = [f"line{i} {LIVE}" for i in range(10)]
    out = snippet("\n".join(lines), line=3, before=2, after=5)
    assert LIVE not in out
    assert len(out.splitlines()) == 5
    assert len(snippet("x" * 500, 1).splitlines()[0]) == 200


def test_names():
    assert public_prefix("NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY") == "NEXT_PUBLIC_"
    assert public_prefix("SUPABASE_SERVICE_ROLE_KEY") is None
    assert is_secret_name("NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY")
    assert is_secret_name("VITE_OPENAI_API_KEY")
    assert not is_secret_name("NEXT_PUBLIC_SUPABASE_ANON_KEY")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_redact.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'dpr.redact'`

- [ ] **Step 3: Write the implementation**

`src/dpr/data/secrets.yaml`:

```yaml
public_prefixes: [NEXT_PUBLIC_, NUXT_PUBLIC_, EXPO_PUBLIC_, REACT_APP_, GATSBY_, VITE_, PUBLIC_]
secret_name_words:
  - SERVICE_ROLE
  - SECRET
  - PRIVATE
  - ADMIN
  - WEBHOOK_SECRET
  - DATABASE_URL
  - DB_URL
  - SMTP
  - PASSWORD
  - OPENAI_API_KEY
  - ANTHROPIC_API_KEY
  - AWS_SECRET
  - ACCESS_KEY
key_patterns:
  - {kind: stripe-live-secret, live: true, regex: 'sk_live_[0-9A-Za-z]{10,}'}
  - {kind: stripe-live-restricted, live: true, regex: 'rk_live_[0-9A-Za-z]{10,}'}
  - {kind: stripe-test-secret, live: false, regex: 'sk_test_[0-9A-Za-z]{10,}'}
  - {kind: supabase-secret, live: true, regex: 'sb_secret_[0-9A-Za-z_-]{10,}'}
  - {kind: slack-token, live: true, regex: 'xox[baprs]-[0-9A-Za-z-]{10,}'}
  - {kind: aws-access-key-id, live: true, regex: 'AKIA[0-9A-Z]{16}'}
  - {kind: github-token, live: true, regex: '(?:ghp|gho)_[0-9A-Za-z]{36}'}
  - {kind: github-pat, live: true, regex: 'github_pat_[0-9A-Za-z_]{22,}'}
  - {kind: google-api-key, live: true, regex: 'AIza[0-9A-Za-z_-]{35}'}
```

`src/dpr/redact.py`:

```python
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
```

Note: `json.JSONDecodeError`, `binascii.Error` and `UnicodeDecodeError` are all subclasses of `ValueError`, so one `except ValueError` covers bad base64, bad UTF-8 and bad JSON.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_redact.py -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/data/secrets.yaml src/dpr/redact.py tests/test_redact.py
git commit -m "Add key detection and redaction that never returns key values"
```

---

### Task 7: JS/TS parser helpers

**Files:**
- Create: `src/dpr/parsing/__init__.py` (empty), `src/dpr/parsing/jsts.py`
- Test: `tests/parsing/__init__.py` (empty), `tests/parsing/test_jsts.py`

**Interfaces:**
- Consumes: `RepoIndex` from Task 5
- Produces (all in `dpr.parsing.jsts`):
  - `JsTree(rel: str, root: Node, source: bytes, line_offset: int, tree: object)`
  - `FUNCTION_TYPES: frozenset[str]`
  - `grammar_for(rel) -> "javascript" | "typescript" | "tsx"`
  - `script_blocks(text) -> list[tuple[code, line_offset, grammar]]`
  - `parse_source(rel, code, grammar=None, line_offset=0) -> JsTree`
  - `parse_file(index, rel) -> list[JsTree]` (cached in `index.cache[("js", rel)]`; `.vue`/`.svelte` give one tree per `<script>` block)
  - `node_text(node) -> str`, `line(tree, node) -> int` (1-based, includes offset)
  - `walk(node, types=None) -> Iterator[Node]` (pre-order)
  - `callee(call) -> str` (function text without whitespace, e.g. `prisma.user.findUnique`, `cookies().set`)
  - `calls(tree, pattern, within=None) -> Iterator[Node]` (call_expression nodes whose callee fully matches)
  - `arguments(call) -> list[Node]`
  - `unwrap(node) -> Node | None` (strips await, parentheses, `as`, `!`, `satisfies`)
  - `object_pairs(obj) -> dict[str, Node]`, `has_spread(obj) -> bool`
  - `string_value(node) -> str | None`
  - `enclosing_function(node) -> Node | None`
  - `exported_functions(tree) -> dict[str, Node]` (named exports plus `"default"`)
  - `resolve_identifier(ident) -> Node | None` (value of the nearest earlier `const/let/var` with that name in the same function or program, unwrapped)
  - `has_directive(tree, directive="use server") -> bool`
  - `member_root(node) -> str | None` (`req.body.email` gives `req`)

- [ ] **Step 1: Write the failing test**

`tests/parsing/__init__.py`: empty file.

`tests/parsing/test_jsts.py`:

```python
from dpr.parsing import jsts
from dpr.walk import RepoIndex

ROUTE = """import { prisma } from "@/lib/db"

export async function GET(req: Request, { params }: { params: { id: string } }) {
  const invoice = await prisma.invoice.findUnique({ where: { id: params.id } })
  return NextResponse.json(invoice)
}

export const POST = async (req) => {
  const body = await req.json()
  return Response.json({ ok: true, ...body })
}
"""


def tree(code=ROUTE, rel="app/api/x/route.ts"):
    return jsts.parse_source(rel, code)


def test_grammar_for():
    assert jsts.grammar_for("a.ts") == "typescript"
    assert jsts.grammar_for("a.tsx") == "tsx"
    assert jsts.grammar_for("a.jsx") == "javascript"


def test_calls_callee_and_line():
    t = tree()
    [call] = list(jsts.calls(t, r"prisma\.\w+\.findUnique"))
    assert jsts.callee(call) == "prisma.invoice.findUnique"
    assert jsts.line(t, call) == 4


def test_object_pairs_and_spread():
    t = tree()
    [call] = list(jsts.calls(t, r"prisma\.\w+\.findUnique"))
    [arg] = jsts.arguments(call)
    pairs = jsts.object_pairs(arg)
    assert list(pairs) == ["where"]
    assert list(jsts.object_pairs(pairs["where"])) == ["id"]
    [resp] = list(jsts.calls(t, r"Response\.json"))
    obj = jsts.arguments(resp)[0]
    assert jsts.has_spread(obj)
    assert list(jsts.object_pairs(obj)) == ["ok"]


def test_string_value():
    t = tree("a('x'); b(\"y\"); c(`z`); d(`${v}`); e(1)", rel="a.js")
    values = [jsts.string_value(jsts.arguments(c)[0]) for c in jsts.calls(t, r"[a-e]")]
    assert values == ["x", "y", "z", None, None]


def test_exported_functions_and_default():
    t = tree(ROUTE + "\nexport default function handler(req, res) {}\n")
    exported = jsts.exported_functions(t)
    assert sorted(exported) == ["GET", "POST", "default", "handler"]
    assert exported["POST"].type == "arrow_function"


def test_default_export_of_identifier():
    t = tree("function handler(req, res) {}\nexport default handler\n", rel="pages/api/a.js")
    assert jsts.exported_functions(t)["default"].type == "function_declaration"


def test_resolve_identifier_and_enclosing_function():
    t = tree()
    [resp] = list(jsts.calls(t, r"NextResponse\.json"))
    ident = jsts.arguments(resp)[0]
    value = jsts.resolve_identifier(ident)
    assert value.type == "call_expression"
    assert jsts.callee(value) == "prisma.invoice.findUnique"
    fn = jsts.enclosing_function(resp)
    assert fn.type == "function_declaration"


def test_member_root():
    t = tree("log(req.body.email); log(user); log(a[0].b)", rel="a.js")
    roots = [jsts.member_root(jsts.arguments(c)[0]) for c in jsts.calls(t, "log")]
    assert roots == ["req", "user", "a"]


def test_has_directive():
    assert jsts.has_directive(tree('"use server"\nexport async function a() {}', rel="a.ts"))
    assert not jsts.has_directive(tree("import x from 'y'\n'use server'", rel="a.ts"))


def test_vue_script_blocks_keep_file_line_numbers(tmp_path):
    (tmp_path / "C.vue").write_text(
        "<template>\n  <div/>\n</template>\n"
        '<script setup lang="ts">\nconst a = fetchIt()\n</script>\n'
    )
    index = RepoIndex(tmp_path)
    [t] = jsts.parse_file(index, "C.vue")
    [call] = list(jsts.calls(t, "fetchIt"))
    assert jsts.line(t, call) == 5
    assert jsts.parse_file(index, "C.vue") is jsts.parse_file(index, "C.vue")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/parsing/test_jsts.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'dpr.parsing'`

- [ ] **Step 3: Write the implementation**

`src/dpr/parsing/__init__.py`: empty file.

`src/dpr/parsing/jsts.py`:

```python
"""tree-sitter parsing for JavaScript and TypeScript, plus small node helpers."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from functools import cache

import tree_sitter_javascript
import tree_sitter_typescript
from tree_sitter import Language, Node, Parser

from dpr.walk import RepoIndex

FUNCTION_TYPES = frozenset(
    {
        "function_declaration",
        "generator_function_declaration",
        "function_expression",
        "function",
        "arrow_function",
        "method_definition",
    }
)
WRAPPERS = frozenset(
    {
        "await_expression",
        "parenthesized_expression",
        "as_expression",
        "non_null_expression",
        "satisfies_expression",
        "type_assertion",
    }
)
SCRIPT_BLOCK = re.compile(r"<script\b([^>]*)>(.*?)</script>", re.DOTALL | re.IGNORECASE)


@dataclass(frozen=True)
class JsTree:
    rel: str
    root: Node
    source: bytes
    line_offset: int
    tree: object


@cache
def _parser(grammar: str) -> Parser:
    if grammar == "javascript":
        return Parser(Language(tree_sitter_javascript.language()))
    if grammar == "typescript":
        return Parser(Language(tree_sitter_typescript.language_typescript()))
    if grammar == "tsx":
        return Parser(Language(tree_sitter_typescript.language_tsx()))
    raise ValueError(f"unknown grammar {grammar}")


def grammar_for(rel: str) -> str:
    lower = rel.lower()
    if lower.endswith((".ts", ".mts", ".cts")):
        return "typescript"
    if lower.endswith(".tsx"):
        return "tsx"
    return "javascript"


def script_blocks(text: str) -> list[tuple[str, int, str]]:
    blocks = []
    for match in SCRIPT_BLOCK.finditer(text):
        is_ts = re.search(r"lang\s*=\s*['\"]ts['\"]", match.group(1))
        offset = text.count("\n", 0, match.start(2))
        blocks.append((match.group(2), offset, "typescript" if is_ts else "javascript"))
    return blocks


def parse_source(rel: str, code: str, grammar: str | None = None, line_offset: int = 0) -> JsTree:
    source = code.encode("utf-8")
    parsed = _parser(grammar or grammar_for(rel)).parse(source)
    return JsTree(rel, parsed.root_node, source, line_offset, parsed)


def parse_file(index: RepoIndex, rel: str) -> list[JsTree]:
    key = ("js", rel)
    if key not in index.cache:
        text = index.text(rel)
        if rel.lower().endswith((".vue", ".svelte")):
            trees = [parse_source(rel, c, g, o) for c, o, g in script_blocks(text)]
        else:
            trees = [parse_source(rel, text)]
        index.cache[key] = trees
    return index.cache[key]


def node_text(node: Node | None) -> str:
    if node is None or node.text is None:
        return ""
    return node.text.decode("utf-8", errors="replace")


def line(tree: JsTree, node: Node) -> int:
    return node.start_point.row + 1 + tree.line_offset


def walk(node: Node, types: frozenset[str] | set[str] | None = None) -> Iterator[Node]:
    stack = [node]
    while stack:
        current = stack.pop()
        if types is None or current.type in types:
            yield current
        stack.extend(reversed(current.children))


def callee(call: Node) -> str:
    return re.sub(r"\s+", "", node_text(call.child_by_field_name("function")))


def calls(
    tree: JsTree, pattern: str | re.Pattern[str], within: Node | None = None
) -> Iterator[Node]:
    regex = re.compile(pattern) if isinstance(pattern, str) else pattern
    for node in walk(within or tree.root, {"call_expression"}):
        if regex.fullmatch(callee(node)):
            yield node


def arguments(call: Node) -> list[Node]:
    args = call.child_by_field_name("arguments")
    if args is None:
        return []
    return [child for child in args.named_children if child.type != "comment"]


def unwrap(node: Node | None) -> Node | None:
    while node is not None and node.type in WRAPPERS:
        named = [c for c in node.named_children if c.type != "comment"]
        node = named[0] if named else None
    return node


def string_value(node: Node | None) -> str | None:
    node = unwrap(node)
    if node is None:
        return None
    if node.type == "string":
        parts = [c for c in node.named_children if c.type in ("string_fragment", "escape_sequence")]
        return "".join(node_text(c) for c in parts)
    if node.type == "template_string":
        if any(c.type == "template_substitution" for c in node.named_children):
            return None
        return node_text(node)[1:-1]
    return None


def object_pairs(obj: Node | None) -> dict[str, Node]:
    pairs: dict[str, Node] = {}
    obj = unwrap(obj)
    if obj is None or obj.type != "object":
        return pairs
    for child in obj.named_children:
        if child.type == "pair":
            key = child.child_by_field_name("key")
            name = string_value(key) if key.type == "string" else node_text(key)
            pairs[name or ""] = child.child_by_field_name("value")
        elif child.type == "shorthand_property_identifier":
            pairs[node_text(child)] = child
        elif child.type == "method_definition":
            pairs[node_text(child.child_by_field_name("name"))] = child
    return pairs


def has_spread(obj: Node | None) -> bool:
    obj = unwrap(obj)
    return obj is not None and any(c.type == "spread_element" for c in obj.named_children)


def enclosing_function(node: Node) -> Node | None:
    current = node.parent
    while current is not None:
        if current.type in FUNCTION_TYPES:
            return current
        current = current.parent
    return None


def _top_level_function(root: Node, name: str) -> Node | None:
    for stmt in root.named_children:
        if stmt.type in ("function_declaration", "generator_function_declaration"):
            if node_text(stmt.child_by_field_name("name")) == name:
                return stmt
        if stmt.type in ("lexical_declaration", "variable_declaration"):
            for decl in stmt.named_children:
                value = unwrap(decl.child_by_field_name("value"))
                if node_text(decl.child_by_field_name("name")) == name and value is not None:
                    if value.type in FUNCTION_TYPES:
                        return value
    return None


def exported_functions(tree: JsTree) -> dict[str, Node]:
    found: dict[str, Node] = {}
    for stmt in tree.root.named_children:
        if stmt.type != "export_statement":
            continue
        is_default = any(c.type == "default" for c in stmt.children)
        decl = stmt.child_by_field_name("declaration")
        named_function = ("function_declaration", "generator_function_declaration")
        if decl is not None and decl.type in named_function:
            found[node_text(decl.child_by_field_name("name"))] = decl
            if is_default:
                found["default"] = decl
        elif decl is not None and decl.type in ("lexical_declaration", "variable_declaration"):
            for item in decl.named_children:
                value = unwrap(item.child_by_field_name("value"))
                if item.type == "variable_declarator" and value is not None:
                    if value.type in FUNCTION_TYPES:
                        found[node_text(item.child_by_field_name("name"))] = value
        elif is_default:
            value = unwrap(stmt.child_by_field_name("value"))
            if value is not None and value.type in FUNCTION_TYPES:
                found["default"] = value
            elif value is not None and value.type == "identifier":
                target = _top_level_function(tree.root, node_text(value))
                if target is not None:
                    found["default"] = target
    return found


def resolve_identifier(ident: Node) -> Node | None:
    name = node_text(ident)
    scope = enclosing_function(ident)
    if scope is None:
        scope = ident
        while scope.parent is not None:
            scope = scope.parent
    best = None
    for decl in walk(scope, {"variable_declarator"}):
        target = decl.child_by_field_name("name")
        if target is None or target.type != "identifier" or node_text(target) != name:
            continue
        if decl.start_byte < ident.start_byte:
            best = decl.child_by_field_name("value")
    return unwrap(best)


def has_directive(tree: JsTree, directive: str = "use server") -> bool:
    for stmt in tree.root.named_children:
        if stmt.type == "comment":
            continue
        if stmt.type == "expression_statement" and stmt.named_children:
            return string_value(stmt.named_children[0]) == directive
        return False
    return False


def member_root(node: Node | None) -> str | None:
    node = unwrap(node)
    while node is not None and node.type in ("member_expression", "subscript_expression"):
        node = unwrap(node.child_by_field_name("object"))
    if node is not None and node.type == "identifier":
        return node_text(node)
    return None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/parsing/test_jsts.py -v`
Expected: PASS (10 tests)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/parsing tests/parsing
git commit -m "Add tree-sitter JS/TS parsing helpers with Vue and Svelte script offsets"
```

---

### Task 8: Python ast helpers

**Files:**
- Create: `src/dpr/parsing/pyast.py`
- Test: `tests/parsing/test_pyast.py`

**Interfaces:**
- Consumes: `RepoIndex` from Task 5
- Produces (all in `dpr.parsing.pyast`):
  - `parse_file(index, rel) -> ast.Module | None` (cached in `index.cache[("py", rel)]`; syntax errors add `"<rel>: Python syntax could not be parsed"` to `index.skipped` and return `None`)
  - `dotted(node) -> str | None` (`a.b.c`; a call inside becomes `name()`, e.g. `cookies().set`)
  - `calls(tree, pattern, within=None) -> Iterator[ast.Call]` (sorted by line and column)
  - `kwarg(call, name) -> ast.expr | None`
  - `MISSING` sentinel and `constant(node, default=MISSING) -> object`
  - `functions(tree) -> list[ast.FunctionDef | ast.AsyncFunctionDef]`
  - `function_at(tree, lineno) -> ast.FunctionDef | ast.AsyncFunctionDef | None` (innermost)
  - `class_defs(tree) -> list[ast.ClassDef]`, `base_names(cls) -> list[str]`
  - `assignments(body) -> dict[str, ast.expr]` (simple `name = value` and `name: T = value`)
  - `name_root(node) -> str | None` (`request.GET.get("url")` gives `request`)
  - `names_in(node) -> set[str]`

- [ ] **Step 1: Write the failing test**

`tests/parsing/test_pyast.py`:

```python
import ast

from dpr.parsing import pyast
from dpr.walk import RepoIndex

CODE = """
from django.db import models

class Invoice(models.Model):
    amount = models.IntegerField(unique=True)
    note: str = "x"

    class Meta:
        db_table = "billing_invoice"

def view(request, pk):
    def inner():
        return requests.get(request.GET.get("url"))
    return cookies().set("sid", "v")
"""


def tree():
    return ast.parse(CODE)


def test_dotted_and_calls():
    t = tree()
    names = [pyast.dotted(c.func) for c in pyast.calls(t, r".*")]
    assert names == [
        "models.IntegerField",
        "requests.get",
        "request.GET.get",
        "cookies().set",
        "cookies",
    ]
    assert [c.lineno for c in pyast.calls(t, r"requests\.get")] == [13]


def test_kwarg_and_constant():
    [call] = list(pyast.calls(tree(), r"models\.IntegerField"))
    assert pyast.constant(pyast.kwarg(call, "unique")) is True
    assert pyast.kwarg(call, "null") is None
    assert pyast.constant(call.func, default="nope") == "nope"


def test_classes_bases_assignments():
    [cls] = [c for c in pyast.class_defs(tree()) if c.name == "Invoice"]
    assert pyast.base_names(cls) == ["models.Model"]
    body = pyast.assignments(cls.body)
    assert sorted(body) == ["amount", "note"]
    meta = next(n for n in cls.body if isinstance(n, ast.ClassDef))
    assert pyast.constant(pyast.assignments(meta.body)["db_table"]) == "billing_invoice"


def test_function_at_is_innermost():
    t = tree()
    assert pyast.function_at(t, 13).name == "inner"
    assert pyast.function_at(t, 14).name == "view"
    assert pyast.function_at(t, 2) is None
    assert [f.name for f in pyast.functions(t)] == ["view", "inner"]


def test_name_root_and_names_in():
    [call] = list(pyast.calls(tree(), r"requests\.get"))
    assert pyast.name_root(call.args[0]) == "request"
    assert {"request", "requests"} <= pyast.names_in(call)


def test_parse_file_caches_and_records_syntax_errors(tmp_path):
    (tmp_path / "ok.py").write_text("x = 1\n")
    (tmp_path / "bad.py").write_text("print 'py2'\n")
    index = RepoIndex(tmp_path)
    assert pyast.parse_file(index, "ok.py") is pyast.parse_file(index, "ok.py")
    assert pyast.parse_file(index, "bad.py") is None
    assert index.skipped == ["bad.py: Python syntax could not be parsed"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/parsing/test_pyast.py -v`
Expected: FAIL with `ImportError: cannot import name 'pyast'`

- [ ] **Step 3: Write the implementation**

`src/dpr/parsing/pyast.py`:

```python
"""Python ast parsing and small helpers."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.walk import RepoIndex

MISSING = object()
FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


def parse_file(index: RepoIndex, rel: str) -> ast.Module | None:
    key = ("py", rel)
    if key not in index.cache:
        try:
            index.cache[key] = ast.parse(index.text(rel), filename=rel)
        except (SyntaxError, ValueError):
            index.cache[key] = None
            index.skipped.append(f"{rel}: Python syntax could not be parsed")
    return index.cache[key]


def dotted(node: ast.AST | None) -> str | None:
    parts: list[str] = []
    while True:
        if isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        elif isinstance(node, ast.Name):
            parts.append(node.id)
            break
        elif isinstance(node, ast.Call):
            inner = dotted(node.func)
            if inner is None:
                return None
            parts.append(inner + "()")
            break
        else:
            return None
    return ".".join(reversed(parts))


def calls(
    tree: ast.AST, pattern: str | re.Pattern[str], within: ast.AST | None = None
) -> Iterator[ast.Call]:
    regex = re.compile(pattern) if isinstance(pattern, str) else pattern
    found = []
    for node in ast.walk(within or tree):
        if isinstance(node, ast.Call):
            name = dotted(node.func)
            if name is not None and regex.fullmatch(name):
                found.append(node)
    found.sort(key=lambda n: (n.lineno, n.col_offset))
    yield from found


def kwarg(call: ast.Call, name: str) -> ast.expr | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def constant(node: ast.AST | None, default: object = MISSING) -> object:
    return node.value if isinstance(node, ast.Constant) else default


def functions(tree: ast.AST) -> list[FunctionNode]:
    found = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)]
    return sorted(found, key=lambda n: (n.lineno, n.col_offset))


def function_at(tree: ast.AST, lineno: int) -> FunctionNode | None:
    best = None
    for fn in functions(tree):
        end = fn.end_lineno or fn.lineno
        if fn.lineno <= lineno <= end and (best is None or fn.lineno >= best.lineno):
            best = fn
    return best


def class_defs(tree: ast.AST) -> list[ast.ClassDef]:
    found = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
    return sorted(found, key=lambda n: n.lineno)


def base_names(cls: ast.ClassDef) -> list[str]:
    return [dotted(base) or "" for base in cls.bases]


def assignments(body: list[ast.stmt]) -> dict[str, ast.expr]:
    found: dict[str, ast.expr] = {}
    for stmt in body:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    found[target.id] = stmt.value
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            if stmt.value is not None:
                found[stmt.target.id] = stmt.value
    return found


def name_root(node: ast.AST | None) -> str | None:
    while isinstance(node, ast.Attribute | ast.Subscript | ast.Call):
        node = node.func if isinstance(node, ast.Call) else node.value
    return node.id if isinstance(node, ast.Name) else None


def names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/parsing/test_pyast.py -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/parsing/pyast.py tests/parsing/test_pyast.py
git commit -m "Add Python ast helpers"
```

---

### Task 9: SQL statement splitter

**Files:**
- Create: `src/dpr/parsing/sql.py`
- Test: `tests/parsing/test_sql.py`

**Interfaces:**
- Consumes: nothing
- Produces (all in `dpr.parsing.sql`):
  - `Statement(text: str, norm: str, line: int)`. `norm` is lowercased outside single and double quotes (dollar-quoted bodies are lowercased too), comments become spaces, whitespace collapsed. `line` is the 1-based line of the first non-comment character.
  - `split_sql(sql: str) -> list[Statement]`
  - `IDENT`, `QNAME` regex fragments (for normalised text)
  - `find_top_level(s, keyword_regex, start=0) -> int` (index at paren depth 0, outside quotes, on a word boundary, or `-1`)
  - `balanced(s, open_index) -> tuple[str, int]` (inner text of the parenthesis at `open_index`, index after the closing one)
  - `split_top_level(s, sep=",") -> list[str]`
  - `qualify(name, default_schema="public") -> str` (`"public"."Docs"` gives `public.Docs`; `docs` gives `public.docs`)
  - `clean_predicate(p) -> str` (strips whitespace and redundant outer parentheses)

- [ ] **Step 1: Write the failing test**

`tests/parsing/test_sql.py`:

```python
from dpr.parsing.sql import (
    balanced,
    clean_predicate,
    find_top_level,
    qualify,
    split_sql,
    split_top_level,
)


def test_split_basic_lines_and_norm():
    stmts = split_sql("CREATE TABLE A (id int);\n\n  ALTER   TABLE a\n ENABLE ROW LEVEL SECURITY;")
    assert [s.line for s in stmts] == [1, 3]
    assert stmts[0].norm == "create table a (id int)"
    assert stmts[1].norm == "alter table a enable row level security"


def test_semicolons_inside_quotes_comments_and_dollar_bodies():
    sql = (
        "-- leading comment; not a statement\n"
        "insert into t values ('a;b', 'it''s');\n"
        '/* block /* nested; */ still; */ select "Mixed;Case" from t;\n'
        "create function f() returns int as $$ select 1; select 2; $$ language sql;\n"
        "create function g() returns int as $body$ SELECT 3; $body$ language sql;\n"
    )
    stmts = split_sql(sql)
    assert len(stmts) == 4
    assert stmts[0].line == 2
    assert stmts[0].norm == "insert into t values ('a;b', 'it''s')"
    assert stmts[1].norm == 'select "Mixed;Case" from t'
    assert stmts[1].line == 3
    assert "select 1; select 2;" in stmts[2].norm
    assert "$body$ select 3; $body$" in stmts[3].norm


def test_quoted_values_keep_case():
    [stmt] = split_sql("INSERT INTO storage.buckets (id) VALUES ('Avatars')")
    assert stmt.norm == "insert into storage.buckets (id) values ('Avatars')"


def test_positional_parameters_are_not_dollar_quotes():
    stmts = split_sql("select $1; select 2;")
    assert [s.norm for s in stmts] == ["select $1", "select 2"]


def test_helpers():
    s = "for select to authenticated using (a = (b)) with check (c)"
    assert find_top_level(s, r"using\b") == s.index("using")
    assert find_top_level("x (using y)", r"using\b") == -1
    assert find_top_level("reusing", r"using\b") == -1
    inner, end = balanced(s, s.index("("))
    assert inner == "a = (b)"
    assert s[end:].startswith(" with check")
    assert split_top_level("a int, b numeric(10, 2), 'x,y'") == [
        "a int",
        "b numeric(10, 2)",
        "'x,y'",
    ]
    assert qualify('"public"."Docs"') == "public.Docs"
    assert qualify("docs") == "public.docs"
    assert qualify("auth.users") == "auth.users"
    assert clean_predicate(" ((true)) ") == "true"
    assert clean_predicate("(a) and (b)") == "(a) and (b)"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/parsing/test_sql.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'dpr.parsing.sql'`

- [ ] **Step 3: Write the implementation**

`src/dpr/parsing/sql.py`:

```python
"""Split SQL into statements and find top-level clauses."""

from __future__ import annotations

import re
from dataclasses import dataclass

IDENT = r'(?:"[^"]+"|[a-z_][a-z0-9_$]*)'
QNAME = rf"(?:{IDENT}\s*\.\s*)?{IDENT}"
DOLLAR = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)?\$")


@dataclass(frozen=True)
class Statement:
    text: str
    norm: str
    line: int


class _Builder:
    def __init__(self) -> None:
        self.statements: list[Statement] = []
        self.raw: list[str] = []
        self.norm: list[str] = []
        self.start_line: int | None = None

    def emit(self, line: int) -> None:
        normalized = re.sub(r"\s+", " ", "".join(self.norm)).strip()
        if normalized:
            text = "".join(self.raw).strip()
            self.statements.append(Statement(text, normalized, self.start_line or line))
        self.raw, self.norm, self.start_line = [], [], None


def _quoted_end(sql: str, i: int) -> int:
    quote = sql[i]
    j = i + 1
    while j < len(sql):
        if sql[j] == quote:
            if j + 1 < len(sql) and sql[j + 1] == quote:
                j += 2
                continue
            return j + 1
        j += 1
    return len(sql)


def _block_comment_end(sql: str, i: int) -> int:
    depth, j = 1, i + 2
    while j < len(sql) and depth:
        if sql.startswith("/*", j):
            depth, j = depth + 1, j + 2
        elif sql.startswith("*/", j):
            depth, j = depth - 1, j + 2
        else:
            j += 1
    return j


def split_sql(sql: str) -> list[Statement]:
    b = _Builder()
    i, line, n = 0, 1, len(sql)
    while i < n:
        ch = sql[i]
        if sql.startswith("--", i):
            end = sql.find("\n", i)
            end = n if end == -1 else end
            b.raw.append(sql[i:end])
            b.norm.append(" ")
            i = end
            continue
        if sql.startswith("/*", i):
            end = _block_comment_end(sql, i)
            b.raw.append(sql[i:end])
            b.norm.append(" ")
            line += sql.count("\n", i, end)
            i = end
            continue
        if b.start_line is None and not ch.isspace() and ch != ";":
            b.start_line = line
        if ch in ("'", '"'):
            end = _quoted_end(sql, i)
            b.raw.append(sql[i:end])
            b.norm.append(sql[i:end])
            line += sql.count("\n", i, end)
            i = end
            continue
        if ch == "$":
            match = DOLLAR.match(sql, i)
            follows_word = i > 0 and (sql[i - 1].isalnum() or sql[i - 1] == "_")
            if match and not follows_word:
                close = sql.find(match.group(0), match.end())
                end = n if close == -1 else close + len(match.group(0))
                b.raw.append(sql[i:end])
                b.norm.append(sql[i:end].lower())
                line += sql.count("\n", i, end)
                i = end
                continue
        if ch == ";":
            b.emit(line)
            i += 1
            continue
        if ch == "\n":
            line += 1
        b.raw.append(ch)
        b.norm.append(ch.lower())
        i += 1
    b.emit(line)
    return b.statements


def find_top_level(s: str, keyword_regex: str, start: int = 0) -> int:
    pattern = re.compile(keyword_regex)
    depth, quote = 0, None
    for i in range(start, len(s)):
        ch = s[i]
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0 and pattern.match(s, i):
            if i == 0 or not (s[i - 1].isalnum() or s[i - 1] == "_"):
                return i
    return -1


def balanced(s: str, open_index: int) -> tuple[str, int]:
    depth, quote = 0, None
    for i in range(open_index, len(s)):
        ch = s[i]
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return s[open_index + 1 : i], i + 1
    return s[open_index + 1 :], len(s)


def split_top_level(s: str, sep: str = ",") -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    depth, quote = 0, None
    for ch in s:
        if quote:
            current.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == sep and depth == 0:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def qualify(name: str, default_schema: str = "public") -> str:
    parts = [p[1:-1] if p.startswith('"') else p for p in re.findall(IDENT, name)]
    if len(parts) == 1:
        parts.insert(0, default_schema)
    return ".".join(parts[-2:])


def clean_predicate(predicate: str) -> str:
    p = predicate.strip()
    while p.startswith("("):
        inner, end = balanced(p, 0)
        if end != len(p):
            break
        p = inner.strip()
    return p
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/parsing/test_sql.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/parsing/sql.py tests/parsing/test_sql.py
git commit -m "Add SQL statement splitter aware of quotes, comments and dollar bodies"
```

---

### Task 10: SQL schema state, migrations and psql dumps

**Files:**
- Create: `src/dpr/parsing/sqlschema.py`
- Test: `tests/parsing/test_sqlschema.py`

**Interfaces:**
- Consumes: `Location` (Task 2), `RepoIndex` (Task 5), everything in `dpr.parsing.sql` (Task 9)
- Produces (all in `dpr.parsing.sqlschema`):
  - `Column(name, type, unique=False, autoincrement=False)`
  - `TableDef(key, columns, location, rls=False, rls_location=None)` with properties `schema`, `name`, and `column_names() -> list[str]`
  - `Policy(name, table, command, roles, roles_explicit, using, with_check, permissive, location)`; `command` is one of `all|select|insert|update|delete`; `roles` defaults to `("public",)`; predicates are cleaned normalised text or `None`
  - `View(key, security_invoker, sources, location)`, `Function(key, security_definer, sets_search_path, tables, location)`, `Bucket(id, public, location)`
  - `SchemaState` with `tables`, `policies: dict[tuple[table_key, name], Policy]`, `views`, `functions`, `buckets`, `sources: list[str]`, and methods `apply(stmt, file)`, `policies_for(table_key) -> list[Policy]` (ordered by file then line)
  - `MIGRATION_GLOBS`, `load_schema(index) -> SchemaState`
  - `apply_dump(state, text, file) -> list[str]` (applies pasted `pg_tables` / `pg_policies` output in psql aligned or CSV form; policies for a table in the dump replace that table's migration policies; returns problem lines)

- [ ] **Step 1: Write the failing test**

`tests/parsing/test_sqlschema.py`:

```python
from dpr.parsing.sql import split_sql
from dpr.parsing.sqlschema import SchemaState, apply_dump, load_schema
from dpr.walk import RepoIndex

MIGRATION = """
create table public.profiles (
  id uuid primary key,
  user_id uuid not null references auth.users,
  email text,
  constraint profiles_email_key unique (email)
);
create table if not exists invoices (id bigserial primary key, org_id uuid, amount int);
alter table public.profiles enable row level security;
create policy "profiles_update" on public.profiles as permissive for update to authenticated
  using ((select auth.uid()) = user_id) with check (true);
create policy read_all on profiles for select using (true);
alter policy read_all on public.profiles to anon, authenticated;
create policy temp on profiles for delete using (false);
drop policy if exists temp on public.profiles;
alter table invoices add column user_id uuid, add column note text;
create view public.invoice_list as select i.id from public.invoices i join profiles p on true;
create view public.safe_list with (security_invoker = true) as select id from invoices;
alter view public.invoice_list set (security_invoker = on);
create or replace function public.all_docs() returns setof documents language sql
  security definer as $$ select * from public.documents $$;
create function public.ok() returns int language sql security definer set search_path = ''
  as $fn$ select count(*) from invoices $fn$;
insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true), ('private', 'private', false);
create table public.tmp (id int);
drop table public.tmp;
"""


def state():
    s = SchemaState()
    for stmt in split_sql(MIGRATION):
        s.apply(stmt, "m.sql")
    return s


def test_tables_columns_and_rls():
    s = state()
    assert sorted(s.tables) == ["public.invoices", "public.profiles"]
    profiles = s.tables["public.profiles"]
    assert profiles.column_names() == ["id", "user_id", "email"]
    assert [c.unique for c in profiles.columns] == [True, False, True]
    assert profiles.rls is True and profiles.rls_location.line == 9
    invoices = s.tables["public.invoices"]
    assert invoices.column_names() == ["id", "org_id", "amount", "user_id", "note"]
    assert invoices.columns[0].autoincrement is True
    assert invoices.rls is False
    assert profiles.location.line == 2


def test_policies():
    s = state()
    policies = {p.name: p for p in s.policies_for("public.profiles")}
    assert sorted(policies) == ["profiles_update", "read_all"]
    update = policies["profiles_update"]
    assert (update.command, update.roles, update.roles_explicit) == (
        "update",
        ("authenticated",),
        True,
    )
    assert update.using == "(select auth.uid()) = user_id"
    assert update.with_check == "true"
    assert update.location.line == 10
    read_all = policies["read_all"]
    assert (read_all.command, read_all.using, read_all.with_check) == ("select", "true", None)
    assert read_all.roles == ("anon", "authenticated")


def test_views_functions_buckets():
    s = state()
    assert s.views["public.invoice_list"].security_invoker is True
    assert s.views["public.invoice_list"].sources == ("public.invoices", "public.profiles")
    assert s.views["public.safe_list"].security_invoker is True
    all_docs = s.functions["public.all_docs"]
    assert (all_docs.security_definer, all_docs.sets_search_path) == (True, False)
    assert all_docs.tables == ("public.documents",)
    assert s.functions["public.ok"].sets_search_path is True
    assert {b.id: b.public for b in s.buckets.values()} == {"avatars": True, "private": False}


def test_load_schema_applies_files_in_path_order(tmp_path):
    mig = tmp_path / "supabase" / "migrations"
    mig.mkdir(parents=True)
    (mig / "002_rls.sql").write_text("alter table docs enable row level security;")
    (mig / "001_init.sql").write_text("create table docs (id int, user_id uuid);")
    (tmp_path / "app.ts").write_text("x")
    s = load_schema(RepoIndex(tmp_path))
    assert s.sources == ["supabase/migrations/001_init.sql", "supabase/migrations/002_rls.sql"]
    assert s.tables["public.docs"].rls is True
    assert s.tables["public.docs"].location.file == "supabase/migrations/001_init.sql"


ALIGNED = """
 schemaname | tablename | rowsecurity
------------+-----------+-------------
 public     | profiles  | f
 public     | invoices  | t
(2 rows)

 schemaname | tablename | policyname | permissive | roles | cmd | qual | with_check
------------+-----------+------------+------------+-------+-----+------+------------
 public | invoices | inv_read | PERMISSIVE | {authenticated} | SELECT | (auth.role() = 'authenticated'::text) |
(1 row)
"""

CSV = """schemaname,tablename,policyname,permissive,roles,cmd,qual,with_check
public,profiles,p_all,PERMISSIVE,{public},ALL,(auth.uid() = user_id),
"""


def test_apply_dump_aligned_overrides_migrations():
    s = state()
    problems = apply_dump(s, ALIGNED, "dump.txt")
    assert problems == []
    assert s.tables["public.profiles"].rls is False
    assert s.tables["public.profiles"].rls_location.file == "dump.txt"
    assert s.tables["public.invoices"].rls is True
    [policy] = s.policies_for("public.invoices")
    assert policy.using == "auth.role() = 'authenticated'::text"
    assert policy.with_check is None
    assert policy.location.line == 10


def test_apply_dump_csv_replaces_table_policies():
    s = state()
    apply_dump(s, CSV, "dump.csv")
    [policy] = s.policies_for("public.profiles")
    assert (policy.name, policy.command, policy.roles_explicit) == ("p_all", "all", False)
    assert policy.using == "auth.uid() = user_id"


def test_apply_dump_reports_bad_rows():
    problems = apply_dump(
        SchemaState(), " schemaname | tablename | rowsecurity\n public | x\n", "d"
    )
    assert problems == ["d:2: row skipped, unexpected column count"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/parsing/test_sqlschema.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'dpr.parsing.sqlschema'`

- [ ] **Step 3: Write the implementation**

`src/dpr/parsing/sqlschema.py`:

```python
"""Schema state built from SQL migrations or a pasted psql dump."""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field, replace

from dpr.model import Location
from dpr.parsing.sql import (
    IDENT,
    QNAME,
    Statement,
    balanced,
    clean_predicate,
    find_top_level,
    qualify,
    split_sql,
    split_top_level,
)
from dpr.walk import RepoIndex

MIGRATION_GLOBS = ("*migrations/*.sql", "*db/*.sql", "schema.sql", "*/schema.sql")
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


CREATE_TABLE = re.compile(
    rf"^create\s+(?:(?:global|local)\s+)?(?:temporary\s+|temp\s+|unlogged\s+)?table\s+"
    rf"(?:if\s+not\s+exists\s+)?({QNAME})\s*(.*)$",
    re.S,
)
ALTER_TABLE = re.compile(
    rf"^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?({QNAME})\s+(.*)$", re.S
)
RLS_ACTION = re.compile(r"^(enable|disable|force|no\s+force)\s+row\s+level\s+security")
CREATE_POLICY = re.compile(rf"^create\s+policy\s+({IDENT})\s+on\s+({QNAME})\s*(.*)$", re.S)
ALTER_POLICY = re.compile(rf"^alter\s+policy\s+({IDENT})\s+on\s+({QNAME})\s*(.*)$", re.S)
DROP_POLICY = re.compile(rf"^drop\s+policy\s+(?:if\s+exists\s+)?({IDENT})\s+on\s+({QNAME})")
CREATE_VIEW = re.compile(
    rf"^create\s+(?:or\s+replace\s+)?(?:(?:temp|temporary)\s+)?(?:recursive\s+)?view\s+"
    rf"({QNAME})\s*(.*)$",
    re.S,
)
ALTER_VIEW = re.compile(rf"^alter\s+view\s+(?:if\s+exists\s+)?({QNAME})\s+set\s*(\(.*\))", re.S)
CREATE_FUNCTION = re.compile(rf"^create\s+(?:or\s+replace\s+)?function\s+({QNAME})\s*(.*)$", re.S)
INSERT_BUCKET = re.compile(
    r"^insert\s+into\s+storage\s*\.\s*buckets\s*\(([^)]*)\)\s*values\s*(.*)$", re.S
)
DROP_OBJECT = re.compile(rf"^drop\s+(table|view|function)\s+(?:if\s+exists\s+)?({QNAME})")
CONSTRAINT_START = re.compile(
    r"^(constraint|primary\s+key|unique|foreign\s+key|check|exclude|like)\b"
)
TABLE_KEY_CONSTRAINT = re.compile(
    rf"^(?:constraint\s+{IDENT}\s+)?(?:primary\s+key|unique)\s*\(([^)]*)\)"
)
SOURCE_TABLE = re.compile(rf"\b(?:from|join)\s+({QNAME})")
BODY_TABLE = re.compile(rf"\b(?:from|join|into|update)\s+({QNAME})")


def _strip_quotes(name: str) -> str:
    return name[1:-1] if name.startswith('"') else name


def _column(item: str) -> Column | None:
    if CONSTRAINT_START.match(item):
        return None
    match = re.match(rf"^({IDENT})\s+(.*)$", item, re.S)
    if not match:
        return None
    rest = match.group(2)
    col_type = rest.split(" ")[0]
    unique = bool(re.search(r"\b(unique|primary\s+key)\b", rest))
    autoinc = col_type in ("serial", "bigserial", "smallserial", "serial4", "serial8") or bool(
        re.search(r"\bgenerated\b.*\bidentity\b", rest)
    )
    return Column(_strip_quotes(match.group(1)), col_type, unique, autoinc)


def _policy_clauses(rest: str) -> dict[str, object]:
    out: dict[str, object] = {
        "permissive": True,
        "command": "all",
        "roles": ("public",),
        "roles_explicit": False,
        "using": None,
        "with_check": None,
    }
    match = re.match(r"^as\s+(permissive|restrictive)\s*", rest)
    if match:
        out["permissive"] = match.group(1) == "permissive"
        rest = rest[match.end() :]
    match = re.match(r"^for\s+(all|select|insert|update|delete)\s*", rest)
    if match:
        out["command"] = match.group(1)
        rest = rest[match.end() :]
    match = re.match(r"^to\s+", rest)
    if match:
        starts = (find_top_level(rest, r"using\b"), find_top_level(rest, r"with\s+check\b"))
        ends = [i for i in starts if i != -1]
        end = min(ends) if ends else len(rest)
        roles = [_strip_quotes(r.strip()) for r in split_top_level(rest[match.end() : end])]
        out["roles"] = tuple(r for r in roles if r)
        out["roles_explicit"] = True
        rest = rest[end:]
    for key, keyword in (("using", r"using\s*\("), ("with_check", r"with\s+check\s*\(")):
        start = find_top_level(rest, keyword)
        if start != -1:
            inner, _ = balanced(rest, rest.index("(", start))
            out[key] = clean_predicate(inner)
    return out


@dataclass
class SchemaState:
    tables: dict[str, TableDef] = field(default_factory=dict)
    policies: dict[tuple[str, str], Policy] = field(default_factory=dict)
    views: dict[str, View] = field(default_factory=dict)
    functions: dict[str, Function] = field(default_factory=dict)
    buckets: dict[str, Bucket] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)

    def policies_for(self, table_key: str) -> list[Policy]:
        found = [p for (t, _), p in self.policies.items() if t == table_key]
        return sorted(found, key=lambda p: (p.location.file, p.location.line, p.name))

    def table(self, key: str, loc: Location) -> TableDef:
        if key not in self.tables:
            self.tables[key] = TableDef(key, [], loc)
        return self.tables[key]

    def apply(self, stmt: Statement, file: str) -> None:
        loc = Location(file, stmt.line)
        s = stmt.norm
        for handler in (
            self._create_table,
            self._alter_table,
            self._create_policy,
            self._alter_policy,
            self._drop_policy,
            self._create_view,
            self._alter_view,
            self._create_function,
            self._insert_bucket,
            self._drop_object,
        ):
            if handler(s, loc):
                return

    def _create_table(self, s: str, loc: Location) -> bool:
        match = CREATE_TABLE.match(s)
        if not match:
            return False
        key = qualify(match.group(1))
        if key in self.tables:
            return True
        columns: list[Column] = []
        keyed: set[str] = set()
        rest = match.group(2)
        if rest.startswith("("):
            body, _ = balanced(rest, 0)
            for item in split_top_level(body):
                constraint = TABLE_KEY_CONSTRAINT.match(item)
                if constraint:
                    keyed.update(_strip_quotes(c.strip()) for c in constraint.group(1).split(","))
                column = _column(item)
                if column:
                    columns.append(column)
        columns = [replace(c, unique=True) if c.name in keyed else c for c in columns]
        self.tables[key] = TableDef(key, columns, loc)
        return True

    def _alter_table(self, s: str, loc: Location) -> bool:
        match = ALTER_TABLE.match(s)
        if not match:
            return False
        table = self.table(qualify(match.group(1)), loc)
        rest = match.group(2)
        action = RLS_ACTION.match(rest)
        if action:
            if action.group(1) in ("enable", "disable"):
                table.rls = action.group(1) == "enable"
                table.rls_location = loc
            return True
        for item in split_top_level(rest):
            added = re.match(r"^add\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?(.*)$", item, re.S)
            column = _column(added.group(1)) if added else None
            if column and column.name not in table.column_names():
                table.columns.append(column)
        return True

    def _create_policy(self, s: str, loc: Location) -> bool:
        match = CREATE_POLICY.match(s)
        if not match:
            return False
        name, table = _strip_quotes(match.group(1)), qualify(match.group(2))
        clauses = _policy_clauses(match.group(3))
        self.policies[(table, name)] = Policy(name=name, table=table, location=loc, **clauses)
        return True

    def _alter_policy(self, s: str, loc: Location) -> bool:
        match = ALTER_POLICY.match(s)
        if not match:
            return False
        name, table = _strip_quotes(match.group(1)), qualify(match.group(2))
        current = self.policies.get((table, name))
        rest = match.group(3)
        rename = re.match(rf"^rename\s+to\s+({IDENT})", rest)
        if current is None:
            return True
        if rename:
            del self.policies[(table, name)]
            new_name = _strip_quotes(rename.group(1))
            self.policies[(table, new_name)] = replace(current, name=new_name)
            return True
        clauses = _policy_clauses(rest)
        updated = current
        if clauses["roles_explicit"]:
            updated = replace(updated, roles=clauses["roles"], roles_explicit=True)
        if clauses["using"] is not None:
            updated = replace(updated, using=clauses["using"])
        if clauses["with_check"] is not None:
            updated = replace(updated, with_check=clauses["with_check"])
        self.policies[(table, name)] = updated
        return True

    def _drop_policy(self, s: str, loc: Location) -> bool:
        match = DROP_POLICY.match(s)
        if not match:
            return False
        self.policies.pop((qualify(match.group(2)), _strip_quotes(match.group(1))), None)
        return True

    def _create_view(self, s: str, loc: Location) -> bool:
        match = CREATE_VIEW.match(s)
        if not match:
            return False
        rest = match.group(2)
        if rest.startswith("("):
            _, end = balanced(rest, 0)
            rest = rest[end:].lstrip()
        invoker = False
        if rest.startswith("with"):
            options, end = balanced(rest, rest.index("("))
            invoker = _invoker(options)
            rest = rest[end:]
        sources = tuple(sorted({qualify(t) for t in SOURCE_TABLE.findall(rest)}))
        key = qualify(match.group(1))
        self.views[key] = View(key, invoker, sources, loc)
        return True

    def _alter_view(self, s: str, loc: Location) -> bool:
        match = ALTER_VIEW.match(s)
        if not match:
            return False
        key = qualify(match.group(1))
        if key in self.views:
            options, _ = balanced(match.group(2), 0)
            if "security_invoker" in options:
                self.views[key] = replace(self.views[key], security_invoker=_invoker(options))
        return True

    def _create_function(self, s: str, loc: Location) -> bool:
        match = CREATE_FUNCTION.match(s)
        if not match:
            return False
        rest = match.group(2)
        body = re.search(r"(\$[a-z0-9_]*\$)(.*?)\1", rest, re.S)
        inside = body.group(2) if body else rest
        outside = rest.replace(body.group(0), " ") if body else rest
        key = qualify(match.group(1))
        self.functions[key] = Function(
            key=key,
            security_definer=bool(re.search(r"\bsecurity\s+definer\b", outside)),
            sets_search_path=bool(re.search(r"\bset\s+search_path\b", outside)),
            tables=tuple(sorted({qualify(t) for t in BODY_TABLE.findall(inside)})),
            location=loc,
        )
        return True

    def _insert_bucket(self, s: str, loc: Location) -> bool:
        match = INSERT_BUCKET.match(s)
        if not match:
            return False
        columns = [_strip_quotes(c.strip()) for c in match.group(1).split(",")]
        rest = match.group(2).lstrip()
        while rest.startswith("("):
            inner, end = balanced(rest, 0)
            row = dict(
                zip(columns, (v.strip().strip("'") for v in split_top_level(inner)), strict=False)
            )
            if row.get("id"):
                public = row.get("public", "false").lower() in TRUE_WORDS
                self.buckets[row["id"]] = Bucket(row["id"], public, loc)
            rest = rest[end:].lstrip().lstrip(",").lstrip()
        return True

    def _drop_object(self, s: str, loc: Location) -> bool:
        match = DROP_OBJECT.match(s)
        if not match:
            return False
        kind, key = match.group(1), qualify(match.group(2))
        if kind == "table":
            self.tables.pop(key, None)
            self.policies = {k: v for k, v in self.policies.items() if k[0] != key}
        elif kind == "view":
            self.views.pop(key, None)
        else:
            self.functions.pop(key, None)
        return True


def _invoker(options: str) -> bool:
    match = re.search(r"security_invoker(?:\s*=\s*'?(\w+)'?)?", options)
    return bool(match) and (match.group(1) is None or match.group(1) in TRUE_WORDS)


def load_schema(index: RepoIndex) -> SchemaState:
    state = SchemaState()
    for rel in sorted({f.rel for f in index.glob(*MIGRATION_GLOBS)}):
        state.sources.append(rel)
        for stmt in split_sql(index.text(rel)):
            state.apply(stmt, rel)
    return state


def _dump_rows(text: str) -> list[tuple[int, dict[str, str]]]:
    """Rows from psql aligned or CSV output, each with its 1-based line number."""
    rows: list[tuple[int, dict[str, str]]] = []
    header: list[str] | None = None
    delimiter = "|"
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or re.fullmatch(r"[-+]+", line) or re.fullmatch(r"\(\d+ rows?\)", line):
            if not line:
                header = None
            continue
        if "tablename" in line and ("rowsecurity" in line or "policyname" in line):
            delimiter = "|" if "|" in line else ","
            header = [h.strip() for h in line.split(delimiter)]
            continue
        if header is None:
            continue
        cells = next(csv.reader([line])) if delimiter == "," else line.split("|")
        cells = [c.strip() for c in cells]
        if len(cells) != len(header):
            rows.append((number, {}))
            continue
        rows.append((number, dict(zip(header, cells, strict=True))))
    return rows


def apply_dump(state: SchemaState, text: str, file: str) -> list[str]:
    problems: list[str] = []
    replaced: set[str] = set()
    for number, row in _dump_rows(text):
        loc = Location(file, number)
        if not row or not row.get("tablename"):
            problems.append(f"{file}:{number}: row skipped, unexpected column count")
            continue
        key = qualify(f'"{row.get("schemaname") or "public"}"."{row["tablename"]}"')
        if "rowsecurity" in row:
            table = state.table(key, loc)
            table.rls = row["rowsecurity"].lower() in TRUE_WORDS
            table.rls_location = loc
            continue
        if key not in replaced:
            state.policies = {k: v for k, v in state.policies.items() if k[0] != key}
            replaced.add(key)
        roles = tuple(r.strip() for r in row.get("roles", "").strip("{}").split(",") if r.strip())
        qual = re.sub(r"\s+", " ", row.get("qual", "")).strip().lower()
        check = re.sub(r"\s+", " ", row.get("with_check", "")).strip().lower()
        state.policies[(key, row["policyname"])] = Policy(
            name=row["policyname"],
            table=key,
            command=row.get("cmd", "ALL").lower(),
            roles=roles or ("public",),
            roles_explicit=bool(roles) and roles != ("public",),
            using=clean_predicate(qual) if qual else None,
            with_check=clean_predicate(check) if check else None,
            permissive=row.get("permissive", "PERMISSIVE").upper() == "PERMISSIVE",
            location=loc,
        )
    return problems
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/parsing/test_sqlschema.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/parsing/sqlschema.py tests/parsing/test_sqlschema.py
git commit -m "Add schema state from SQL migrations and pasted psql dumps"
```

---

### Task 11: Prisma schema parser

**Files:**
- Create: `src/dpr/parsing/prisma.py`
- Test: `tests/parsing/test_prisma.py`

**Interfaces:**
- Consumes: nothing
- Produces (in `dpr.parsing.prisma`):
  - `PrismaField(name, type, optional, is_list, attributes, column, line)`; `column` is the `@map("...")` value or `name`
  - `PrismaModel(name, table, fields, line)`; `table` is the `@@map("...")` value or `name`
  - `parse_prisma(text: str) -> list[PrismaModel]`

- [ ] **Step 1: Write the failing test**

`tests/parsing/test_prisma.py`:

```python
from dpr.parsing.prisma import parse_prisma

SCHEMA = """
generator client { provider = "prisma-client-js" }

// a comment with model Fake {
model User {
  id           Int       @id @default(autoincrement())
  email        String    @unique
  passwordHash String    @map("password_hash")
  website      String?   @default("https://example.com") // trailing comment
  invoices     Invoice[]
  @@map("users")
}

enum Role {
  ADMIN
}

model Invoice {
  id     Int  @id
  userId Int
  user   User @relation(fields: [userId], references: [id], onDelete: Cascade)
}
"""


def test_models_and_fields():
    user, invoice = parse_prisma(SCHEMA)
    assert (user.name, user.table, user.line) == ("User", "users", 5)
    names = [f.name for f in user.fields]
    assert names == ["id", "email", "passwordHash", "website", "invoices"]
    by_name = {f.name: f for f in user.fields}
    assert "@default(autoincrement())" in by_name["id"].attributes
    assert by_name["passwordHash"].column == "password_hash"
    assert by_name["website"].optional is True
    assert by_name["website"].attributes == '@default("https://example.com")'
    assert by_name["invoices"].is_list is True
    assert by_name["email"].line == 7
    assert invoice.table == "Invoice"
    assert [f.name for f in invoice.fields] == ["id", "userId", "user"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/parsing/test_prisma.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'dpr.parsing.prisma'`

- [ ] **Step 3: Write the implementation**

`src/dpr/parsing/prisma.py`:

```python
"""Parser for model blocks in schema.prisma files."""

from __future__ import annotations

import re
from dataclasses import dataclass

MODEL_START = re.compile(r"^\s*model\s+(\w+)\s*\{")
FIELD = re.compile(r"^\s*(\w+)\s+(\w+)(\[\])?(\?)?\s*(.*?)\s*$")
TABLE_MAP = re.compile(r'@@map\(\s*"([^"]+)"\s*\)')
COLUMN_MAP = re.compile(r'(?<!@)@map\(\s*"([^"]+)"\s*\)')


@dataclass(frozen=True)
class PrismaField:
    name: str
    type: str
    optional: bool
    is_list: bool
    attributes: str
    column: str
    line: int


@dataclass(frozen=True)
class PrismaModel:
    name: str
    table: str
    fields: tuple[PrismaField, ...]
    line: int


def _strip_comment(line: str) -> str:
    quote = False
    for i, ch in enumerate(line):
        if ch == '"':
            quote = not quote
        elif not quote and line.startswith("//", i):
            return line[:i]
    return line


def parse_prisma(text: str) -> list[PrismaModel]:
    models: list[PrismaModel] = []
    name, table, start = "", "", 0
    fields: list[PrismaField] = []
    inside = False
    for number, raw in enumerate(text.splitlines(), start=1):
        line = _strip_comment(raw)
        if not inside:
            match = MODEL_START.match(line)
            if match:
                name = table = match.group(1)
                start, fields, inside = number, [], True
            continue
        stripped = line.strip()
        if stripped.startswith("}"):
            models.append(PrismaModel(name, table, tuple(fields), start))
            inside = False
            continue
        if not stripped:
            continue
        if stripped.startswith("@@"):
            mapped = TABLE_MAP.search(stripped)
            if mapped:
                table = mapped.group(1)
            continue
        match = FIELD.match(line)
        if match:
            attributes = match.group(5)
            column = COLUMN_MAP.search(attributes)
            fields.append(
                PrismaField(
                    name=match.group(1),
                    type=match.group(2),
                    optional=bool(match.group(4)),
                    is_list=bool(match.group(3)),
                    attributes=attributes,
                    column=column.group(1) if column else match.group(1),
                    line=number,
                )
            )
    return models
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/parsing/test_prisma.py -v`
Expected: PASS (1 test)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/parsing/prisma.py tests/parsing/test_prisma.py
git commit -m "Add schema.prisma model parser"
```

---

### Task 12: Data model extraction for all ORMs

**Files:**
- Create: `src/dpr/parsing/schemas.py`
- Test: `tests/parsing/test_schemas.py`

**Interfaces:**
- Consumes: `DataModel`, `Field`, `Location` (Task 2); `RepoIndex` (Task 5); `jsts` (Task 7); `pyast` (Task 8); `SchemaState` (Task 10); `parse_prisma` (Task 11)
- Produces (in `dpr.parsing.schemas`):
  - `extract_models(index: RepoIndex, state: SchemaState) -> list[DataModel]`. Order: Prisma, SQL (tables whose name matches a Prisma model or table are skipped), Django, SQLAlchemy, Drizzle.
  - `find_model(models: list[DataModel], name: str) -> DataModel | None` (case-insensitive match on model name, table, or table without schema, also ignoring a trailing `s`)

- [ ] **Step 1: Write the failing test**

`tests/parsing/test_schemas.py`:

```python
from dpr.parsing.schemas import extract_models, find_model
from dpr.parsing.sqlschema import load_schema
from dpr.walk import RepoIndex


def write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def build(tmp_path):
    write(
        tmp_path,
        "prisma/schema.prisma",
        """
model User {
  id    Int    @id @default(autoincrement())
  email String @unique
  @@map("users")
}
""",
    )
    write(
        tmp_path,
        "prisma/migrations/1_init/migration.sql",
        'create table "users" (id serial primary key, email text);',
    )
    write(
        tmp_path,
        "supabase/migrations/1.sql",
        "create table public.documents (id uuid, user_id uuid);",
    )
    write(
        tmp_path,
        "billing/models.py",
        """
from django.db import models

class Invoice(models.Model):
    amount = models.IntegerField()
    number = models.CharField(max_length=20, unique=True)
    owner = models.ForeignKey("auth.User", on_delete=models.CASCADE)

class Base(models.Model):
    class Meta:
        abstract = True

class Note(models.Model):
    uid = models.UUIDField(primary_key=True)
    class Meta:
        db_table = "notes"
""",
    )
    write(
        tmp_path,
        "svc/db.py",
        """
from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

class Account(Base):
    __tablename__ = "accounts"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"))
""",
    )
    write(
        tmp_path,
        "src/db/schema.ts",
        """
import { pgTable, serial, text, uuid } from "drizzle-orm/pg-core"

export const profiles = pgTable("profiles", {
  id: serial("id").primaryKey(),
  fullName: text("full_name").notNull(),
  email: text().unique(),
  orgId: uuid("org_id"),
})
""",
    )
    index = RepoIndex(tmp_path)
    return extract_models(index, load_schema(index))


def test_sources_and_prisma_sql_dedupe(tmp_path):
    models = build(tmp_path)
    assert [(m.source, m.name, m.table) for m in models] == [
        ("prisma", "User", "users"),
        ("sql", "documents", "public.documents"),
        ("django", "Invoice", "billing_invoice"),
        ("django", "Note", "notes"),
        ("sqlalchemy", "Account", "accounts"),
        ("drizzle", "profiles", "profiles"),
    ]


def test_fields(tmp_path):
    models = {m.name: m for m in build(tmp_path)}
    user = models["User"]
    assert [(f.name, f.unique, f.autoincrement) for f in user.fields] == [
        ("id", True, True),
        ("email", True, False),
    ]
    invoice = models["Invoice"]
    assert invoice.field_names() == ["id", "amount", "number", "owner"]
    assert invoice.fields[0].autoincrement is True
    assert invoice.fields[2].unique is True
    assert models["Note"].field_names() == ["uid"]
    account = models["Account"]
    assert [(f.name, f.type, f.unique, f.autoincrement) for f in account.fields] == [
        ("id", "Integer", True, True),
        ("email", "String", True, False),
        ("org_id", "Mapped[int]", False, False),
    ]
    profiles = models["profiles"]
    assert [(f.name, f.type, f.unique, f.autoincrement) for f in profiles.fields] == [
        ("id", "serial", True, True),
        ("full_name", "text", False, False),
        ("email", "text", True, False),
        ("org_id", "uuid", False, False),
    ]
    assert profiles.fields[1].location.line == 6


def test_find_model(tmp_path):
    models = build(tmp_path)
    assert find_model(models, "user").name == "User"
    assert find_model(models, "invoices").name == "Invoice"
    assert find_model(models, "documents").source == "sql"
    assert find_model(models, "missing") is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/parsing/test_schemas.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'dpr.parsing.schemas'`

- [ ] **Step 3: Write the implementation**

`src/dpr/parsing/schemas.py`:

```python
"""Extract data models from Prisma, SQL, Django, SQLAlchemy and Drizzle."""

from __future__ import annotations

import ast
import re
from pathlib import PurePosixPath

from dpr.model import DataModel, Field, Location
from dpr.parsing import jsts, pyast
from dpr.parsing.prisma import parse_prisma
from dpr.parsing.sqlschema import SchemaState
from dpr.walk import RepoIndex

DJANGO_FIELD = re.compile(r"^\w*(Field|ForeignKey|OneToOneField|ManyToManyField)$")
DJANGO_AUTO = ("AutoField", "BigAutoField", "SmallAutoField")
SA_COLUMN = re.compile(r"^(?:\w+\.)*(Column|mapped_column)$")
DRIZZLE_TABLE = re.compile(r"(?:\w+\.)?(pgTable|mysqlTable|sqliteTable)")


def _prisma(index: RepoIndex) -> list[DataModel]:
    models = []
    for entry in index.glob("*.prisma"):
        for model in parse_prisma(index.text(entry.rel)):
            fields = tuple(
                Field(
                    name=f.name,
                    type=f.type + ("[]" if f.is_list else ""),
                    location=Location(entry.rel, f.line),
                    unique="@unique" in f.attributes or "@id" in f.attributes,
                    autoincrement="autoincrement()" in f.attributes,
                )
                for f in model.fields
            )
            location = Location(entry.rel, model.line)
            models.append(DataModel(model.name, model.table, "prisma", location, fields))
    return models


def _sql(state: SchemaState) -> list[DataModel]:
    models = []
    for table in state.tables.values():
        fields = tuple(
            Field(c.name, c.type, table.location, c.unique, c.autoincrement) for c in table.columns
        )
        models.append(DataModel(table.name, table.key, "sql", table.location, fields))
    return models


def _django_model(entry_rel: str, cls: ast.ClassDef) -> DataModel | None:
    meta = next((n for n in cls.body if isinstance(n, ast.ClassDef) and n.name == "Meta"), None)
    meta_values = pyast.assignments(meta.body) if meta else {}
    if pyast.constant(meta_values.get("abstract")) is True:
        return None
    fields: list[Field] = []
    has_pk = False
    for stmt in cls.body:
        if not (isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call)):
            continue
        if len(stmt.targets) != 1 or not isinstance(stmt.targets[0], ast.Name):
            continue
        kind = (pyast.dotted(stmt.value.func) or "").split(".")[-1]
        if not DJANGO_FIELD.match(kind):
            continue
        pk = pyast.constant(pyast.kwarg(stmt.value, "primary_key")) is True
        unique = pk or pyast.constant(pyast.kwarg(stmt.value, "unique")) is True
        has_pk = has_pk or pk
        fields.append(
            Field(
                stmt.targets[0].id,
                kind,
                Location(entry_rel, stmt.lineno),
                unique,
                kind in DJANGO_AUTO,
            )
        )
    if not has_pk:
        fields.insert(0, Field("id", "BigAutoField", Location(entry_rel, cls.lineno), True, True))
    path = PurePosixPath(entry_rel)
    app = path.parent.parent.name if path.parent.name == "models" else path.parent.name
    table = pyast.constant(meta_values.get("db_table"), None)
    if not isinstance(table, str):
        table = f"{app}_{cls.name.lower()}"
    return DataModel(cls.name, table, "django", Location(entry_rel, cls.lineno), tuple(fields))


def _django(index: RepoIndex) -> list[DataModel]:
    models = []
    for entry in index.py_files:
        if entry.name != "models.py" and "/models/" not in f"/{entry.rel}":
            continue
        if "django" not in index.text(entry.rel):
            continue
        tree = pyast.parse_file(index, entry.rel)
        if tree is None:
            continue
        for cls in pyast.class_defs(tree):
            if any(b == "models.Model" or b.endswith("Model") for b in pyast.base_names(cls)):
                model = _django_model(entry.rel, cls)
                if model:
                    models.append(model)
    return models


def _sa_type(call: ast.Call, annotation: ast.expr | None) -> str:
    for arg in call.args:
        name = pyast.dotted(arg.func if isinstance(arg, ast.Call) else arg) or ""
        last = name.split(".")[-1]
        if last[:1].isupper() and last != "ForeignKey":
            return last
    return ast.unparse(annotation) if annotation is not None else ""


def _sqlalchemy(index: RepoIndex) -> list[DataModel]:
    models = []
    for entry in index.py_files:
        if "__tablename__" not in index.text(entry.rel):
            continue
        tree = pyast.parse_file(index, entry.rel)
        if tree is None:
            continue
        for cls in pyast.class_defs(tree):
            table = pyast.constant(pyast.assignments(cls.body).get("__tablename__"), None)
            if not isinstance(table, str):
                continue
            fields = []
            for stmt in cls.body:
                annotation = None
                if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                    target, value = stmt.targets[0], stmt.value
                elif isinstance(stmt, ast.AnnAssign):
                    target, value, annotation = stmt.target, stmt.value, stmt.annotation
                else:
                    continue
                if not isinstance(target, ast.Name) or not isinstance(value, ast.Call):
                    continue
                if not SA_COLUMN.match(pyast.dotted(value.func) or ""):
                    continue
                col_type = _sa_type(value, annotation)
                pk = pyast.constant(pyast.kwarg(value, "primary_key")) is True
                unique = pk or pyast.constant(pyast.kwarg(value, "unique")) is True
                auto = (pk and col_type in ("Integer", "BigInteger")) or (
                    pyast.constant(pyast.kwarg(value, "autoincrement")) is True
                )
                fields.append(
                    Field(target.id, col_type, Location(entry.rel, stmt.lineno), unique, auto)
                )
            models.append(
                DataModel(
                    cls.name, table, "sqlalchemy", Location(entry.rel, cls.lineno), tuple(fields)
                )
            )
    return models


def _drizzle_base_call(node):
    node = jsts.unwrap(node)
    while node is not None and node.type == "call_expression":
        fn = node.child_by_field_name("function")
        if fn is not None and fn.type == "member_expression":
            node = jsts.unwrap(fn.child_by_field_name("object"))
            continue
        return node
    return None


def _drizzle(index: RepoIndex) -> list[DataModel]:
    models = []
    for entry in index.js_files:
        text = index.text(entry.rel)
        if "drizzle" not in text or "Table(" not in text:
            continue
        for tree in jsts.parse_file(index, entry.rel):
            for call in jsts.calls(tree, DRIZZLE_TABLE):
                args = jsts.arguments(call)
                table = jsts.string_value(args[0]) if args else None
                if table is None or len(args) < 2:
                    continue
                fields = []
                for key, value in jsts.object_pairs(args[1]).items():
                    base = _drizzle_base_call(value)
                    if base is None:
                        continue
                    col_type = jsts.callee(base)
                    base_args = jsts.arguments(base)
                    column = jsts.string_value(base_args[0]) if base_args else None
                    chain = re.sub(r"\s+", "", jsts.node_text(value))
                    unique = ".unique(" in chain or ".primaryKey(" in chain
                    auto = col_type in ("serial", "bigserial", "smallserial") or any(
                        word in chain for word in (".autoincrement(", "AsIdentity(")
                    )
                    fields.append(
                        Field(
                            column or key,
                            col_type,
                            Location(entry.rel, jsts.line(tree, value)),
                            unique,
                            auto,
                        )
                    )
                models.append(
                    DataModel(
                        table,
                        table,
                        "drizzle",
                        Location(entry.rel, jsts.line(tree, call)),
                        tuple(fields),
                    )
                )
    return models


def extract_models(index: RepoIndex, state: SchemaState) -> list[DataModel]:
    models = _prisma(index)
    prisma_names = {m.table.lower() for m in models} | {m.name.lower() for m in models}
    models += [m for m in _sql(state) if m.name.lower() not in prisma_names]
    return models + _django(index) + _sqlalchemy(index) + _drizzle(index)


def find_model(models: list[DataModel], name: str) -> DataModel | None:
    wanted = name.lower()
    for model in models:
        candidates = {model.name.lower(), model.table.lower(), model.table.split(".")[-1].lower()}
        if wanted in candidates or wanted.rstrip("s") in {c.rstrip("s") for c in candidates}:
            return model
    return None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/parsing/test_schemas.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/parsing/schemas.py tests/parsing/test_schemas.py
git commit -m "Extract data models from Prisma, SQL, Django, SQLAlchemy and Drizzle"
```

---

### Task 13: Route extraction for Next.js, Express and Fastify

**Files:**
- Create: `src/dpr/parsing/routes_js.py`
- Test: `tests/parsing/test_routes_js.py`

**Interfaces:**
- Consumes: `Route` (Task 2), `RepoIndex` (Task 5), `jsts` (Task 7)
- Produces (in `dpr.parsing.routes_js`):
  - `segments_to_path(segments: list[str]) -> str` (drops `(group)` and `@slot`, `[id]` to `:id`, `[...slug]` and `[[...slug]]` to `*slug`)
  - `next_app_routes(index) -> list[Route]` (framework `next-app`, one route per exported HTTP method function)
  - `next_pages_routes(index) -> list[Route]` (framework `next-pages`, method from `req.method === "X"` checks, else `ANY`)
  - `server_actions(index) -> list[Route]` (framework `next-action`, method `ACTION`, path `action:<export name>`)
  - `server_routes(index) -> list[Route]` (framework `express` or `fastify`; method `ANY` for `.all`)
  - Every route carries `handler` (tree-sitter node) and `tree` (`JsTree`)

- [ ] **Step 1: Write the failing test**

`tests/parsing/test_routes_js.py`:

```python
from dpr.parsing.routes_js import (
    next_app_routes,
    next_pages_routes,
    segments_to_path,
    server_actions,
    server_routes,
)
from dpr.walk import RepoIndex


def write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def repo(tmp_path):
    write(
        tmp_path,
        "app/api/users/[id]/route.ts",
        "export async function GET() {}\nexport const DELETE = async () => {}\n"
        "export function helper() {}\n",
    )
    write(tmp_path, "app/(marketing)/api/signup/route.ts", "export async function POST(req) {}\n")
    write(tmp_path, "src/app/route.ts", "export function GET() {}\n")
    write(
        tmp_path,
        "pages/api/reset/index.js",
        "export default async function handler(req, res) {\n"
        "  if (req.method === 'POST') { return res.json({}) }\n}\n",
    )
    write(tmp_path, "pages/api/ping.ts", "export default function ping(req, res) {}\n")
    write(
        tmp_path,
        "app/actions.ts",
        '"use server"\nexport async function createInvoice(data) {}\n'
        "export default async function signupAction() {}\n",
    )
    write(tmp_path, "lib/not-actions.ts", "export async function nope() {}\n")
    write(
        tmp_path,
        "server.js",
        "const app = express()\n"
        "app.get('/health', (req, res) => res.send('ok'))\n"
        "function loginHandler(req, res) {}\n"
        "router.post('/login', loginHandler)\n"
        "axios.get('/x', cb)\n"
        "client.get('/y', (r) => r)\n"
        "app.all('/any', async (req, res) => {})\n",
    )
    return RepoIndex(tmp_path)


def test_segments_to_path():
    assert segments_to_path(["(shop)", "api", "[id]", "@modal", "[...slug]"]) == "/api/:id/*slug"
    assert segments_to_path(["docs", "[[...rest]]"]) == "/docs/*rest"
    assert segments_to_path([""]) == "/"


def test_next_app_routes(tmp_path):
    routes = next_app_routes(repo(tmp_path))
    got = sorted((r.method, r.path, r.file, r.framework) for r in routes)
    assert got == [
        ("DELETE", "/api/users/:id", "app/api/users/[id]/route.ts", "next-app"),
        ("GET", "/", "src/app/route.ts", "next-app"),
        ("GET", "/api/users/:id", "app/api/users/[id]/route.ts", "next-app"),
        ("POST", "/api/signup", "app/(marketing)/api/signup/route.ts", "next-app"),
    ]
    delete = next(r for r in routes if r.method == "DELETE")
    assert delete.line == 2 and delete.handler.type == "arrow_function"


def test_next_pages_routes(tmp_path):
    routes = next_pages_routes(repo(tmp_path))
    assert sorted((r.method, r.path) for r in routes) == [
        ("ANY", "/api/ping"),
        ("POST", "/api/reset"),
    ]


def test_server_actions(tmp_path):
    routes = server_actions(repo(tmp_path))
    assert sorted((r.method, r.path, r.line) for r in routes) == [
        ("ACTION", "action:createInvoice", 2),
        ("ACTION", "action:signupAction", 3),
    ]


def test_server_routes(tmp_path):
    routes = server_routes(repo(tmp_path))
    assert [(r.method, r.path, r.line, r.framework) for r in routes] == [
        ("GET", "/health", 2, "express"),
        ("POST", "/login", 4, "express"),
        ("ANY", "/any", 7, "express"),
    ]
    login = routes[1]
    assert login.handler.type == "function_declaration"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/parsing/test_routes_js.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'dpr.parsing.routes_js'`

- [ ] **Step 3: Write the implementation**

`src/dpr/parsing/routes_js.py`:

```python
"""Routes for Next.js (app router, pages router, server actions), Express and Fastify."""

from __future__ import annotations

import re

from dpr.model import Route
from dpr.parsing import jsts
from dpr.walk import RepoIndex

HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
APP_ROUTE = re.compile(r"(?:^|/)app/((?:[^/]+/)*)route\.(?:[cm]?[jt]s)$")
PAGES_API = re.compile(r"(?:^|/)pages/api/(.+)\.(?:[cm]?[jt]sx?)$")
SERVER_CALL = re.compile(
    r"(?:app|router|server|fastify|routes|\w+Router|\w+router)\.(get|post|put|patch|delete|all)"
)
SERVER_HINT = re.compile(r"\.(?:get|post|put|patch|delete|all)\(\s*['\"`]/")
PAGES_METHOD = re.compile(r"""req\.method\s*[!=]==?\s*['"]([A-Z]+)['"]""")


def segments_to_path(segments: list[str]) -> str:
    parts = []
    for seg in segments:
        if not seg or (seg.startswith("(") and seg.endswith(")")) or seg.startswith("@"):
            continue
        if seg.startswith("[[...") and seg.endswith("]]"):
            parts.append("*" + seg[5:-2])
        elif seg.startswith("[...") and seg.endswith("]"):
            parts.append("*" + seg[4:-1])
        elif seg.startswith("[") and seg.endswith("]"):
            parts.append(":" + seg[1:-1])
        else:
            parts.append(seg)
    return "/" + "/".join(parts)


def next_app_routes(index: RepoIndex) -> list[Route]:
    routes = []
    for entry in index.js_files:
        match = APP_ROUTE.search(entry.rel)
        if not match:
            continue
        path = segments_to_path(match.group(1).strip("/").split("/"))
        for tree in jsts.parse_file(index, entry.rel):
            for name, fn in jsts.exported_functions(tree).items():
                if name in HTTP_METHODS:
                    routes.append(
                        Route(
                            name,
                            path,
                            entry.rel,
                            jsts.line(tree, fn),
                            "next-app",
                            handler=fn,
                            tree=tree,
                        )
                    )
    return routes


def next_pages_routes(index: RepoIndex) -> list[Route]:
    routes = []
    for entry in index.js_files:
        match = PAGES_API.search(entry.rel)
        if not match:
            continue
        segments = match.group(1).split("/")
        if segments[-1] == "index":
            segments = segments[:-1]
        path = segments_to_path(["api", *segments])
        for tree in jsts.parse_file(index, entry.rel):
            handler = jsts.exported_functions(tree).get("default")
            if handler is None:
                continue
            methods = sorted(set(PAGES_METHOD.findall(jsts.node_text(handler)))) or ["ANY"]
            for method in methods:
                routes.append(
                    Route(
                        method,
                        path,
                        entry.rel,
                        jsts.line(tree, handler),
                        "next-pages",
                        handler=handler,
                        tree=tree,
                    )
                )
    return routes


def server_actions(index: RepoIndex) -> list[Route]:
    routes = []
    for entry in index.js_files:
        if "use server" not in index.text(entry.rel):
            continue
        for tree in jsts.parse_file(index, entry.rel):
            if not jsts.has_directive(tree):
                continue
            exported = jsts.exported_functions(tree)
            seen: set[int] = set()
            for name, fn in exported.items():
                if name == "default" or fn.start_byte in seen:
                    continue
                seen.add(fn.start_byte)
                routes.append(
                    Route(
                        "ACTION",
                        f"action:{name}",
                        entry.rel,
                        jsts.line(tree, fn),
                        "next-action",
                        handler=fn,
                        tree=tree,
                    )
                )
            default = exported.get("default")
            if default is not None and default.start_byte not in seen:
                routes.append(
                    Route(
                        "ACTION",
                        "action:default",
                        entry.rel,
                        jsts.line(tree, default),
                        "next-action",
                        handler=default,
                        tree=tree,
                    )
                )
    return routes


def server_routes(index: RepoIndex) -> list[Route]:
    routes = []
    for entry in index.js_files:
        text = index.text(entry.rel)
        if not SERVER_HINT.search(text):
            continue
        framework = "fastify" if "fastify" in text else "express"
        for tree in jsts.parse_file(index, entry.rel):
            for call in jsts.calls(tree, SERVER_CALL):
                args = jsts.arguments(call)
                path = jsts.string_value(args[0]) if len(args) >= 2 else None
                if path is None or not path.startswith("/"):
                    continue
                handler = jsts.unwrap(args[-1])
                if handler is not None and handler.type == "identifier":
                    handler = _function_named(tree, jsts.node_text(handler)) or handler
                allowed = jsts.FUNCTION_TYPES | {"identifier", "member_expression"}
                if handler is None or handler.type not in allowed:
                    continue
                method = jsts.callee(call).rsplit(".", 1)[1].upper()
                routes.append(
                    Route(
                        "ANY" if method == "ALL" else method,
                        path,
                        entry.rel,
                        jsts.line(tree, call),
                        framework,
                        handler=handler,
                        tree=tree,
                    )
                )
    return routes


def _function_named(tree: jsts.JsTree, name: str):
    for node in jsts.walk(tree.root, {"function_declaration"}):
        if jsts.node_text(node.child_by_field_name("name")) == name:
            return node
    for decl in jsts.walk(tree.root, {"variable_declarator"}):
        value = jsts.unwrap(decl.child_by_field_name("value"))
        if jsts.node_text(decl.child_by_field_name("name")) == name and value is not None:
            if value.type in jsts.FUNCTION_TYPES:
                return value
    return None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/parsing/test_routes_js.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/parsing/routes_js.py tests/parsing/test_routes_js.py
git commit -m "Extract Next.js, Express and Fastify routes"
```

---

### Task 14: Python routes and route aggregation

**Files:**
- Create: `src/dpr/parsing/routes_py.py`, `src/dpr/parsing/routes.py`
- Test: `tests/parsing/test_routes_py.py`

**Interfaces:**
- Consumes: `Route` (Task 2), `RepoIndex` (Task 5), `pyast` (Task 8), `routes_js` (Task 13)
- Produces:
  - `dpr.parsing.routes_py.decorator_routes(index) -> list[Route]` (FastAPI `@x.get/post/put/patch/delete/api_route`, Flask `@x.route(methods=...)` and `@x.get`; framework `fastapi` or `flask`)
  - `dpr.parsing.routes_py.django_routes(index) -> list[Route]` (framework `django` for `path/re_path/url` in `urls.py`, `drf` for `router.register`; method `ANY`; `file` and `line` point at the resolved view when found, else at the `urls.py` call; `include(...)` entries are skipped)
  - `dpr.parsing.routes.PUBLIC_FORM` regex and `dpr.parsing.routes.extract_routes(index) -> list[Route]` (all frameworks, `is_public_form` set from path or Python handler name, sorted by file, line, method)

- [ ] **Step 1: Write the failing test**

`tests/parsing/test_routes_py.py`:

```python
from dpr.parsing.routes import extract_routes
from dpr.parsing.routes_py import decorator_routes, django_routes
from dpr.walk import RepoIndex


def write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def repo(tmp_path):
    write(
        tmp_path,
        "api/main.py",
        "from fastapi import APIRouter\nrouter = APIRouter()\n\n"
        '@router.get("/items/{item_id}")\nasync def read_item(item_id: int):\n    return {}\n\n'
        '@router.api_route("/multi", methods=["GET", "POST"])\ndef multi():\n    pass\n',
    )
    write(
        tmp_path,
        "web/app.py",
        "from flask import Flask\napp = Flask(__name__)\n\n"
        '@app.route("/contact", methods=["GET", "POST"])\ndef contact():\n    pass\n\n'
        '@app.route("/about")\ndef about():\n    pass\n',
    )
    write(
        tmp_path,
        "shop/urls.py",
        "from django.urls import path, include\nfrom . import views\n\n"
        "urlpatterns = [\n"
        '    path("invoices/<int:pk>/", views.invoice_detail),\n'
        '    path("orders/", views.OrderView.as_view()),\n'
        '    path("api/", include("accounts.urls")),\n'
        '    path("register/", views.missing_view),\n'
        "]\n",
    )
    write(
        tmp_path,
        "shop/views.py",
        "def invoice_detail(request, pk):\n    pass\n\n\nclass OrderView(View):\n    pass\n",
    )
    write(
        tmp_path,
        "accounts/urls.py",
        "from rest_framework import routers\nfrom .views import AccountViewSet\n"
        'router = routers.DefaultRouter()\nrouter.register(r"accounts", AccountViewSet)\n',
    )
    write(tmp_path, "accounts/views.py", "class AccountViewSet(ModelViewSet):\n    pass\n")
    write(tmp_path, "app/api/signup/route.ts", "export async function POST() {}\n")
    return RepoIndex(tmp_path)


def test_decorator_routes(tmp_path):
    got = sorted(
        (r.method, r.path, r.file, r.line, r.framework) for r in decorator_routes(repo(tmp_path))
    )
    assert got == [
        ("GET", "/about", "web/app.py", 9, "flask"),
        ("GET", "/contact", "web/app.py", 5, "flask"),
        ("GET", "/items/{item_id}", "api/main.py", 5, "fastapi"),
        ("GET", "/multi", "api/main.py", 9, "fastapi"),
        ("POST", "/contact", "web/app.py", 5, "flask"),
        ("POST", "/multi", "api/main.py", 9, "fastapi"),
    ]


def test_django_routes_resolve_views(tmp_path):
    got = sorted(
        (r.path, r.file, r.line, r.framework, type(r.handler).__name__)
        for r in django_routes(repo(tmp_path))
    )
    assert got == [
        ("/accounts", "accounts/views.py", 1, "drf", "ClassDef"),
        ("/invoices/<int:pk>", "shop/views.py", 1, "django", "FunctionDef"),
        ("/orders", "shop/views.py", 5, "django", "ClassDef"),
        ("/register", "shop/urls.py", 8, "django", "NoneType"),
    ]


def test_extract_routes_sets_public_form_flag(tmp_path):
    routes = extract_routes(repo(tmp_path))
    public = sorted((r.method, r.path) for r in routes if r.is_public_form)
    assert public == [
        ("ANY", "/register"),
        ("GET", "/contact"),
        ("POST", "/api/signup"),
        ("POST", "/contact"),
    ]
    assert routes == sorted(routes, key=lambda r: (r.file, r.line, r.method))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/parsing/test_routes_py.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'dpr.parsing.routes'`

- [ ] **Step 3: Write the implementation**

`src/dpr/parsing/routes_py.py`:

```python
"""Routes for Django, Django REST Framework, FastAPI and Flask."""

from __future__ import annotations

import ast
import re
from pathlib import PurePosixPath

from dpr.model import Route
from dpr.parsing import pyast
from dpr.walk import RepoIndex, SourceFile

VERBS = ("get", "post", "put", "patch", "delete")
URL_CALL = re.compile(r"(?:\w+\.)?(path|re_path|url)")
REGISTER_CALL = re.compile(r"(?:\w+\.)*register")


def _methods(decorator: ast.Call, default: list[str]) -> list[str]:
    node = pyast.kwarg(decorator, "methods")
    if isinstance(node, ast.List | ast.Tuple):
        values = [pyast.constant(e, None) for e in node.elts]
        return [v.upper() for v in values if isinstance(v, str)] or default
    return default


def decorator_routes(index: RepoIndex) -> list[Route]:
    routes = []
    for entry in index.py_files:
        text = index.text(entry.rel).lower()
        framework = "fastapi" if "fastapi" in text else "flask" if "flask" in text else None
        if framework is None:
            continue
        tree = pyast.parse_file(index, entry.rel)
        if tree is None:
            continue
        for fn in pyast.functions(tree):
            for dec in fn.decorator_list:
                if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
                    continue
                first = dec.args[0] if dec.args else pyast.kwarg(dec, "path")
                path = pyast.constant(first, None)
                if not isinstance(path, str):
                    continue
                verb = dec.func.attr
                if verb in VERBS:
                    methods = [verb.upper()]
                elif verb == "route":
                    methods = _methods(dec, ["GET"])
                elif verb == "api_route":
                    methods = _methods(dec, ["ANY"])
                else:
                    continue
                for method in methods:
                    routes.append(
                        Route(method, path, entry.rel, fn.lineno, framework, handler=fn, tree=tree)
                    )
    return routes


def _view_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        node = node.func
    parts = [p for p in (pyast.dotted(node) or "").split(".") if p and p != "as_view"]
    return parts[-1] if parts else None


def _find_view(index: RepoIndex, urls_rel: str, name: str | None):
    if not name:
        return None, None, None
    folder = PurePosixPath(urls_rel).parent.as_posix()
    prefix = "" if folder == "." else folder + "/"

    def is_local(f: SourceFile) -> bool:
        return f.rel.startswith(prefix)

    ordered = sorted(index.py_files, key=lambda f: (not is_local(f), f.rel))
    for entry in ordered:
        text = index.text(entry.rel)
        if f"def {name}" not in text and f"class {name}" not in text:
            continue
        tree = pyast.parse_file(index, entry.rel)
        if tree is None:
            continue
        for node in tree.body:
            is_def = isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
            if is_def and node.name == name:
                return node, entry.rel, tree
    return None, None, None


def _url_path(route: str) -> str:
    return "/" + route.strip().lstrip("^").rstrip("$").strip("/")


def django_routes(index: RepoIndex) -> list[Route]:
    routes = []
    for entry in index.named("urls.py"):
        tree = pyast.parse_file(index, entry.rel)
        if tree is None:
            continue
        for call in pyast.calls(tree, URL_CALL):
            route = pyast.constant(call.args[0], None) if len(call.args) >= 2 else None
            if not isinstance(route, str):
                continue
            view = call.args[1]
            if isinstance(view, ast.Call) and (pyast.dotted(view.func) or "").endswith("include"):
                continue
            handler, rel, view_tree = _find_view(index, entry.rel, _view_name(view))
            routes.append(
                Route(
                    "ANY",
                    _url_path(route),
                    rel or entry.rel,
                    handler.lineno if handler else call.lineno,
                    "django",
                    handler=handler,
                    tree=view_tree,
                )
            )
        for call in pyast.calls(tree, REGISTER_CALL):
            prefix = pyast.constant(call.args[0], None) if len(call.args) >= 2 else None
            if not isinstance(prefix, str):
                continue
            handler, rel, view_tree = _find_view(index, entry.rel, _view_name(call.args[1]))
            routes.append(
                Route(
                    "ANY",
                    _url_path(prefix),
                    rel or entry.rel,
                    handler.lineno if handler else call.lineno,
                    "drf",
                    handler=handler,
                    tree=view_tree,
                )
            )
    return routes
```

`src/dpr/parsing/routes.py`:

```python
"""All routes from every supported framework."""

from __future__ import annotations

import re
from dataclasses import replace

from dpr.model import Route
from dpr.parsing import routes_js, routes_py
from dpr.walk import RepoIndex

PUBLIC_FORM = re.compile(
    r"sign-?up|register|log-?in|sign-?in|reset|forgot|contact|waitlist|newsletter|feedback"
    r"|invite|upload",
    re.IGNORECASE,
)


def extract_routes(index: RepoIndex) -> list[Route]:
    found = (
        routes_js.next_app_routes(index)
        + routes_js.next_pages_routes(index)
        + routes_js.server_actions(index)
        + routes_js.server_routes(index)
        + routes_py.decorator_routes(index)
        + routes_py.django_routes(index)
    )
    routes = []
    for route in found:
        name = getattr(route.handler, "name", None)
        name = name if isinstance(name, str) else ""
        public = bool(PUBLIC_FORM.search(route.path) or PUBLIC_FORM.search(name))
        routes.append(replace(route, is_public_form=public))
    return sorted(routes, key=lambda r: (r.file, r.line, r.method))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/parsing/test_routes_py.py tests/parsing/test_routes_js.py -v`
Expected: PASS (8 tests)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/parsing/routes_py.py src/dpr/parsing/routes.py tests/parsing/test_routes_py.py
git commit -m "Extract Django, DRF, FastAPI and Flask routes and aggregate all routes"
```

---

### Task 15: Git helper, packages and env var names

**Files:**
- Create: `src/dpr/gitutil.py`, `src/dpr/discovery/__init__.py` (empty), `src/dpr/discovery/packages.py`
- Test: `tests/test_gitutil.py`, `tests/discovery/__init__.py` (empty), `tests/discovery/test_packages.py`

**Interfaces:**
- Consumes: `GitInfo`, `EnvVar`, `Location` (Task 2); `RepoIndex`, `line_of` (Task 5); `public_prefix` (Task 6)
- Produces:
  - `dpr.gitutil.run_git(root: Path, *args: str, timeout: int = 30) -> str | None` (always passes `-c core.fsmonitor=false` so a repo config cannot run commands; `None` when git is missing, fails or times out)
  - `dpr.gitutil.git_info(root: Path) -> GitInfo` (`revision` is the short sha, plus ` (with uncommitted changes)` when dirty, or `uncommitted working tree` when there is no repo or no commit)
  - `dpr.gitutil.tracked_files(root: Path) -> list[str] | None`
  - `dpr.discovery.packages.normalise(name: str) -> str` (lowercase, `_` to `-`)
  - `dpr.discovery.packages.collect_packages(index) -> tuple[set[str], dict[str, list[Location]]]` (normalised names from `package.json`, `pyproject.toml`, `requirements*.txt` and imports; the dict maps a package to its import sites)
  - `dpr.discovery.packages.collect_env_vars(index) -> list[EnvVar]` (sorted by name; names only)

- [ ] **Step 1: Write the failing tests**

`tests/test_gitutil.py`:

```python
import subprocess

from dpr.gitutil import git_info, run_git, tracked_files


def git(root, *args):
    subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "-c",
            "user.name=dpr",
            "-c",
            "user.email=dpr@example.invalid",
            *args,
        ],
        check=True,
        capture_output=True,
    )


def test_not_a_repo(tmp_path):
    info = git_info(tmp_path)
    assert (info.is_repo, info.revision) == (False, "uncommitted working tree")
    assert run_git(tmp_path, "status") is None
    assert tracked_files(tmp_path) is None


def test_repo_without_commits(tmp_path):
    git(tmp_path, "init", "-q")
    info = git_info(tmp_path)
    assert (info.is_repo, info.revision) == (True, "uncommitted working tree")


def test_clean_and_dirty_repo(tmp_path):
    git(tmp_path, "init", "-q")
    (tmp_path / "a.txt").write_text("a")
    git(tmp_path, "add", "a.txt")
    git(tmp_path, "commit", "-q", "-m", "init")
    sha = run_git(tmp_path, "rev-parse", "--short", "HEAD").strip()
    assert git_info(tmp_path).revision == sha
    (tmp_path / "b.txt").write_text("b")
    assert git_info(tmp_path).revision == f"{sha} (with uncommitted changes)"
    assert tracked_files(tmp_path) == ["a.txt"]
```

`tests/discovery/__init__.py`: empty file.

`tests/discovery/test_packages.py`:

```python
from dpr.discovery.packages import collect_env_vars, collect_packages, normalise
from dpr.walk import RepoIndex


def write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_collect_packages(tmp_path):
    write(
        tmp_path,
        "package.json",
        '{"dependencies": {"next": "14"}, "devDependencies": {"vitest": "1"}}',
    )
    write(tmp_path, "web/broken/package.json", "{not json")
    write(
        tmp_path,
        "pyproject.toml",
        '[project]\ndependencies = ["Django>=5", "psycopg[binary]"]\n'
        '[dependency-groups]\ndev = ["pytest"]\n'
        '[tool.poetry.dependencies]\nsentry_sdk = "^2"\n',
    )
    write(
        tmp_path,
        "requirements-dev.txt",
        "# tools\nslowapi==0.1 ; python_version > '3'\n-r base.txt\n",
    )
    write(
        tmp_path,
        "src/a.ts",
        "import { createClient } from '@supabase/supabase-js'\n"
        "import './styles.css'\nconst x = require(\"stripe\")\nimport 'server-only'\n",
    )
    write(tmp_path, "svc/b.py", "import os\nfrom openai import OpenAI\n")
    packages, sites = collect_packages(RepoIndex(tmp_path))
    for name in [
        "next",
        "vitest",
        "django",
        "psycopg",
        "pytest",
        "sentry-sdk",
        "slowapi",
        "@supabase/supabase-js",
        "stripe",
        "server-only",
        "openai",
        "os",
    ]:
        assert name in packages, name
    assert [str(loc) for loc in sites["stripe"]] == ["src/a.ts:3"]
    assert [str(loc) for loc in sites["openai"]] == ["svc/b.py:2"]
    assert normalise("Flask_Login") == "flask-login"


def test_collect_env_vars_names_only(tmp_path):
    write(
        tmp_path,
        ".env.local",
        "NEXT_PUBLIC_SUPABASE_URL=https://x\nSECRET_VALUE_HOLDER=do-not-read\n",
    )
    write(
        tmp_path,
        "lib/a.ts",
        "const u = process.env.NEXT_PUBLIC_SUPABASE_URL\nconst k = process.env['STRIPE_SECRET_KEY']\n"
        "const v = import.meta.env.VITE_API\n",
    )
    write(
        tmp_path,
        "src/routes/+page.svelte",
        "<script>\nimport { PUBLIC_MAP_TOKEN } from '$env/static/public'\n</script>\n",
    )
    write(
        tmp_path,
        "svc/settings.py",
        "import os\nA = os.environ['DATABASE_URL']\nB = os.environ.get('DEBUG')\n"
        "C = os.getenv('REDIS_URL')\nD = env.bool('USE_TLS')\n",
    )
    env = {e.name: e for e in collect_env_vars(RepoIndex(tmp_path))}
    assert sorted(env) == [
        "DATABASE_URL",
        "DEBUG",
        "NEXT_PUBLIC_SUPABASE_URL",
        "PUBLIC_MAP_TOKEN",
        "REDIS_URL",
        "SECRET_VALUE_HOLDER",
        "STRIPE_SECRET_KEY",
        "USE_TLS",
        "VITE_API",
    ]
    assert [str(loc) for loc in env["NEXT_PUBLIC_SUPABASE_URL"].locations] == [
        ".env.local:1",
        "lib/a.ts:1",
    ]
    assert env["NEXT_PUBLIC_SUPABASE_URL"].public and env["VITE_API"].public
    assert not env["STRIPE_SECRET_KEY"].public
    assert "do-not-read" not in repr(env)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_gitutil.py tests/discovery/test_packages.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'dpr.gitutil'`

- [ ] **Step 3: Write the implementation**

`src/dpr/gitutil.py`:

```python
"""Run git without letting repository config execute commands."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from dpr.model import GitInfo


def run_git(root: Path, *args: str, timeout: int = 30) -> str | None:
    if shutil.which("git") is None:
        return None
    command = ["git", "-c", "core.fsmonitor=false", "-C", str(root), *args]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout if result.returncode == 0 else None


def git_info(root: Path) -> GitInfo:
    inside = run_git(root, "rev-parse", "--is-inside-work-tree")
    if not inside or inside.strip() != "true":
        return GitInfo(False, "uncommitted working tree")
    sha = run_git(root, "rev-parse", "--short", "HEAD")
    if not sha:
        return GitInfo(True, "uncommitted working tree")
    dirty = run_git(root, "status", "--porcelain")
    suffix = " (with uncommitted changes)" if dirty else ""
    return GitInfo(True, sha.strip() + suffix)


def tracked_files(root: Path) -> list[str] | None:
    output = run_git(root, "ls-files", "-z")
    if output is None:
        return None
    return [name for name in output.split("\0") if name]
```

`src/dpr/discovery/__init__.py`: empty file.

`src/dpr/discovery/packages.py`:

```python
"""Dependency names, import sites and environment variable names."""

from __future__ import annotations

import json
import re
import tomllib
from collections import defaultdict

from dpr.model import EnvVar, Location
from dpr.redact import public_prefix
from dpr.walk import RepoIndex, line_of

JS_IMPORT = re.compile(
    r"""(?:\bfrom\s+|\brequire\(\s*|\bimport\s*\(\s*|^\s*import\s+)['"]([^'"./][^'"]*)['"]""",
    re.MULTILINE,
)
PY_IMPORT = re.compile(r"^\s*(?:from\s+([A-Za-z_]\w*)|import\s+([A-Za-z_]\w*))", re.MULTILINE)
JS_ENV = re.compile(
    r"(?:process\.env|import\.meta\.env)\.([A-Z][A-Z0-9_]*)"
    r"|process\.env\[\s*['\"]([A-Z][A-Z0-9_]*)['\"]\s*\]"
)
PY_ENV = re.compile(
    r"os\.environ\[\s*['\"]([A-Z][A-Z0-9_]*)['\"]\s*\]"
    r"|os\.environ\.get\(\s*['\"]([A-Z][A-Z0-9_]*)['\"]"
    r"|os\.getenv\(\s*['\"]([A-Z][A-Z0-9_]*)['\"]"
    r"|\benv(?:\.\w+)?\(\s*['\"]([A-Z][A-Z0-9_]*)['\"]"
)
SVELTE_ENV = re.compile(
    r"import\s*\{([^}]*)\}\s*from\s*['\"]\$env/(?:static|dynamic)/(?:public|private)['\"]"
)


def normalise(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def _requirement_name(spec: str) -> str:
    return re.split(r"[\s\[<>=!~;@]", spec.strip(), maxsplit=1)[0]


def _js_package(spec: str) -> str:
    parts = spec.split("/")
    return "/".join(parts[:2]) if spec.startswith("@") else parts[0]


def _manifest_packages(index: RepoIndex) -> set[str]:
    names: set[str] = set()
    for entry in index.named("package.json"):
        try:
            data = json.loads(index.text(entry.rel))
        except ValueError:
            continue
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            names.update(data.get(key) or {})
    for entry in index.named("pyproject.toml"):
        try:
            data = tomllib.loads(index.text(entry.rel))
        except tomllib.TOMLDecodeError:
            continue
        project = data.get("project", {})
        specs = list(project.get("dependencies", []))
        for group in project.get("optional-dependencies", {}).values():
            specs += group
        for group in data.get("dependency-groups", {}).values():
            specs += [item for item in group if isinstance(item, str)]
        specs += list(data.get("tool", {}).get("poetry", {}).get("dependencies", {}))
        names.update(_requirement_name(spec) for spec in specs)
    for entry in index.named("requirements*.txt"):
        for raw in index.text(entry.rel).splitlines():
            line = raw.split("#", 1)[0].strip()
            if line and not line.startswith("-"):
                names.add(_requirement_name(line))
    return {normalise(n) for n in names if n}


def collect_packages(index: RepoIndex) -> tuple[set[str], dict[str, list[Location]]]:
    packages = _manifest_packages(index)
    sites: dict[str, list[Location]] = defaultdict(list)
    for entry in index.js_files:
        text = index.text(entry.rel)
        for match in JS_IMPORT.finditer(text):
            name = normalise(_js_package(match.group(1)))
            packages.add(name)
            sites[name].append(Location(entry.rel, line_of(text, match.start(1))))
    for entry in index.py_files:
        text = index.text(entry.rel)
        for match in PY_IMPORT.finditer(text):
            name = normalise(match.group(1) or match.group(2))
            packages.add(name)
            sites[name].append(
                Location(
                    entry.rel, line_of(text, match.start(1) if match.group(1) else match.start(2))
                )
            )
    return packages, dict(sites)


def collect_env_vars(index: RepoIndex) -> list[EnvVar]:
    sites: dict[str, list[Location]] = defaultdict(list)
    for entry in index.env_files:
        for name, number in index.env_names(entry):
            sites[name].append(Location(entry.rel, number))
    for entry in index.js_files:
        text = index.text(entry.rel)
        for match in JS_ENV.finditer(text):
            sites[match.group(1) or match.group(2)].append(
                Location(entry.rel, line_of(text, match.start()))
            )
        for match in SVELTE_ENV.finditer(text):
            for name in re.findall(r"[A-Z][A-Z0-9_]*", match.group(1)):
                sites[name].append(Location(entry.rel, line_of(text, match.start())))
    for entry in index.py_files:
        text = index.text(entry.rel)
        for match in PY_ENV.finditer(text):
            name = next(g for g in match.groups() if g)
            sites[name].append(Location(entry.rel, line_of(text, match.start())))
    return [
        EnvVar(name, public_prefix(name) is not None, tuple(dict.fromkeys(sites[name])))
        for name in sorted(sites)
    ]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_gitutil.py tests/discovery/test_packages.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/gitutil.py src/dpr/discovery tests/test_gitutil.py tests/discovery
git commit -m "Add safe git helper, dependency collection and env var name discovery"
```

---

### Task 16: Stack signals, SDK catalogue and `detect()`

**Files:**
- Create: `src/dpr/data/stack.yaml`, `src/dpr/data/sdks.yaml`, `src/dpr/discovery/detect.py`
- Test: `tests/discovery/test_detect.py`

**Interfaces:**
- Consumes: `Detection`, `SdkUse` (Task 2); `dpr.data.load` (Task 3); `RepoIndex` (Task 5); `load_schema` (Task 10); `extract_models` (Task 12); `extract_routes` (Task 14); `git_info` (Task 15); `collect_packages`, `collect_env_vars`, `normalise` (Task 15)
- Produces: `dpr.discovery.detect.detect(index: RepoIndex) -> Detection` with every field filled. `stack.yaml` sections (`frameworks`, `databases`, `orms`, `auth_providers`, `hosting`, `logging`, `rate_limiters`, `test_frameworks`) map a name to optional `packages`, `files` (basename globs) and `text` (regex searched in JS/TS and Python files). `sdks.yaml` entries have `name`, `category`, `recipient`, `paid`, `packages`.

- [ ] **Step 1: Write the failing test**

`tests/discovery/test_detect.py`:

```python
import subprocess

from dpr.discovery.detect import detect
from dpr.walk import RepoIndex


def write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_detect_next_supabase_app(tmp_path):
    write(
        tmp_path,
        "package.json",
        '{"dependencies": {"next": "14", "@supabase/supabase-js": "2", "@prisma/client": "5",'
        ' "@sentry/nextjs": "8", "openai": "4", "@upstash/ratelimit": "1"},'
        ' "devDependencies": {"vitest": "1"}}',
    )
    write(
        tmp_path,
        "next.config.js",
        "module.exports = { async headers() { return [{ source: '/(.*)', headers: "
        "[{ key: 'X-Frame-Options', value: 'DENY' }] }] } }\n",
    )
    write(tmp_path, "vercel.json", "{}")
    write(tmp_path, ".github/workflows/ci.yml", "on: push")
    write(tmp_path, ".env.example", "NEXT_PUBLIC_SUPABASE_ANON_KEY=\n")
    write(tmp_path, "prisma/schema.prisma", "model User {\n  id Int @id\n}\n")
    write(tmp_path, "supabase/migrations/1.sql", "create table docs (id int);")
    write(tmp_path, "lib/ai.ts", "import OpenAI from 'openai'\nconst s = supabase.auth.getUser()\n")
    write(tmp_path, "app/api/chat/route.ts", "export async function POST() {}\n")
    subprocess.run(["git", "-C", str(tmp_path), "init", "-q"], check=True)

    d = detect(RepoIndex(tmp_path))
    assert d.languages == {"javascript/typescript": 3}
    assert d.frameworks == ["next"]
    assert d.databases == ["supabase"]
    assert d.orms == ["prisma"]
    assert d.auth_providers == ["supabase-auth"]
    assert d.hosting == ["vercel"]
    assert d.ci == [".github/workflows/ci.yml"]
    assert d.logging == ["sentry"]
    assert d.header_config == ["next.config.js"]
    assert d.rate_limiters == ["upstash-ratelimit"]
    assert d.test_frameworks == ["vitest"]
    assert [s.name for s in d.sdks] == ["openai", "sentry"]
    openai = d.sdks[0]
    assert (openai.category, openai.paid, openai.recipient) == ("llm", True, True)
    assert [str(loc) for loc in openai.locations] == ["lib/ai.ts:1"]
    assert [(r.method, r.path) for r in d.routes] == [("POST", "/api/chat")]
    assert [m.name for m in d.models] == ["User", "docs"]
    assert "public.docs" in d.schema.tables
    assert d.serverless is True
    assert d.public_supabase_key is True
    assert d.git.is_repo is True
    assert "next" in d.packages


def test_detect_django_app(tmp_path):
    write(tmp_path, "requirements.txt", "Django==5.0\ndjangorestframework\nsentry-sdk\n")
    write(tmp_path, "manage.py", "import django\n")
    write(
        tmp_path,
        "shop/settings.py",
        "SECURE_HSTS_SECONDS = 3600\nfrom django.contrib.auth import x\n",
    )
    write(tmp_path, "Dockerfile", "FROM python")
    d = detect(RepoIndex(tmp_path))
    assert d.frameworks == ["django", "djangorestframework"]
    assert d.orms == ["django-orm"]
    assert d.auth_providers == ["django-auth"]
    assert d.hosting == ["docker"]
    assert d.header_config == ["shop/settings.py"]
    assert d.serverless is False
    assert d.public_supabase_key is False
    assert d.git.is_repo is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/discovery/test_detect.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'dpr.discovery.detect'`

- [ ] **Step 3: Write the data files and implementation**

`src/dpr/data/stack.yaml`:

```yaml
frameworks:
  next: {packages: [next], files: ["next.config.*"]}
  nuxt: {packages: [nuxt]}
  remix: {packages: ["@remix-run/node", "@remix-run/react"]}
  astro: {packages: [astro]}
  sveltekit: {packages: ["@sveltejs/kit"]}
  express: {packages: [express]}
  fastify: {packages: [fastify]}
  nestjs: {packages: ["@nestjs/core"]}
  django: {packages: [django], files: [manage.py]}
  djangorestframework: {packages: [djangorestframework, rest-framework]}
  fastapi: {packages: [fastapi]}
  flask: {packages: [flask]}
databases:
  supabase: {packages: ["@supabase/supabase-js", "@supabase/ssr", supabase]}
  firebase: {packages: [firebase, firebase-admin]}
  postgres: {packages: [pg, postgres, psycopg, psycopg2, psycopg2-binary, asyncpg, "@neondatabase/serverless", "@vercel/postgres"]}
  mysql: {packages: [mysql2, pymysql, mysqlclient, "@planetscale/database"]}
  mongodb: {packages: [mongodb, mongoose, pymongo, motor]}
  sqlite: {packages: [better-sqlite3, "@libsql/client"]}
  dynamodb: {packages: ["@aws-sdk/client-dynamodb"]}
orms:
  prisma: {packages: [prisma, "@prisma/client"], files: ["*.prisma"]}
  drizzle: {packages: [drizzle-orm]}
  sequelize: {packages: [sequelize]}
  typeorm: {packages: [typeorm]}
  knex: {packages: [knex]}
  mongoose: {packages: [mongoose]}
  sqlalchemy: {packages: [sqlalchemy, flask-sqlalchemy]}
  django-orm: {packages: [django]}
  tortoise: {packages: [tortoise-orm]}
auth_providers:
  supabase-auth: {text: 'supabase\.auth\.'}
  clerk: {packages: ["@clerk/nextjs", "@clerk/clerk-sdk-node", "@clerk/express", "@clerk/clerk-react"]}
  auth0: {packages: ["@auth0/nextjs-auth0", "@auth0/auth0-react", auth0]}
  nextauth: {packages: [next-auth, "@auth/core"]}
  firebase-auth: {text: 'firebase/auth|firebase_admin\.auth'}
  passport: {packages: [passport]}
  lucia: {packages: [lucia]}
  better-auth: {packages: [better-auth]}
  django-auth: {text: 'django\.contrib\.auth'}
  fastapi-security: {text: 'fastapi\.security'}
  flask-login: {packages: [flask-login]}
hosting:
  vercel: {files: [vercel.json]}
  netlify: {files: [netlify.toml]}
  fly: {files: [fly.toml]}
  render: {files: [render.yaml]}
  railway: {files: [railway.json, railway.toml]}
  app-engine: {files: [app.yaml]}
  heroku: {files: [Procfile]}
  docker: {files: [Dockerfile, docker-compose.yml, docker-compose.yaml, compose.yaml]}
  serverless-framework: {files: [serverless.yml]}
  terraform: {files: ["*.tf"]}
logging:
  winston: {packages: [winston]}
  pino: {packages: [pino]}
  bunyan: {packages: [bunyan]}
  sentry: {packages: ["@sentry/nextjs", "@sentry/node", "@sentry/react", "@sentry/browser", sentry-sdk]}
  loguru: {packages: [loguru]}
  structlog: {packages: [structlog]}
  datadog: {packages: [dd-trace, ddtrace]}
rate_limiters:
  upstash-ratelimit: {packages: ["@upstash/ratelimit"]}
  express-rate-limit: {packages: [express-rate-limit]}
  rate-limiter-flexible: {packages: [rate-limiter-flexible]}
  fastify-rate-limit: {packages: ["@fastify/rate-limit"]}
  slowapi: {packages: [slowapi]}
  django-ratelimit: {packages: [django-ratelimit]}
  flask-limiter: {packages: [flask-limiter]}
test_frameworks:
  jest: {packages: [jest]}
  vitest: {packages: [vitest]}
  playwright: {packages: ["@playwright/test"]}
  cypress: {packages: [cypress]}
  mocha: {packages: [mocha]}
  pytest: {packages: [pytest]}
header_config:
  files: ["next.config.*", "middleware.[jt]s", nginx.conf, vercel.json, netlify.toml, _headers, settings.py]
  text: 'helmet|Content-Security-Policy|Strict-Transport-Security|X-Frame-Options|SECURE_HSTS|SECURE_CONTENT_TYPE_NOSNIFF'
serverless_hosting: [vercel, netlify, serverless-framework]
```

`src/dpr/data/sdks.yaml`:

```yaml
- {name: stripe, category: payments, recipient: true, paid: false, packages: [stripe, "@stripe/stripe-js", "@stripe/react-stripe-js"]}
- {name: paddle, category: payments, recipient: true, paid: false, packages: ["@paddle/paddle-js", "@paddle/paddle-node-sdk"]}
- {name: lemonsqueezy, category: payments, recipient: true, paid: false, packages: ["@lemonsqueezy/lemonsqueezy.js"]}
- {name: sendgrid, category: email, recipient: true, paid: true, packages: ["@sendgrid/mail", sendgrid]}
- {name: postmark, category: email, recipient: true, paid: true, packages: [postmark, postmarker]}
- {name: resend, category: email, recipient: true, paid: true, packages: [resend]}
- {name: mailgun, category: email, recipient: true, paid: true, packages: [mailgun.js, mailgun]}
- {name: nodemailer, category: email, recipient: true, paid: true, packages: [nodemailer]}
- {name: twilio, category: sms, recipient: true, paid: true, packages: [twilio]}
- {name: aws-s3, category: storage, recipient: true, paid: true, packages: ["@aws-sdk/client-s3", boto3]}
- {name: aws-ml, category: ml, recipient: true, paid: true, packages: ["@aws-sdk/client-textract", "@aws-sdk/client-rekognition", "@aws-sdk/client-transcribe"]}
- {name: openai, category: llm, recipient: true, paid: true, packages: [openai]}
- {name: anthropic, category: llm, recipient: true, paid: true, packages: ["@anthropic-ai/sdk", anthropic]}
- {name: google-ai, category: llm, recipient: true, paid: true, packages: ["@google/generative-ai", "@google/genai", google-generativeai, google-genai]}
- {name: replicate, category: llm, recipient: true, paid: true, packages: [replicate]}
- {name: segment, category: analytics, recipient: true, paid: false, packages: ["@segment/analytics-next", "@segment/analytics-node", analytics-node]}
- {name: mixpanel, category: analytics, recipient: true, paid: false, packages: [mixpanel, mixpanel-browser]}
- {name: amplitude, category: analytics, recipient: true, paid: false, packages: ["@amplitude/analytics-browser", "@amplitude/analytics-node", amplitude-js]}
- {name: posthog, category: analytics, recipient: true, paid: false, packages: [posthog-js, posthog-node, posthog]}
- {name: plausible, category: analytics, recipient: true, paid: false, packages: [plausible-tracker, next-plausible]}
- {name: sentry, category: error-tracking, recipient: true, paid: false, packages: ["@sentry/nextjs", "@sentry/node", "@sentry/react", "@sentry/browser", sentry-sdk]}
- {name: datadog, category: monitoring, recipient: true, paid: false, packages: [dd-trace, "@datadog/browser-rum", ddtrace]}
- {name: logrocket, category: session-replay, recipient: true, paid: false, packages: [logrocket]}
- {name: fullstory, category: session-replay, recipient: true, paid: false, packages: ["@fullstory/browser"]}
- {name: hotjar, category: session-replay, recipient: true, paid: false, packages: ["@hotjar/browser", react-hotjar]}
- {name: intercom, category: support, recipient: true, paid: false, packages: ["@intercom/messenger-js-sdk", react-use-intercom]}
- {name: crisp, category: support, recipient: true, paid: false, packages: [crisp-sdk-web]}
- {name: zendesk, category: support, recipient: true, paid: false, packages: [node-zendesk, zenpy]}
- {name: hubspot, category: crm, recipient: true, paid: false, packages: ["@hubspot/api-client", hubspot-api-client]}
- {name: mailchimp, category: email-marketing, recipient: true, paid: false, packages: ["@mailchimp/mailchimp_marketing", mailchimp-marketing]}
- {name: algolia, category: search, recipient: true, paid: true, packages: [algoliasearch]}
- {name: cloudinary, category: image, recipient: true, paid: true, packages: [cloudinary, next-cloudinary]}
- {name: uploadthing, category: storage, recipient: true, paid: true, packages: [uploadthing]}
- {name: google-maps, category: maps, recipient: true, paid: true, packages: ["@googlemaps/google-maps-services-js", "@react-google-maps/api", googlemaps]}
- {name: puppeteer, category: browser, recipient: false, paid: true, packages: [puppeteer, puppeteer-core]}
- {name: sharp, category: image, recipient: false, paid: true, packages: [sharp]}
```

`src/dpr/discovery/detect.py`:

```python
"""Build a Detection from one RepoIndex."""

from __future__ import annotations

import re

from dpr.data import load
from dpr.discovery.packages import collect_env_vars, collect_packages, normalise
from dpr.gitutil import git_info
from dpr.model import Detection, Location, SdkUse
from dpr.parsing.routes import extract_routes
from dpr.parsing.schemas import extract_models
from dpr.parsing.sqlschema import load_schema
from dpr.walk import RepoIndex


def _code_matches(index: RepoIndex, pattern: str) -> bool:
    regex = re.compile(pattern)
    return any(regex.search(index.text(f.rel)) for f in index.js_files + index.py_files)


def _match(signals: dict, index: RepoIndex, packages: set[str]) -> list[str]:
    found = []
    for name, spec in signals.items():
        if (
            any(normalise(p) in packages for p in spec.get("packages", []))
            or any(index.named(pattern) for pattern in spec.get("files", []))
            or (spec.get("text") and _code_matches(index, spec["text"]))
        ):
            found.append(name)
    return found


def _header_config(index: RepoIndex, spec: dict) -> list[str]:
    regex = re.compile(spec["text"])
    return sorted(f.rel for f in index.named(*spec["files"]) if regex.search(index.text(f.rel)))


def _sdks(packages: set[str], sites: dict[str, list[Location]]) -> list[SdkUse]:
    found = []
    for sdk in load("sdks.yaml"):
        names = [normalise(p) for p in sdk["packages"]]
        if not any(n in packages for n in names):
            continue
        locations = sorted(
            {loc for n in names for loc in sites.get(n, [])}, key=lambda loc: (loc.file, loc.line)
        )[:20]
        found.append(
            SdkUse(sdk["name"], sdk["category"], sdk["recipient"], sdk["paid"], tuple(locations))
        )
    return found


def detect(index: RepoIndex) -> Detection:
    stack = load("stack.yaml")
    packages, sites = collect_packages(index)
    schema = load_schema(index)
    env_vars = collect_env_vars(index)
    hosting = _match(stack["hosting"], index, packages)
    return Detection(
        languages=index.language_counts(),
        frameworks=_match(stack["frameworks"], index, packages),
        databases=_match(stack["databases"], index, packages),
        orms=_match(stack["orms"], index, packages),
        auth_providers=_match(stack["auth_providers"], index, packages),
        hosting=hosting,
        ci=sorted(f.rel for f in index.glob(".github/workflows/*")),
        logging=_match(stack["logging"], index, packages),
        header_config=_header_config(index, stack["header_config"]),
        rate_limiters=_match(stack["rate_limiters"], index, packages),
        test_frameworks=_match(stack["test_frameworks"], index, packages),
        env_vars=env_vars,
        sdks=_sdks(packages, sites),
        routes=extract_routes(index),
        models=extract_models(index, schema),
        git=git_info(index.root),
        serverless=any(h in stack["serverless_hosting"] for h in hosting),
        public_supabase_key=any(e.public and "SUPABASE" in e.name for e in env_vars),
        packages=packages,
        schema=schema,
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/discovery -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/data/stack.yaml src/dpr/data/sdks.yaml src/dpr/discovery/detect.py tests/discovery/test_detect.py
git commit -m "Add stack and SDK detection"
```

---

### Task 17: Question catalogue, answers and prompts

**Files:**
- Create: `src/dpr/data/questions.yaml`, `src/dpr/questions/__init__.py` (empty), `src/dpr/questions/catalogue.py`, `src/dpr/questions/prompt.py`
- Test: `tests/test_questions.py`

**Interfaces:**
- Consumes: `Detection`, `Question`, `QuestionResult`, `ScanError` (Task 2); `dpr.data.load` (Task 3)
- Produces:
  - `dpr.questions.catalogue.MAX_PROMPTS = 8`
  - `load_questions() -> list[Question]` (22 questions, catalogue order)
  - `questions_for(reviews: Iterable[str]) -> list[Question]`
  - `options(question, detection) -> list[str]` (values of the detection field named by `options_from`, then static options, then honest outs)
  - `resolve(questions, detection, answers=None, interactive=False, ask=None) -> tuple[list[QuestionResult], list[str]]`. `answers` is a path, a dict or `None`. Order of precedence: detection (`answered_by`), answers, `ask(question, options)` when `interactive` and `ask` is given (at most 8 prompts), else open with source `none`. An honest-out answer is recorded with `open=True`. Returns results in question order and warnings for unknown keys. Raises `ScanError` for a missing file, invalid YAML, or a file that is not a mapping.
  - `answers_template(questions, detection) -> str` (commented YAML with one empty key per question)
  - `dpr.questions.prompt.ask_on_terminal(question, options, input_fn=input, output=print) -> str | None`

- [ ] **Step 1: Write the failing test**

`tests/test_questions.py`:

```python
import pytest
import yaml

from dpr.model import Detection, Question, ScanError
from dpr.questions.catalogue import (
    answers_template,
    load_questions,
    options,
    questions_for,
    resolve,
)
from dpr.questions.prompt import ask_on_terminal

SLUGS = {"inventory", "rls", "auth", "baseline", "owasp", "leaks", "abuse"}


def test_catalogue_shape():
    questions = load_questions()
    assert len(questions) == 22
    assert len({q.id for q in questions}) == 22
    for q in questions:
        assert set(q.reviews) <= SLUGS
        assert q.type in ("choice", "multi", "text")
        assert q.why and q.who and q.text.endswith("?")
        assert all(isinstance(o, str) for o in q.static_options + q.honest_out)


def test_questions_for():
    assert [q.id for q in questions_for(["rls"])] == [
        "frontend_key_type",
        "rls_via_dashboard",
        "tables_not_in_migrations",
        "buckets_public",
    ]
    assert [q.id for q in questions_for(["leaks"])] == [
        "hosting_env_not_in_repo",
        "log_tool_access_retention",
    ]


def test_options_from_detection():
    [db_region] = [q for q in load_questions() if q.id == "db_region"]
    assert options(db_region, Detection(hosting=["vercel"])) == ["vercel", "Not sure"]


def test_resolve_from_dict():
    qs = questions_for(["rls"])
    results, warnings = resolve(
        qs,
        Detection(),
        {
            "frontend_key_type": "Anon or publishable key only",
            "rls_via_dashboard": "Not sure",
            "nonsense": 1,
        },
    )
    by_id = {r.question.id: r for r in results}
    assert [r.question.id for r in results] == [q.id for q in qs]
    assert (by_id["frontend_key_type"].open, by_id["frontend_key_type"].source) == (
        False,
        "answers",
    )
    assert (by_id["rls_via_dashboard"].open, by_id["rls_via_dashboard"].answer) == (
        True,
        "Not sure",
    )
    assert (by_id["buckets_public"].open, by_id["buckets_public"].source) == (True, "none")
    assert warnings == ["unknown answer key ignored: nonsense"]


def test_resolve_from_file_and_errors(tmp_path):
    good = tmp_path / "a.yaml"
    good.write_text("buckets_public: 'No'\n")
    results, _ = resolve(questions_for(["rls"]), Detection(), str(good))
    assert next(r for r in results if r.question.id == "buckets_public").answer == "No"
    with pytest.raises(ScanError, match="not found"):
        resolve([], Detection(), str(tmp_path / "missing.yaml"))
    bad = tmp_path / "bad.yaml"
    bad.write_text("a: [unclosed\n")
    with pytest.raises(ScanError, match="YAML"):
        resolve([], Detection(), str(bad))
    listy = tmp_path / "list.yaml"
    listy.write_text("- a\n")
    with pytest.raises(ScanError, match="mapping"):
        resolve([], Detection(), str(listy))


def test_interactive_is_capped_at_eight():
    calls = []

    def ask(question, opts):
        calls.append(question.id)
        return opts[-1] if opts else "Not sure"

    results, _ = resolve(load_questions(), Detection(), None, interactive=True, ask=ask)
    assert len(calls) == 8
    assert sum(r.source == "interactive" for r in results) == 8
    assert sum(r.source == "none" for r in results) == 14


def test_answered_by_detection():
    q = Question(
        id="x", reviews=("rls",), text="Host?", type="text", why="w", who="w", answered_by="hosting"
    )
    [result] = resolve([q], Detection(hosting=["vercel", "docker"]))[0]
    assert (result.answer, result.source, result.open) == ("vercel, docker", "detection", False)


def test_answers_template_is_valid_yaml():
    qs = questions_for(["inventory"])
    text = answers_template(qs, Detection(hosting=["vercel"]))
    assert "# Options: vercel, Not sure" in text
    assert yaml.safe_load(text) == {q.id: None for q in qs}


def test_ask_on_terminal():
    [q] = [x for x in load_questions() if x.id == "buckets_public"]
    printed = []
    assert ask_on_terminal(q, ["Yes", "No"], input_fn=lambda _: "2", output=printed.append) == "No"
    assert ask_on_terminal(q, ["Yes", "No"], input_fn=lambda _: "  ", output=printed.append) is None
    assert (
        ask_on_terminal(q, ["Yes"], input_fn=lambda _: "only avatars", output=printed.append)
        == "only avatars"
    )
    assert q.text in printed
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_questions.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'dpr.questions'`

- [ ] **Step 3: Write the data file and implementation**

Quote `"Yes"` and `"No"` in the YAML below. Unquoted, YAML reads them as booleans.

`src/dpr/data/questions.yaml`:

```yaml
questions:
  - id: user_countries
    reviews: [inventory]
    text: Which countries are your users in?
    type: multi
    static_options: [South Africa, United Kingdom, European Union, United States]
    why: Code does not record where users physically are.
    who: Founder or product owner
    lawyer: true
  - id: company_country
    reviews: [inventory]
    text: In which country is the company established?
    type: text
    why: Company registration is not in the repository.
    who: Founder
    lawyer: true
  - id: db_region
    reviews: [inventory]
    text: Which region are the database, object storage and backups provisioned in?
    type: choice
    options_from: hosting
    why: Regions are usually chosen in a provider dashboard, not in code.
    who: Whoever set up the hosting account
    lawyer: true
  - id: retention_policy
    reviews: [inventory]
    text: Is there a stated retention or deletion policy, even an informal one?
    type: text
    honest_out: [No formal policy, Not sure]
    why: A policy can exist without any deletion job in code.
    who: Founder or data owner
    lawyer: true
  - id: prod_access
    reviews: [inventory]
    text: Who on the team can open production data today?
    type: text
    why: Dashboard and database access is granted outside the repository.
    who: Whoever administers the hosting and database accounts
    lawyer: true
  - id: dpas_in_place
    reviews: [inventory]
    text: Do data processing agreements exist with the third parties found?
    type: choice
    static_options: [Yes for all, For some, None]
    why: Contracts are not stored in code.
    who: Founder or legal owner
    lawyer: true
  - id: data_outside_repo
    reviews: [inventory]
    text: Is personal data held anywhere outside this repository, such as a support inbox, CRM, spreadsheets, analytics dashboards or laptops?
    type: text
    why: Systems outside the repository are invisible to a code scan.
    who: The whole team
    lawyer: true
  - id: frontend_key_type
    reviews: [rls]
    text: Which database key does the deployed frontend ship?
    type: choice
    static_options: [Anon or publishable key only, A service key is also used in the browser]
    why: Deployed environment values are set in the hosting dashboard.
    who: Whoever manages the hosting environment variables
  - id: rls_via_dashboard
    reviews: [rls]
    text: Was row level security or any policy changed in the provider dashboard rather than in a migration?
    type: choice
    static_options: ["Yes", "No, migrations only"]
    why: Dashboard changes leave no trace in the repository.
    who: Whoever administers the database project
  - id: tables_not_in_migrations
    reviews: [rls]
    text: Do tables exist in production that no migration file creates?
    type: choice
    static_options: ["Yes", "No"]
    why: Only the live database can list its tables.
    who: Whoever administers the database project
  - id: buckets_public
    reviews: [rls]
    text: Are any storage buckets public?
    type: choice
    static_options: ["Yes", "No"]
    why: Buckets are often created in a dashboard.
    who: Whoever administers the storage project
  - id: provider_email_templates
    reviews: [auth]
    text: Which auth emails does the provider send, such as verification, reset, magic link or invite?
    type: text
    why: Email templates are often configured in a provider dashboard.
    who: Whoever administers the auth provider
  - id: provider_session_lifetimes
    reviews: [auth]
    text: What session and token lifetimes are configured in the auth provider?
    type: text
    why: Lifetimes are often set in provider settings.
    who: Whoever administers the auth provider
  - id: edge_protection
    reviews: [auth, baseline, owasp, abuse]
    text: Does a CDN or WAF in front of the app add headers, rate limits or blocking?
    type: choice
    static_options: ["Yes", "No"]
    why: Edge configuration lives outside the repository.
    who: Whoever manages DNS and the CDN
  - id: provider_hash_params
    reviews: [baseline]
    text: If a managed provider stores passwords, which hashing settings does it use?
    type: text
    why: Provider-side hashing parameters are not visible in code.
    who: Whoever administers the auth provider
  - id: tls_termination
    reviews: [baseline]
    text: Is TLS terminated somewhere that forwards plain HTTP inside the network?
    type: choice
    static_options: ["Yes", "No"]
    why: Load balancer and proxy settings live in infrastructure consoles.
    who: Whoever manages the infrastructure
  - id: prod_config_matches_repo
    reviews: [owasp]
    text: Does production run with the same configuration as the repository?
    type: choice
    static_options: ["Yes", "No"]
    why: Production overrides are set outside the repository.
    who: Whoever deploys the app
  - id: hosting_env_not_in_repo
    reviews: [leaks]
    text: Are environment variables set in the hosting dashboard that do not appear in the repository?
    type: choice
    static_options: ["Yes", "No"]
    why: Dashboard variables are not visible to a code scan.
    who: Whoever manages the hosting environment variables
  - id: log_tool_access_retention
    reviews: [leaks]
    text: Who can read the logging and error tracking tools, and how long do they keep data?
    type: text
    why: Seats and retention are configured in the vendor dashboards.
    who: Whoever administers the logging and error tracking accounts
  - id: traffic_peak
    reviews: [abuse]
    text: What is the heaviest legitimate use of a paid feature by one user in one hour?
    type: text
    why: Real traffic is not in the repository.
    who: Whoever reads the product analytics
  - id: spend_caps
    reviews: [abuse]
    text: Which spend caps or quotas are set in provider dashboards?
    type: text
    why: Caps and quotas are set in provider consoles.
    who: Whoever owns the provider billing accounts
  - id: alert_channel
    reviews: [abuse]
    text: Which alerting channel does the team actually read?
    type: text
    why: Team habits are not in code.
    who: The team lead
```

`src/dpr/questions/__init__.py`: empty file.

`src/dpr/questions/catalogue.py`:

```python
"""Questions the code cannot answer, and how answers are gathered."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path

import yaml

from dpr.data import load
from dpr.model import Detection, Question, QuestionResult, ScanError

MAX_PROMPTS = 8
Ask = Callable[[Question, list[str]], str | None]


def load_questions() -> list[Question]:
    return [
        Question(
            id=q["id"],
            reviews=tuple(q["reviews"]),
            text=q["text"],
            type=q["type"],
            why=q["why"],
            who=q["who"],
            options_from=q.get("options_from"),
            static_options=tuple(q.get("static_options", [])),
            honest_out=tuple(q.get("honest_out", ["Not sure"])),
            answered_by=q.get("answered_by"),
            lawyer=bool(q.get("lawyer", False)),
        )
        for q in load("questions.yaml")["questions"]
    ]


def questions_for(reviews: Iterable[str]) -> list[Question]:
    wanted = set(reviews)
    return [q for q in load_questions() if wanted & set(q.reviews)]


def options(question: Question, detection: Detection) -> list[str]:
    found = [str(v) for v in getattr(detection, question.options_from or "", None) or []]
    found += [o for o in question.static_options if o not in found]
    return found + [o for o in question.honest_out if o not in found]


def _read_answers(source: str | Path | dict | None) -> dict:
    if source is None:
        return {}
    if isinstance(source, dict):
        return source
    path = Path(source)
    if not path.is_file():
        raise ScanError(f"answers file not found: {source}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ScanError(f"answers file is not valid YAML: {source}") from exc
    if not isinstance(data, dict):
        raise ScanError("answers file must be a mapping of question id to answer")
    return data


def _as_text(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, list | tuple):
        return ", ".join(str(v) for v in value) or None
    return str(value).strip() or None


def resolve(
    questions: list[Question],
    detection: Detection,
    answers: str | Path | dict | None = None,
    interactive: bool = False,
    ask: Ask | None = None,
) -> tuple[list[QuestionResult], list[str]]:
    data = _read_answers(answers)
    known = {q.id for q in load_questions()} | {q.id for q in questions}
    warnings = [f"unknown answer key ignored: {key}" for key in data if key not in known]
    results: list[QuestionResult] = []
    prompts = 0
    for q in questions:
        detected = getattr(detection, q.answered_by, None) if q.answered_by else None
        if detected:
            results.append(QuestionResult(q, _as_text(detected), "detection", False))
            continue
        text = _as_text(data.get(q.id))
        if text is not None:
            results.append(QuestionResult(q, text, "answers", text in q.honest_out))
            continue
        if interactive and ask is not None and prompts < MAX_PROMPTS:
            prompts += 1
            text = _as_text(ask(q, options(q, detection)))
            if text is not None:
                results.append(QuestionResult(q, text, "interactive", text in q.honest_out))
                continue
        results.append(QuestionResult(q, None, "none", True))
    return results, warnings


def answers_template(questions: list[Question], detection: Detection) -> str:
    lines = [
        "# dpr answers file. Fill in what you know and leave the rest empty.",
        '# Honest answers such as "Not sure" are fine. They are listed as open questions.',
        "",
    ]
    for q in questions:
        lines.append(f"# {q.text}")
        opts = options(q, detection)
        if opts:
            lines.append(f"# Options: {', '.join(opts)}")
        lines.extend([f"{q.id}:", ""])
    return "\n".join(lines)
```

`src/dpr/questions/prompt.py`:

```python
"""Terminal prompts for --interactive."""

from __future__ import annotations

from collections.abc import Callable

from dpr.model import Question


def ask_on_terminal(
    question: Question,
    options: list[str],
    input_fn: Callable[[str], str] = input,
    output: Callable[[str], None] = print,
) -> str | None:
    output("")
    output(question.text)
    for number, option in enumerate(options, start=1):
        output(f"  {number}. {option}")
    raw = input_fn("Answer (number or text, empty to skip): ").strip()
    if not raw:
        return None
    if raw.isdigit() and 1 <= int(raw) <= len(options):
        return options[int(raw) - 1]
    return raw
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_questions.py -v`
Expected: PASS (9 tests)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/data/questions.yaml src/dpr/questions tests/test_questions.py
git commit -m "Add question catalogue with answers file, prompts and template"
```

---

### Task 18: Review registry

**Files:**
- Create: `src/dpr/reviews/__init__.py`
- Test: `tests/reviews/__init__.py` (empty), `tests/reviews/test_registry.py`

**Interfaces:**
- Consumes: `ScanError` (Task 2)
- Produces (in `dpr.reviews`):
  - `REVIEWS = ("inventory", "rls", "auth", "baseline", "owasp", "leaks", "abuse")` (review number is index + 1)
  - `TITLES: dict[str, str]`, `LABELS: dict[str, str]` (finding block prefix per review), `RUN_ORDER`
  - `number(slug) -> int`
  - `resolve_reviews(requested: Iterable[str | int]) -> list[str]` (accepts `all`, `1`..`7`, slugs; returns slugs in review number order; raises `ScanError` on unknown or empty input)
  - `available() -> dict[str, module]` (imports `dpr.reviews.<slug>` for each slug; a slug whose module does not exist yet is left out; any other import error is raised)
  - Every review module exposes `run(ctx: Context) -> ReviewSection | None`. It returns `None` when the review does not apply, after adding the reason to `ctx.not_covered`. Findings come from `dpr.rules.run_checks`, called by the pipeline, not by the module.

- [ ] **Step 1: Write the failing test**

`tests/reviews/__init__.py`: empty file.

`tests/reviews/test_registry.py`:

```python
import pytest

from dpr.model import ScanError
from dpr.reviews import LABELS, REVIEWS, RUN_ORDER, TITLES, available, number, resolve_reviews


def test_constants():
    assert number("inventory") == 1 and number("abuse") == 7
    assert set(TITLES) == set(REVIEWS) == set(LABELS) == set(RUN_ORDER)
    assert RUN_ORDER[-1] == "inventory"


def test_resolve_reviews():
    assert resolve_reviews(["all"]) == list(REVIEWS)
    assert resolve_reviews(["6", 2]) == ["rls", "leaks"]
    assert resolve_reviews(["LEAKS", "rls", "2"]) == ["rls", "leaks"]
    with pytest.raises(ScanError, match="unknown review"):
        resolve_reviews(["8"])
    with pytest.raises(ScanError, match="no reviews"):
        resolve_reviews([])


def test_available_only_lists_existing_modules():
    modules = available()
    assert set(modules) <= set(REVIEWS)
    for slug, module in modules.items():
        assert module.__name__ == f"dpr.reviews.{slug}"
        assert callable(module.run)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/reviews/test_registry.py -v`
Expected: FAIL with `ImportError: cannot import name 'LABELS' from 'dpr.reviews'` (or `ModuleNotFoundError`)

- [ ] **Step 3: Write the implementation**

`src/dpr/reviews/__init__.py`:

```python
"""Review numbers, slugs, titles and loading."""

from __future__ import annotations

import importlib
from collections.abc import Iterable
from types import ModuleType

from dpr.model import ScanError

REVIEWS = ("inventory", "rls", "auth", "baseline", "owasp", "leaks", "abuse")
TITLES = {
    "inventory": "Data inventory",
    "rls": "Database lock check",
    "auth": "Failure path test plan",
    "baseline": "Security baseline",
    "owasp": "OWASP sweep",
    "leaks": "Leak hunt",
    "abuse": "Abuse and bill guard",
}
LABELS = {
    "inventory": "INV",
    "rls": "RLS",
    "auth": "CASE",
    "baseline": "FIX",
    "owasp": "FINDING",
    "leaks": "LEAK",
    "abuse": "GUARD",
}
RUN_ORDER = ("leaks", "rls", "baseline", "auth", "owasp", "abuse", "inventory")


def number(slug: str) -> int:
    return REVIEWS.index(slug) + 1


def resolve_reviews(requested: Iterable[str | int]) -> list[str]:
    selected: set[str] = set()
    for item in requested:
        token = str(item).strip().lower()
        if token == "all":
            selected.update(REVIEWS)
        elif token.isdigit() and 1 <= int(token) <= len(REVIEWS):
            selected.add(REVIEWS[int(token) - 1])
        elif token in REVIEWS:
            selected.add(token)
        else:
            raise ScanError(f"unknown review: {item}. Use all, 1 to 7, or {', '.join(REVIEWS)}")
    if not selected:
        raise ScanError("no reviews selected")
    return [slug for slug in REVIEWS if slug in selected]


def available() -> dict[str, ModuleType]:
    modules: dict[str, ModuleType] = {}
    for slug in REVIEWS:
        name = f"dpr.reviews.{slug}"
        try:
            modules[slug] = importlib.import_module(name)
        except ModuleNotFoundError as exc:
            if exc.name != name:
                raise
    return modules
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/reviews/test_registry.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/reviews/__init__.py tests/reviews
git commit -m "Add review registry with number and slug selection"
```

---

### Task 19: Leak hunt, key and config checks

**Files:**
- Create: `src/dpr/reviews/leaks.py`, `src/dpr/data/rule_text/leaks_keys.yaml`
- Test: `tests/reviews/helpers.py`, `tests/reviews/test_leaks_keys.py`, `tests/reviews/test_rule_text.py`

**Interfaces:**
- Consumes: `Location`, `Part`, `ReviewSection`, `Tag` (Task 2); `rules.rule`, `make_finding`, `Context`, `run_checks` (Task 4); `line_of` (Task 5); `find_keys`, `is_secret_name`, `public_prefix`, `snippet` (Task 6); `jsts` (Task 7); `pyast` (Task 8); `detect` (Task 16)
- Produces:
  - Registered rules `LEAK-PUBLIC-SECRET`, `LEAK-HARDCODED-KEY`, `LEAK-KEY-IN-BUILD`, `LEAK-SOURCEMAP`, `LEAK-SENTRY-PII` (review `leaks`)
  - `dpr.reviews.leaks.ROTATE` (the sentence every key fix starts with)
  - `dpr.reviews.leaks.run(ctx) -> ReviewSection` with parts `text "What this review never prints"` and `findings "Leaks"`
  - `ctx.facts["sentry"]`: list of `Location` of error tracker init calls
  - `tests/reviews/helpers.py`: `write(root, rel, text)` and `findings_for(root, review, rule_id) -> list[Finding]`

- [ ] **Step 1: Write the failing tests**

`tests/reviews/helpers.py`:

```python
from dpr import reviews, rules
from dpr.discovery.detect import detect
from dpr.walk import RepoIndex


def write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def findings_for(root, review, rule_id, **options):
    reviews.available()
    index = RepoIndex(root)
    ctx = rules.Context(index=index, detection=detect(index), options=rules.Options(**options))
    return [f for f in rules.run_checks(review, ctx) if f.rule_id == rule_id]
```

`tests/reviews/test_rule_text.py`:

```python
from importlib.resources import files

from dpr import reviews, rules
from dpr.reviews.leaks import ROTATE

KEY_RULES = (
    "LEAK-PUBLIC-SECRET",
    "LEAK-HARDCODED-KEY",
    "LEAK-KEY-IN-BUILD",
    "LEAK-ENV-TRACKED",
    "LEAK-ENV-IN-HISTORY",
)


def test_rule_text_matches_registered_rules():
    reviews.available()
    assert set(rules._all_rule_text()) == set(rules.SPECS)


def test_every_key_fix_starts_with_rotate():
    reviews.available()
    for rule_id in KEY_RULES:
        if rule_id in rules.SPECS:
            assert rules.rule_text(rule_id).fix.startswith(ROTATE), rule_id


def test_rule_text_has_no_legal_verdicts_or_em_dashes():
    folder = files("dpr.data").joinpath("rule_text")
    for item in folder.iterdir():
        raw = item.read_text(encoding="utf-8")
        lowered = raw.lower()
        for phrase in (
            "compliant with",
            "complies with",
            "satisfies article",
            "satisfies section",
            "lawful basis is",
        ):
            assert phrase not in lowered, (item.name, phrase)
        assert "\u2014" not in raw, item.name
```

`tests/reviews/test_leaks_keys.py`:

```python
from dpr.model import Tag
from dpr.reviews.leaks import ROTATE
from tests.reviews.helpers import findings_for, write

LIVE = "sk_" + "live_" + "a1B2c3D4e5F6g7H8i9J0k1L2"
TEST = "sk_" + "test_" + "a1B2c3D4e5F6g7H8i9J0k1L2"


def test_public_secret(tmp_path):
    write(
        tmp_path,
        ".env.example",
        "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=\nNEXT_PUBLIC_SUPABASE_ANON_KEY=\nSUPABASE_SERVICE_ROLE_KEY=\n",
    )
    write(tmp_path, "lib/a.ts", "const k = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY\n")
    [f] = findings_for(tmp_path, "leaks", "LEAK-PUBLIC-SECRET")
    assert [str(loc) for loc in f.locations] == [".env.example:1", "lib/a.ts:1"]
    assert (f.tag, f.severity.value) == (Tag.CONFIRMED, "critical")
    assert f.fix.startswith(ROTATE)
    assert "rename NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY to SUPABASE_SERVICE_ROLE_KEY" in f.fix
    assert f.snippet is None


def test_hardcoded_key_live_and_test(tmp_path):
    write(
        tmp_path,
        "lib/stripe.ts",
        f'import Stripe from "stripe"\nexport const s = new Stripe("{LIVE}")\n',
    )
    write(tmp_path, "scripts/seed.py", f'KEY = "{TEST}"\n')
    found = {f.locations[0].file: f for f in findings_for(tmp_path, "leaks", "LEAK-HARDCODED-KEY")}
    live = found["lib/stripe.ts"]
    assert (live.locations[0].line, live.severity.value) == (2, "critical")
    assert "stripe-live-secret" in live.title
    assert LIVE not in (live.snippet or "") and "<redacted:stripe-live-secret>" in live.snippet
    assert found["scripts/seed.py"].severity.value == "high"


def test_key_in_build_output(tmp_path):
    write(tmp_path, "src/a.ts", "export {}\n")
    write(tmp_path, "dist/assets/main.js", f'var a="x";var k="{LIVE}";')
    [f] = findings_for(tmp_path, "leaks", "LEAK-KEY-IN-BUILD")
    assert str(f.locations[0]) == "dist/assets/main.js:1"
    assert f.snippet is None


def test_sourcemaps(tmp_path):
    write(
        tmp_path, "next.config.js", "module.exports = {\n  productionBrowserSourceMaps: true,\n}\n"
    )
    write(tmp_path, ".next/static/chunks/main.js.map", "{}")
    found = findings_for(tmp_path, "leaks", "LEAK-SOURCEMAP")
    assert sorted(str(f.locations[0]) for f in found) == [
        ".next/static/chunks/main.js.map:1",
        "next.config.js:2",
    ]


def test_sentry_pii(tmp_path):
    write(
        tmp_path,
        "sentry.client.config.ts",
        'import * as Sentry from "@sentry/nextjs"\nSentry.init({\n  dsn: "x",\n  sendDefaultPii: true,\n})\n',
    )
    write(
        tmp_path,
        "sentry.server.config.ts",
        'import * as Sentry from "@sentry/nextjs"\nSentry.init({ dsn: "x" })\n',
    )
    write(
        tmp_path,
        "sentry.edge.config.ts",
        'import * as Sentry from "@sentry/nextjs"\n'
        'Sentry.init({ dsn: "x", beforeSend(event) { return event } })\n',
    )
    write(
        tmp_path,
        "app/settings.py",
        "import sentry_sdk\nsentry_sdk.init(\n    dsn='x',\n    send_default_pii=True,\n)\n",
    )
    found = sorted(
        (f.locations[0].file, f.locations[0].line)
        for f in findings_for(tmp_path, "leaks", "LEAK-SENTRY-PII")
    )
    assert found == [
        ("app/settings.py", 4),
        ("sentry.client.config.ts", 4),
        ("sentry.server.config.ts", 2),
    ]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/reviews/test_leaks_keys.py tests/reviews/test_rule_text.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'dpr.reviews.leaks'`

- [ ] **Step 3: Write the rule text and implementation**

`src/dpr/data/rule_text/leaks_keys.yaml`:

```yaml
LEAK-PUBLIC-SECRET:
  title: Secret-looking variable ${name} has a public prefix
  effort_minutes: 15
  detail: ${name} starts with ${prefix}, so the build puts its value into code the browser downloads. The name suggests a credential, not a publishable key.
  attack: Open the site, open devtools, search the downloaded JavaScript for the value, then call the provider with it.
  blast: Whatever this credential grants. A service role key reads and writes every table and ignores row level security.
  fix: |-
    Rotate the key now. It already reached a browser or history; removing it from the next build does not undo that.
    Then rename ${name} to ${renamed} so it has no public prefix, move every call that uses it into server-only code, and redeploy.
  verify: After redeploying, search the built JavaScript for the old value and confirm the provider rejects the old key.
LEAK-HARDCODED-KEY:
  title: Hardcoded ${kind} key in source
  effort_minutes: 20
  detail: A ${kind} key is written directly in a source file, so everyone with repository access, and every build that includes the file, has it.
  attack: Anyone who can read the repository or a build artifact copies the key and uses it.
  blast: Whatever this key grants at the provider.
  fix: |-
    Rotate the key now. It already reached a browser or history; removing it from the next build does not undo that.
    Then read it from a server-side environment variable instead of the source file.
  verify: Confirm the provider rejects the old key and a fresh scan reports no hardcoded key here.
LEAK-KEY-IN-BUILD:
  title: ${kind} key in build output
  effort_minutes: 20
  detail: A ${kind} key appears in built files that are deployed or served to browsers.
  attack: Download the built file from the site and read the key out of it.
  blast: Whatever this key grants at the provider.
  fix: |-
    Rotate the key now. It already reached a browser or history; removing it from the next build does not undo that.
    Then find where the value enters the build, usually a public-prefixed variable, move the call behind your own server, rebuild and redeploy.
  verify: Rebuild, search the new build output for the key type, and confirm the provider rejects the old key.
LEAK-SOURCEMAP:
  title: Source maps ship to production
  effort_minutes: 10
  detail: ${what}
  attack: Download the .map file next to a JavaScript bundle and read the original source, including comments and internal endpoints.
  fix: Turn off production browser source maps, or upload them privately to the error tracker and delete them from the deployed output.
  verify: On the live site, request a bundle URL with .map appended and expect a 404.
LEAK-SENTRY-PII:
  title: Error tracker can send personal data
  effort_minutes: 10
  detail: ${what}
  blast: Error events can carry IP addresses, cookies, request bodies and user details to the error tracking vendor, readable by every seat on that account.
  fix: Set sendDefaultPii (send_default_pii in Python) to false unless the team decided otherwise, add a beforeSend (before_send) hook that removes request bodies, cookies and user fields, and list the error tracker as a data recipient in the inventory.
  verify: Trigger a test error and inspect the event in the error tracker for user, IP and request body fields.
```

`src/dpr/reviews/leaks.py`:

```python
"""Review 6, leak hunt: keys, public env names, build output and error tracker config."""

from __future__ import annotations

import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Part, ReviewSection, Tag
from dpr.parsing import jsts, pyast
from dpr.redact import find_keys, is_secret_name, public_prefix, snippet
from dpr.rules import Context, make_finding, rule
from dpr.walk import line_of

ROTATE = (
    "Rotate the key now. It already reached a browser or history; "
    "removing it from the next build does not undo that."
)
NEXT_SOURCEMAPS = re.compile(r"productionBrowserSourceMaps\s*:\s*true")
VITE_SOURCEMAPS = re.compile(r"\bsourcemap\s*:\s*(?:true|['\"](?:inline|hidden)['\"])")


@rule("LEAK-PUBLIC-SECRET", review="leaks", severity="critical", exploitability="high")
def public_secret(ctx: Context) -> Iterator[Finding]:
    for env in ctx.detection.env_vars:
        prefix = public_prefix(env.name)
        if prefix and is_secret_name(env.name):
            yield make_finding(
                "LEAK-PUBLIC-SECRET",
                tag=Tag.CONFIRMED,
                locations=env.locations,
                name=env.name,
                prefix=prefix,
                renamed=env.name[len(prefix) :],
            )


@rule("LEAK-HARDCODED-KEY", review="leaks", severity="critical", exploitability="high")
def hardcoded_key(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.files:
        text = ctx.index.text(entry.rel)
        for hit in find_keys(text):
            yield make_finding(
                "LEAK-HARDCODED-KEY",
                tag=Tag.CONFIRMED,
                locations=[Location(entry.rel, hit.line)],
                severity=None if hit.live else "high",
                snippet=snippet(text, hit.line),
                kind=hit.kind,
            )


@rule("LEAK-KEY-IN-BUILD", review="leaks", severity="critical", exploitability="high")
def key_in_build(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.build_files:
        text = entry.path.read_text(encoding="utf-8", errors="replace")
        for hit in find_keys(text):
            yield make_finding(
                "LEAK-KEY-IN-BUILD",
                tag=Tag.CONFIRMED,
                locations=[Location(entry.rel, hit.line)],
                severity=None if hit.live else "high",
                kind=hit.kind,
            )


@rule("LEAK-SOURCEMAP", review="leaks", severity="medium", exploitability="medium")
def sourcemaps(ctx: Context) -> Iterator[Finding]:
    maps = [f for f in ctx.index.build_files if f.name.endswith(".map")]
    if maps:
        yield make_finding(
            "LEAK-SOURCEMAP",
            tag=Tag.CONFIRMED,
            locations=[Location(f.rel, 1) for f in maps[:5]],
            what=f"{len(maps)} source map file(s) are in the build output.",
        )
    for entry in ctx.index.named("next.config.*", "vite.config.*"):
        text = ctx.index.text(entry.rel)
        pattern = NEXT_SOURCEMAPS if entry.name.startswith("next.") else VITE_SOURCEMAPS
        for match in pattern.finditer(text):
            line = line_of(text, match.start())
            yield make_finding(
                "LEAK-SOURCEMAP",
                tag=Tag.CONFIRMED,
                locations=[Location(entry.rel, line)],
                snippet=snippet(text, line),
                what=f"{entry.name} turns on source maps for the production build.",
            )


def _sentry_detail(sends_pii: bool, scrubs: bool) -> str:
    if sends_pii:
        extra = "" if scrubs else " There is no beforeSend hook to scrub events."
        return "The error tracker is set to send default personal data." + extra
    return "The error tracker is initialised without a beforeSend hook, so events are not scrubbed."


def _js_sentry(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.js_files:
        text = ctx.index.text(entry.rel)
        if "sentry" not in text.lower():
            continue
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for call in jsts.calls(tree, r"(?:\w+\.)?init"):
                args = jsts.arguments(call)
                pairs = jsts.object_pairs(args[0]) if args else {}
                if "dsn" not in pairs:
                    continue
                init_line = jsts.line(tree, call)
                ctx.facts.setdefault("sentry", []).append(Location(entry.rel, init_line))
                pii = pairs.get("sendDefaultPii")
                sends_pii = pii is not None and jsts.node_text(pii) == "true"
                scrubs = "beforeSend" in pairs
                if not sends_pii and scrubs:
                    continue
                line = jsts.line(tree, pii if sends_pii else call)
                yield make_finding(
                    "LEAK-SENTRY-PII",
                    tag=Tag.CONFIRMED,
                    locations=[Location(entry.rel, line)],
                    snippet=snippet(text, line),
                    what=_sentry_detail(sends_pii, scrubs),
                )


def _py_sentry(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if "sentry_sdk" not in text:
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        if tree is None:
            continue
        for call in pyast.calls(tree, r"sentry_sdk\.init"):
            ctx.facts.setdefault("sentry", []).append(Location(entry.rel, call.lineno))
            pii = pyast.kwarg(call, "send_default_pii")
            sends_pii = pyast.constant(pii) is True
            scrubs = pyast.kwarg(call, "before_send") is not None
            if not sends_pii and scrubs:
                continue
            line = pii.lineno if sends_pii else call.lineno
            yield make_finding(
                "LEAK-SENTRY-PII",
                tag=Tag.CONFIRMED,
                locations=[Location(entry.rel, line)],
                snippet=snippet(text, line),
                what=_sentry_detail(sends_pii, scrubs),
            )


@rule("LEAK-SENTRY-PII", review="leaks", severity="medium", exploitability="low")
def sentry_pii(ctx: Context) -> Iterator[Finding]:
    yield from _js_sentry(ctx)
    yield from _py_sentry(ctx)


def run(ctx: Context) -> ReviewSection:
    note = (
        "No secret value is printed in this report. Findings name the variable or key type "
        "and where it is. A key that reached a browser or git history must be rotated."
    )
    return ReviewSection(
        "leaks",
        [Part("text", "What this review never prints", body=note), Part("findings", "Leaks")],
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/reviews -v`
Expected: PASS (all tests in `tests/reviews`)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/reviews/leaks.py src/dpr/data/rule_text/leaks_keys.yaml tests/reviews
git commit -m "Add leak hunt checks for keys, public env names, build output and error tracker config"
```

---

### Task 20: Leak hunt, git, response and logging checks

**Files:**
- Create: `src/dpr/reviews/leaks_code.py`, `src/dpr/data/rule_text/leaks_code.yaml`, `src/dpr/data/pii_terms.yaml`
- Modify: `src/dpr/reviews/leaks.py` (import `leaks_code` so its rules register with the review)
- Test: `tests/reviews/test_leaks_code.py`

**Interfaces:**
- Consumes: everything Task 19 consumes, plus `run_git`, `tracked_files` (Task 15), `find_model` (Task 12), `dpr.data.load` (Task 3)
- Produces:
  - Registered rules `LEAK-ENV-TRACKED`, `LEAK-ENV-IN-HISTORY`, `LEAK-BROAD-RESPONSE`, `LEAK-SSR-PROPS`, `LEAK-LOGGED-PII` (review `leaks`)
  - `ctx.facts["logged_pii"]`: list of `Location`
  - When the folder is not a git repository, `ctx.not_covered` gets `git checks skipped: not a git repository or git is unavailable`

- [ ] **Step 1: Write the failing test**

`tests/reviews/test_leaks_code.py`:

```python
import subprocess

from tests.reviews.helpers import findings_for, write


def git(root, *args):
    subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "-c",
            "user.name=dpr",
            "-c",
            "user.email=dpr@example.invalid",
            *args,
        ],
        check=True,
        capture_output=True,
    )


def locs(found):
    return sorted(str(f.locations[0]) for f in found)


def test_env_tracked_and_in_history(tmp_path):
    git(tmp_path, "init", "-q")
    write(tmp_path, ".env.production", "OLD=1\n")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "add prod env")
    git(tmp_path, "rm", "-q", "--cached", ".env.production")
    (tmp_path / ".env.production").unlink()
    write(tmp_path, ".env", "A=1\n")
    write(tmp_path, ".env.example", "A=\n")
    write(tmp_path, "a.py", "x = 1\n")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "more")
    assert locs(findings_for(tmp_path, "leaks", "LEAK-ENV-TRACKED")) == [".env:1"]
    [history] = findings_for(tmp_path, "leaks", "LEAK-ENV-IN-HISTORY")
    assert str(history.locations[0]) == ".env.production:1"
    assert "Commit " in history.detail


def test_history_paths_are_relative_to_scanned_subfolder(tmp_path):
    git(tmp_path, "init", "-q")
    write(tmp_path, "web/.env.staging", "A=1\n")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "one")
    git(tmp_path, "rm", "-q", "web/.env.staging")
    write(tmp_path, "web/a.py", "x = 1\n")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "two")
    assert locs(findings_for(tmp_path / "web", "leaks", "LEAK-ENV-IN-HISTORY")) == [
        ".env.staging:1"
    ]


def test_git_checks_skipped_outside_repo(tmp_path):
    from dpr import reviews, rules
    from dpr.discovery.detect import detect
    from dpr.walk import RepoIndex

    write(tmp_path, "a.py", "x = 1\n")
    reviews.available()
    index = RepoIndex(tmp_path)
    ctx = rules.Context(index=index, detection=detect(index))
    rules.run_checks("leaks", ctx)
    assert "git checks skipped: not a git repository or git is unavailable" in ctx.not_covered


SCHEMA = "model User {\n  id Int @id\n  email String\n  passwordHash String\n}\nmodel Invoice {\n  id Int @id\n}\n"


def test_broad_response_js(tmp_path):
    write(tmp_path, "prisma/schema.prisma", SCHEMA)
    write(
        tmp_path,
        "app/api/users/[id]/route.ts",
        "export async function GET(req, { params }) {\n"
        "  const user = await prisma.user.findUnique({ where: { id: params.id } })\n"
        "  return NextResponse.json(user)\n}\n",
    )
    write(
        tmp_path,
        "app/api/invoices/[id]/route.ts",
        "export async function GET(req, { params }) {\n"
        "  return NextResponse.json(await prisma.invoice.findFirst({ where: { id: params.id } }))\n}\n",
    )
    write(
        tmp_path,
        "app/api/safe/route.ts",
        "export async function GET() {\n"
        "  const user = await prisma.user.findUnique({ where: { id: 1 }, select: { id: true } })\n"
        "  return NextResponse.json(user)\n}\n",
    )
    write(
        tmp_path,
        "app/api/profile/route.ts",
        "export async function GET() {\n"
        "  const { data } = await supabase.from('profiles').select('*').single()\n"
        "  return Response.json(data)\n}\n",
    )
    write(
        tmp_path,
        "app/actions.ts",
        '"use server"\nexport async function me() {\n  return prisma.user.findFirst({ where: { id: 1 } })\n}\n',
    )
    found = {str(f.locations[0]): f for f in findings_for(tmp_path, "leaks", "LEAK-BROAD-RESPONSE")}
    assert sorted(found) == [
        "app/actions.ts:3",
        "app/api/invoices/[id]/route.ts:2",
        "app/api/profile/route.ts:3",
        "app/api/users/[id]/route.ts:3",
    ]
    assert found["app/api/users/[id]/route.ts:3"].severity.value == "high"
    assert found["app/api/invoices/[id]/route.ts:2"].severity.value == "medium"
    assert found["app/api/profile/route.ts:3"].tag.value == "INFERRED"


def test_broad_response_python(tmp_path):
    write(
        tmp_path,
        "shop/serializers.py",
        "from rest_framework import serializers\n\n"
        "class UserSerializer(serializers.ModelSerializer):\n"
        '    class Meta:\n        model = User\n        fields = "__all__"\n',
    )
    write(
        tmp_path,
        "shop/urls.py",
        "from django.urls import path\nfrom . import views\n"
        "urlpatterns = [path('me/', views.me)]\n",
    )
    write(
        tmp_path,
        "shop/views.py",
        "from django.forms.models import model_to_dict\n\n"
        "def me(request):\n    return JsonResponse(model_to_dict(request.user))\n",
    )
    assert locs(findings_for(tmp_path, "leaks", "LEAK-BROAD-RESPONSE")) == [
        "shop/serializers.py:6",
        "shop/views.py:4",
    ]


def test_ssr_props(tmp_path):
    write(
        tmp_path,
        "pages/account.tsx",
        "export async function getServerSideProps() {\n"
        "  const user = await prisma.user.findUnique({ where: { id: 1 } })\n"
        "  return { props: { user } }\n}\n"
        "export default function Page() { return null }\n",
    )
    assert locs(findings_for(tmp_path, "leaks", "LEAK-SSR-PROPS")) == ["pages/account.tsx:3"]


def test_logged_pii(tmp_path):
    write(
        tmp_path,
        "app/api/signup/route.ts",
        "export async function POST(req) {\n"
        "  const body = await req.json()\n"
        "  try {\n    await prisma.user.create({ data: body })\n"
        "  } catch (err) {\n"
        "    console.error('signup failed', body)\n"
        "    console.error(err)\n"
        "    console.error('signup failed', { requestId })\n"
        "  }\n"
        "  try { parse() } catch (e) { console.log(e) }\n"
        "  logger.info(JSON.stringify(req.headers))\n"
        "}\n",
    )
    write(
        tmp_path,
        "svc/views.py",
        "import logging, traceback\nlogger = logging.getLogger(__name__)\n\n"
        "def create(request):\n"
        "    logger.error(f'bad input {request.data}')\n"
        "    try:\n        Invoice.objects.create(**request.data)\n"
        "    except Exception as e:\n        print(e)\n        traceback.print_exc()\n"
        "    try:\n        parse()\n    except ValueError as e:\n        print(e)\n",
    )
    assert locs(findings_for(tmp_path, "leaks", "LEAK-LOGGED-PII")) == [
        "app/api/signup/route.ts:11",
        "app/api/signup/route.ts:6",
        "app/api/signup/route.ts:7",
        "svc/views.py:10",
        "svc/views.py:5",
        "svc/views.py:9",
    ]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/reviews/test_leaks_code.py -v`
Expected: FAIL (no `LEAK-ENV-TRACKED` findings are produced, and `KeyError` or empty lists for the other rules)

- [ ] **Step 3: Write the data files and implementation**

`src/dpr/data/pii_terms.yaml`:

```yaml
sensitive_columns: [password, hash, token, secret, stripe_customer_id, role]
```

`src/dpr/data/rule_text/leaks_code.yaml`:

```yaml
LEAK-ENV-TRACKED:
  title: Environment file ${path} is tracked in git
  effort_minutes: 20
  detail: git tracks ${path}. Everyone with repository access, and every clone and backup, has its values.
  blast: Every credential in the file.
  fix: |-
    Rotate the key now. It already reached a browser or history; removing it from the next build does not undo that.
    Rotate every credential in ${path}, run git rm --cached ${path}, add it to .gitignore, and commit.
  verify: Run git ls-files and confirm no .env file is listed except example files.
LEAK-ENV-IN-HISTORY:
  title: Environment file ${path} is in git history
  effort_minutes: 30
  detail: Commit ${commit} added ${path}. It is no longer tracked, but every clone still has it in history.
  blast: Every credential that was in the file when it was committed.
  fix: |-
    Rotate the key now. It already reached a browser or history; removing it from the next build does not undo that.
    Rotate every credential that was in ${path}. Rewriting history is optional once the old values no longer work.
  verify: Confirm each provider rejects the old credentials.
LEAK-BROAD-RESPONSE:
  title: Response returns a whole ${source} record
  effort_minutes: 15
  detail: ${what}
  proof_needed: Compare the fields in this response with the fields the page or client actually reads.
  attack: Call the endpoint as a normal user and read the extra fields of the JSON response in devtools.
  blast: Every field of the record, for every record this endpoint returns.
  fix: Return an explicit allowlist of fields at the boundary, such as a Prisma select, a serializer with named fields, or a response model. Do not use a denylist; the next migration adds a column it does not know about.
  verify: Call the endpoint and confirm the JSON holds only the fields the UI uses.
LEAK-SSR-PROPS:
  title: Server-rendered props include a whole record
  effort_minutes: 15
  detail: ${what}
  proof_needed: Open the page source and check which fields of the record appear in the serialized props.
  attack: View the page source and read the serialized props, including fields the page never renders.
  blast: Every field of the record, for every visitor who can load the page.
  fix: Select only the fields the page renders before returning props.
  verify: View the page source and confirm only rendered fields appear in the props payload.
LEAK-LOGGED-PII:
  title: Log call may write personal data
  effort_minutes: 10
  detail: ${what}
  proof_needed: Check what this value holds at runtime and who can read the log destination.
  blast: Everyone with access to the logs, the log platform, and anything that keeps them for its retention period.
  fix: Log a request id and an error code instead of the object. If personal data must be logged, list the log destination as a data store in the review 1 inventory.
  verify: Trigger the path in a test and inspect the log line.
```

`src/dpr/reviews/leaks_code.py`:

```python
"""Review 6, leak hunt: git history, over-broad responses and personal data in logs."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from pathlib import PurePosixPath

from dpr.data import load
from dpr.gitutil import run_git, tracked_files
from dpr.model import Finding, Location, Tag
from dpr.parsing import jsts, pyast
from dpr.parsing.schemas import find_model
from dpr.redact import snippet
from dpr.rules import Context, make_finding, rule

ENV_NAME = re.compile(r"^\.env(\..+)?$")
ENV_EXAMPLE = re.compile(r"\.(example|sample|template)$")
RESPONSE_CALL = re.compile(r"(?:NextResponse|Response)\.json|res\.(?:json|send)|reply\.send|json")
ORM_READ = re.compile(
    r"(?:prisma|db|tx)\.(\w+)\.(findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow|findMany)"
)
SUPABASE_ALL = re.compile(r"\.select\(\s*(?:['\"`]\*['\"`])?\s*\)")
SUPABASE_TABLE = re.compile(r"\.from\(\s*['\"`](\w+)['\"`]\s*\)")
SELECT_STAR = re.compile(r"select\s+\*", re.IGNORECASE)
JS_ROUTE_FRAMEWORKS = ("next-app", "next-pages", "next-action", "express", "fastify")
PY_ROUTE_FRAMEWORKS = ("django", "drf", "fastapi", "flask")
LOG_CALL = re.compile(
    r"console\.(?:log|error|warn|info|debug)|(?:logger|log)\.(?:info|error|warn|debug|log|fatal)"
)
PY_LOG_CALL = re.compile(
    r"print|logging\.(?:debug|info|warning|error|exception|critical)"
    r"|(?:logger|log|LOGGER)\.(?:debug|info|warning|error|exception|critical)"
)
SENSITIVE_ROOTS = frozenset(
    {"req", "request", "body", "user", "token", "payload", "headers", "session", "password"}
)
ERROR_NAMES = frozenset({"err", "error", "e", "exc"})
OBJECT_LOGGED = "A request, user, token or database error object is written to the log."
TRACEBACK_LOGGED = "A full traceback, with local values in the message, is printed to the log."
JS_DB = re.compile(r"prisma\.|supabase\.|\bdb\.|\.query\(|\.execute\(|knex|sequelize|mongoose")
PY_DB = re.compile(r"\.objects\.|session\.|cursor\.|\.execute\(|\.query\(")


def _is_real_env(path: str) -> bool:
    name = PurePosixPath(path).name
    return bool(ENV_NAME.match(name)) and not ENV_EXAMPLE.search(name)


@rule("LEAK-ENV-TRACKED", review="leaks", severity="critical", exploitability="high")
def env_tracked(ctx: Context) -> Iterator[Finding]:
    tracked = tracked_files(ctx.index.root)
    if tracked is None:
        ctx.not_covered.append("git checks skipped: not a git repository or git is unavailable")
        return
    for path in tracked:
        if _is_real_env(path):
            yield make_finding(
                "LEAK-ENV-TRACKED", tag=Tag.CONFIRMED, locations=[Location(path, 1)], path=path
            )


@rule("LEAK-ENV-IN-HISTORY", review="leaks", severity="high", exploitability="medium")
def env_in_history(ctx: Context) -> Iterator[Finding]:
    root = ctx.index.root
    output = run_git(
        root,
        "log",
        "--all",
        "--diff-filter=A",
        "--name-only",
        "--format=commit %h",
        "--",
        ":(glob)**/.env",
        ":(glob)**/.env.*",
    )
    if output is None:
        return
    prefix = (run_git(root, "rev-parse", "--show-prefix") or "").strip()
    tracked = set(tracked_files(root) or [])
    first_seen: dict[str, str] = {}
    commit = ""
    for line in output.splitlines():
        if line.startswith("commit "):
            commit = line.split(" ", 1)[1].strip()
            continue
        path = line.strip()
        if not path.startswith(prefix):
            continue
        path = path[len(prefix) :]
        if path and _is_real_env(path) and path not in tracked:
            first_seen.setdefault(path, commit)
    for path, sha in first_seen.items():
        yield make_finding(
            "LEAK-ENV-IN-HISTORY",
            tag=Tag.CONFIRMED,
            locations=[Location(path, 1)],
            path=path,
            commit=sha,
        )


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def _severity(ctx: Context, name: str | None) -> str:
    model = find_model(ctx.detection.models, name) if name else None
    words = load("pii_terms.yaml")["sensitive_columns"]
    if model and any(word in _snake(f.name) for f in model.fields for word in words):
        return "high"
    return "medium"


def _destructured(ident) -> object | None:
    name = jsts.node_text(ident)
    scope = jsts.enclosing_function(ident)
    if scope is None:
        return None
    for decl in jsts.walk(scope, {"variable_declarator"}):
        pattern = decl.child_by_field_name("name")
        if pattern is None or pattern.type != "object_pattern":
            continue
        if decl.start_byte > ident.start_byte:
            continue
        shorthand = jsts.walk(pattern, {"shorthand_property_identifier_pattern"})
        names = {jsts.node_text(n) for n in shorthand}
        for pair in jsts.walk(pattern, {"pair_pattern"}):
            names.add(jsts.node_text(pair.child_by_field_name("value")))
        if name in names:
            return jsts.unwrap(decl.child_by_field_name("value"))
    return None


def _record_source(node) -> tuple[str | None, str | None]:
    node = jsts.unwrap(node)
    if node is not None and node.type in ("identifier", "shorthand_property_identifier"):
        node = jsts.resolve_identifier(node) or _destructured(node)
    if node is None:
        return None, None
    if node.type == "call_expression":
        match = ORM_READ.fullmatch(jsts.callee(node))
        if match:
            args = jsts.arguments(node)
            if args and "select" in jsts.object_pairs(args[0]):
                return None, None
            return "Prisma", match.group(1)
    text = jsts.node_text(node)
    if SUPABASE_ALL.search(text):
        table = SUPABASE_TABLE.search(text)
        return "Supabase", table.group(1) if table else None
    if SELECT_STAR.search(text):
        return "SQL", None
    return None, None


def _broad(
    ctx: Context,
    rel: str,
    line: int,
    source: str,
    name: str | None,
    rule_id: str = "LEAK-BROAD-RESPONSE",
) -> Finding:
    what = (
        f"This response sends every field of the {name or 'queried'} record, "
        "not only the ones the client needs."
    )
    return make_finding(
        rule_id,
        tag=Tag.INFERRED,
        locations=[Location(rel, line)],
        severity=_severity(ctx, name),
        snippet=snippet(ctx.index.text(rel), line),
        source=source,
        what=what,
    )


def _js_responses(ctx: Context) -> Iterator[Finding]:
    for route in ctx.detection.routes:
        handler = route.handler
        if route.framework not in JS_ROUTE_FRAMEWORKS or handler is None:
            continue
        if handler.type not in jsts.FUNCTION_TYPES:
            continue
        candidates = [
            jsts.arguments(c)[0]
            for c in jsts.calls(route.tree, RESPONSE_CALL, handler)
            if jsts.arguments(c)
        ]
        if route.framework == "next-action":
            candidates += [
                r.named_children[0]
                for r in jsts.walk(handler, {"return_statement"})
                if r.named_children
            ]
        for node in candidates:
            source, name = _record_source(node)
            if source:
                yield _broad(ctx, route.file, jsts.line(route.tree, node), source, name)


def _py_responses(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.py_files:
        if "ModelSerializer" not in ctx.index.text(entry.rel):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for cls in pyast.class_defs(tree) if tree else []:
            if not any(b.endswith("ModelSerializer") for b in pyast.base_names(cls)):
                continue
            metas = [n for n in cls.body if isinstance(n, ast.ClassDef) and n.name == "Meta"]
            meta = metas[0] if metas else None
            values = pyast.assignments(meta.body) if meta else {}
            if pyast.constant(values.get("fields")) == "__all__":
                model = (pyast.dotted(values.get("model")) or "").split(".")[-1] or None
                yield _broad(ctx, entry.rel, values["fields"].lineno, "Django", model)
    for route in ctx.detection.routes:
        if route.framework not in PY_ROUTE_FRAMEWORKS or route.handler is None:
            continue
        for node in ast.walk(route.handler):
            dumps_all = isinstance(node, ast.Call) and pyast.dotted(node.func) in (
                "model_to_dict",
                "vars",
            )
            whole = dumps_all or (isinstance(node, ast.Attribute) and node.attr == "__dict__")
            if whole:
                yield _broad(ctx, route.file, node.lineno, "Django", None)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                if SELECT_STAR.search(node.value):
                    yield _broad(ctx, route.file, node.lineno, "SQL", None)


@rule("LEAK-BROAD-RESPONSE", review="leaks", severity="medium", exploitability="medium")
def broad_response(ctx: Context) -> Iterator[Finding]:
    yield from _js_responses(ctx)
    yield from _py_responses(ctx)


@rule("LEAK-SSR-PROPS", review="leaks", severity="medium", exploitability="medium")
def ssr_props(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.js_files:
        text = ctx.index.text(entry.rel)
        if not re.search(r"getServerSideProps|getStaticProps|\bloader\b", text):
            continue
        for tree in jsts.parse_file(ctx.index, entry.rel):
            exported = jsts.exported_functions(tree)
            for name in ("getServerSideProps", "getStaticProps", "loader"):
                fn = exported.get(name)
                for ret in jsts.walk(fn, {"return_statement"}) if fn is not None else []:
                    value = jsts.unwrap(ret.named_children[0]) if ret.named_children else None
                    if value is None:
                        continue
                    if value.type == "call_expression" and jsts.callee(value) == "json":
                        values = jsts.arguments(value)[:1]
                    elif value.type == "object":
                        props = jsts.object_pairs(value).get("props")
                        values = list(jsts.object_pairs(props).values()) if props else []
                    else:
                        values = [value]
                    for item in values:
                        source, model = _record_source(item)
                        if source:
                            yield _broad(
                                ctx,
                                entry.rel,
                                jsts.line(tree, ret),
                                source,
                                model,
                                rule_id="LEAK-SSR-PROPS",
                            )


def _catch_has_db(ident) -> bool:
    name = jsts.node_text(ident)
    node = ident.parent
    while node is not None:
        if node.type == "catch_clause":
            param = node.child_by_field_name("parameter")
            if param is not None and jsts.node_text(param) == name:
                body = node.parent.child_by_field_name("body") if node.parent else None
                return body is not None and bool(JS_DB.search(jsts.node_text(body)))
        node = node.parent
    return False


def _js_sensitive(arg) -> bool:
    arg = jsts.unwrap(arg)
    if arg is None:
        return False
    if arg.type == "shorthand_property_identifier":
        return jsts.node_text(arg) in SENSITIVE_ROOTS
    if arg.type in ("call_expression", "new_expression"):
        return any(_js_sensitive(a) for a in jsts.arguments(arg))
    if arg.type == "object":
        return any(_js_sensitive(v) for v in jsts.object_pairs(arg).values())
    if arg.type == "template_string":
        return any(
            _js_sensitive(s.named_children[0])
            for s in arg.named_children
            if s.type == "template_substitution" and s.named_children
        )
    root = jsts.member_root(arg)
    if root in SENSITIVE_ROOTS:
        return True
    if root in ERROR_NAMES:
        base = arg
        while base.type in ("member_expression", "subscript_expression"):
            base = jsts.unwrap(base.child_by_field_name("object"))
        return _catch_has_db(base)
    return False


def _py_sensitive(node: ast.AST, tree: ast.Module, line: int) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(
            _py_sensitive(v.value, tree, line)
            for v in node.values
            if isinstance(v, ast.FormattedValue)
        )
    if isinstance(node, ast.Call) and pyast.dotted(node.func) in ("json.dumps", "str", "repr"):
        return any(_py_sensitive(a, tree, line) for a in node.args)
    root = pyast.name_root(node)
    if root in SENSITIVE_ROOTS:
        return True
    if root in ERROR_NAMES:
        for block in ast.walk(tree):
            if not isinstance(block, ast.Try):
                continue
            for handler in block.handlers:
                inside = handler.lineno <= line <= (handler.end_lineno or handler.lineno)
                if handler.name == root and inside:
                    return bool(PY_DB.search("\n".join(ast.unparse(s) for s in block.body)))
    return False


def _logged(ctx: Context, rel: str, line: int, what: str) -> Finding:
    ctx.facts.setdefault("logged_pii", []).append(Location(rel, line))
    return make_finding(
        "LEAK-LOGGED-PII",
        tag=Tag.INFERRED,
        locations=[Location(rel, line)],
        snippet=snippet(ctx.index.text(rel), line),
        what=what,
    )


@rule("LEAK-LOGGED-PII", review="leaks", severity="medium", exploitability="low")
def logged_pii(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.js_files:
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for call in jsts.calls(tree, LOG_CALL):
                if any(_js_sensitive(a) for a in jsts.arguments(call)):
                    yield _logged(ctx, entry.rel, jsts.line(tree, call), OBJECT_LOGGED)
    for entry in ctx.index.py_files:
        tree = pyast.parse_file(ctx.index, entry.rel)
        if tree is None:
            continue
        for call in pyast.calls(tree, PY_LOG_CALL):
            if any(_py_sensitive(a, tree, call.lineno) for a in call.args):
                yield _logged(ctx, entry.rel, call.lineno, OBJECT_LOGGED)
        for call in pyast.calls(tree, r"traceback\.print_exc"):
            yield _logged(ctx, entry.rel, call.lineno, TRACEBACK_LOGGED)
```

Modify `src/dpr/reviews/leaks.py`: insert this line between `from dpr.redact import ...` and `from dpr.rules import ...`, so loading the review registers the rules from both files:

```python
from dpr.reviews import leaks_code  # noqa: F401  (registers the leaks_code rules)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/reviews -v`
Expected: PASS (all tests in `tests/reviews`)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/reviews src/dpr/data/rule_text/leaks_code.yaml src/dpr/data/pii_terms.yaml tests/reviews/test_leaks_code.py
git commit -m "Add leak hunt checks for git history, broad responses and logged personal data"
```

---

### Task 21: RLS review, tables, views, functions, buckets and section

**Files:**
- Create: `src/dpr/reviews/rls_common.py`, `src/dpr/reviews/rls.py`, `src/dpr/data/rule_text/rls_tables.yaml`
- Test: `tests/reviews/test_rls_tables.py`

**Interfaces:**
- Consumes: `Location`, `Part`, `ReviewSection`, `Tag` (Task 2); `rules` (Task 4); `line_of` (Task 5); `jsts` (Task 7); `SchemaState`, `TableDef`, `Policy`, `apply_dump` (Task 10); `detect` (Task 16); `tests.reviews.helpers` (Task 19)
- Produces:
  - `dpr.reviews.rls_common`: `OWNER_COLUMNS`, `TENANT_COLUMNS`, `MEMBERSHIP_WORDS`, `AUTH_REF` (regex for `auth.uid(` or `auth.jwt(`), `owner_column(table)`, `tenant_column(table)`, `membership_table(state, tenant)`, `predicate(state, table) -> str | None`, `qualified(key)`, `policies_sql(state, table) -> str`, `replacement_sql(state, policy) -> str`, `sql_block(sql) -> str`, `confirm_commands(table_name) -> str`, `DASHBOARD_QUERIES`, `state_for(ctx) -> SchemaState` (the detected schema with `--db-dump` applied, cached in `ctx.facts["rls.state"]`), `client_facing(ctx) -> bool`, `public_tables(ctx) -> list[TableDef]` (empty when not client facing), `has_owner_or_unknown(table) -> bool`, `predicate_text(policy) -> str`
  - Registered rules `RLS-TABLE-OFF`, `RLS-NO-POLICIES`, `RLS-SELECT-ONLY`, `RLS-VIEW-BYPASS`, `RLS-DEFINER-FUNCTION`, `RLS-PUBLIC-BUCKET` (review `rls`)
  - `dpr.reviews.rls.run(ctx) -> ReviewSection | None`. `None` with `Review 2 (rls): not applicable, no SQL tables, Supabase client or database dump found` in `ctx.not_covered` when nothing applies. A server-only data layer gives a section with one `Relevance` text part. Otherwise parts: table `Table protection status`, findings `Policy defects`, text `Missing policies (runnable SQL)` (when gaps exist), text `How to confirm from outside the app`, text `Confirm in the database`.

- [ ] **Step 1: Write the failing test**

`tests/reviews/test_rls_tables.py`:

```python
from dpr import reviews, rules
from dpr.discovery.detect import detect
from dpr.walk import RepoIndex
from tests.reviews.helpers import findings_for, write

MIG = """create table public.invoices (id bigserial primary key, user_id uuid not null, amount int);
create table public.documents (id bigserial primary key, user_id uuid, body text);
alter table public.documents enable row level security;
create policy "documents_read" on public.documents for select using (auth.uid() = user_id);
create table public.members (org_id uuid, user_id uuid);
alter table public.members enable row level security;
create table public.lookup (code text primary key);
alter table public.lookup enable row level security;
create policy lookup_read on public.lookup for select using (true);
create view public.document_list as select id, body from public.documents;
create view public.safe_list with (security_invoker = true) as select id from public.documents;
create function public.all_docs() returns setof public.documents language sql security definer as $$ select * from public.documents $$;
create function public.util() returns int language sql security definer set search_path = '' as $$ select 1 $$;
insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true), ('private', 'private', false);
create table audit.events (id int);
"""


def app(tmp_path, public_key=True):
    write(tmp_path, "supabase/migrations/001_init.sql", MIG)
    if public_key:
        write(tmp_path, ".env.example", "NEXT_PUBLIC_SUPABASE_ANON_KEY=\n")
    write(
        tmp_path,
        "lib/q.ts",
        "export const q = () => supabase.from('invoices').select('id')\n"
        "export const b = () => supabase.storage.createBucket('uploads', { public: true })\n",
    )
    return tmp_path


def lines(found):
    return sorted((f.locations[0].file, f.locations[0].line) for f in found)


def test_table_off(tmp_path):
    [f] = findings_for(app(tmp_path), "rls", "RLS-TABLE-OFF")
    assert (str(f.locations[0]), f.severity.value, f.tag.value) == (
        "supabase/migrations/001_init.sql:1",
        "critical",
        "CONFIRMED",
    )
    assert "alter table public.invoices enable row level security;" in f.fix
    assert "for select using (auth.uid() = user_id);" in f.fix
    assert "rest/v1/invoices" in f.verify


def test_table_level_rules(tmp_path):
    root = app(tmp_path)
    mig = "supabase/migrations/001_init.sql"
    assert lines(findings_for(root, "rls", "RLS-NO-POLICIES")) == [(mig, 6)]
    assert lines(findings_for(root, "rls", "RLS-SELECT-ONLY")) == [(mig, 4), (mig, 9)]
    assert lines(findings_for(root, "rls", "RLS-VIEW-BYPASS")) == [(mig, 10)]
    definer = {f.locations[0].line: f for f in findings_for(root, "rls", "RLS-DEFINER-FUNCTION")}
    assert (definer[12].severity.value, definer[13].severity.value) == ("high", "medium")
    assert "does not set search_path" in definer[12].detail
    assert lines(findings_for(root, "rls", "RLS-PUBLIC-BUCKET")) == [("lib/q.ts", 2), (mig, 14)]


def test_server_only_data_layer_reports_nothing(tmp_path):
    root = app(tmp_path, public_key=False)
    assert findings_for(root, "rls", "RLS-TABLE-OFF") == []
    reviews.available()
    index = RepoIndex(root)
    ctx = rules.Context(index=index, detection=detect(index))
    section = reviews.available()["rls"].run(ctx)
    assert [p.title for p in section.parts] == ["Relevance"]


def test_not_applicable(tmp_path):
    write(tmp_path, "a.py", "x = 1\n")
    index = RepoIndex(tmp_path)
    ctx = rules.Context(index=index, detection=detect(index))
    assert reviews.available()["rls"].run(ctx) is None
    assert ctx.not_covered == [
        "Review 2 (rls): not applicable, no SQL tables, Supabase client or database dump found"
    ]


def test_section_parts_and_breakage_note(tmp_path):
    index = RepoIndex(app(tmp_path))
    ctx = rules.Context(index=index, detection=detect(index))
    section = reviews.available()["rls"].run(ctx)
    assert [p.title for p in section.parts] == [
        "Table protection status",
        "Policy defects",
        "Missing policies (runnable SQL)",
        "How to confirm from outside the app",
        "Confirm in the database",
    ]
    table = section.parts[0]
    assert [r[0] for r in table.rows] == [
        "public.documents",
        "public.invoices",
        "public.lookup",
        "public.members",
    ]
    invoices = next(r for r in table.rows if r[0] == "public.invoices")
    assert invoices[1:5] == ("no", "0", "yes, every row", "exposed")
    missing = section.parts[2].body
    assert "public.invoices" in missing and "public.members" in missing
    assert "`lib/q.ts:1`" in missing
    assert "pg_policies" in section.parts[4].body


def test_db_dump_is_source_of_truth(tmp_path):
    root = app(tmp_path)
    dump = write(
        tmp_path,
        "dump.csv",
        "schemaname,tablename,rowsecurity\npublic,invoices,t\n\n"
        "schemaname,tablename,policyname,permissive,roles,cmd,qual,with_check\n"
        "public,invoices,inv_own,PERMISSIVE,{authenticated},SELECT,(auth.uid() = user_id),\n",
    )
    assert findings_for(root, "rls", "RLS-TABLE-OFF", db_dump=str(dump)) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/reviews/test_rls_tables.py -v`
Expected: FAIL with `KeyError: 'rls'` (the review module does not exist yet)

- [ ] **Step 3: Write the rule text and implementation**

`src/dpr/data/rule_text/rls_tables.yaml`:

```yaml
RLS-TABLE-OFF:
  title: Row level security is off on ${table}
  effort_minutes: 15
  detail: ${table} never has row level security enabled. ${reach}
  attack: Open the app, copy the public database key from devtools, and request every row of ${table} from the REST endpoint.
  blast: Every row in ${table}, readable and possibly writable by anyone holding the public key.
  fix: Enable row level security and add policies.
RLS-NO-POLICIES:
  title: ${table} has row level security but no policies
  effort_minutes: 10
  detail: Row level security is on and no policy exists, so clients are denied everything. If the app still reads this table, it is using a service key, which must never reach the browser.
  fix: Add policies for the access the app needs.
RLS-SELECT-ONLY:
  title: ${table} only has select policies
  effort_minutes: 5
  detail: Clients can read ${table} but every insert, update and delete from a client is denied. If the app writes to this table, it uses a service key. Check the leaks review for that key.
  fix: No change needed if only the server writes to ${table}. If clients should write, add insert, update and delete policies scoped to the owner.
RLS-VIEW-BYPASS:
  title: View ${view} bypasses row level security on ${tables}
  effort_minutes: 5
  detail: The view ${view} reads ${tables} with the permissions of the view owner, so the row level security on those tables does not apply to people who query the view.
  attack: Query the view through the REST endpoint with the public key and read rows the table policies would hide.
  blast: Every row the view selects from ${tables}.
  fix: Recreate the view with security_invoker set to true.
RLS-DEFINER-FUNCTION:
  title: Security definer function ${function}
  effort_minutes: 15
  detail: ${what}
  attack: Call the function through the RPC endpoint with the public key.
  blast: Whatever the function reads or changes, without the caller's row level security.
  fix: Prefer security invoker. If definer is required, check ownership inside the function, set search_path to an empty value, and revoke execute from anon.
RLS-PUBLIC-BUCKET:
  title: Storage bucket ${bucket} is public
  effort_minutes: 10
  detail: Files in the ${bucket} bucket can be downloaded by anyone who has or guesses the file URL.
  blast: Every file in the ${bucket} bucket.
  fix: Make the bucket private and serve files through signed URLs with a short expiry, unless the files are meant to be public.
```

`src/dpr/reviews/rls_common.py`:

```python
"""Shared RLS helpers: schema state, owner detection and policy SQL."""

from __future__ import annotations

import copy
import re
from pathlib import Path

from dpr.model import Location
from dpr.parsing.sqlschema import Policy, SchemaState, TableDef, apply_dump
from dpr.rules import Context

OWNER_COLUMNS = ("user_id", "owner_id", "created_by", "author_id", "profile_id")
TENANT_COLUMNS = ("org_id", "organization_id", "tenant_id", "workspace_id", "team_id")
MEMBERSHIP_WORDS = ("member", "membership", "org_users", "team_users")
AUTH_REF = re.compile(r"auth\.uid\s*\(|auth\.jwt\s*\(")
DASHBOARD_QUERIES = """```sql
select schemaname, tablename, rowsecurity
from pg_tables
where schemaname not in ('pg_catalog','information_schema')
order by rowsecurity, tablename;

select schemaname, tablename, policyname, permissive, roles, cmd, qual, with_check
from pg_policies
order by tablename, policyname;
```"""


def owner_column(table: TableDef) -> str | None:
    names = table.column_names()
    return next((c for c in OWNER_COLUMNS if c in names), None)


def tenant_column(table: TableDef) -> str | None:
    names = table.column_names()
    return next((c for c in TENANT_COLUMNS if c in names), None)


def has_owner_or_unknown(table: TableDef) -> bool:
    return not table.columns or bool(owner_column(table) or tenant_column(table))


def membership_table(state: SchemaState, tenant: str) -> str | None:
    for key, table in sorted(state.tables.items()):
        names = table.column_names()
        is_membership = any(w in table.name for w in MEMBERSHIP_WORDS)
        if is_membership and "user_id" in names and tenant in names:
            return key
    return None


def predicate(state: SchemaState, table: TableDef) -> str | None:
    owner = owner_column(table)
    if owner:
        return f"auth.uid() = {owner}"
    tenant = tenant_column(table)
    members = membership_table(state, tenant) if tenant else None
    if tenant and members:
        return f"{tenant} in (select {tenant} from {members} where user_id = auth.uid())"
    return None


def predicate_text(policy: Policy) -> str:
    return " ".join(p for p in (policy.using, policy.with_check) if p)


def qualified(key: str) -> str:
    return ".".join(
        p if re.fullmatch(r"[a-z_][a-z0-9_]*", p) else f'"{p}"' for p in key.split(".", 1)
    )


def sql_block(sql: str) -> str:
    return f"```sql\n{sql}\n```"


NO_PREDICATE = "-- No owner or tenant column was found. Choose the predicate for this table first."


def policies_sql(state: SchemaState, table: TableDef) -> str:
    name, target = table.name, qualified(table.key)
    lines = [f"alter table {target} enable row level security;"]
    pred = predicate(state, table)
    if pred is None:
        return "\n".join([*lines, NO_PREDICATE])
    return "\n".join(
        [
            *lines,
            "",
            f'create policy "{name}_select_own" on {target}\n  for select using ({pred});',
            "",
            f'create policy "{name}_insert_own" on {target}\n  for insert with check ({pred});',
            "",
            f'create policy "{name}_update_own" on {target}\n'
            f"  for update using ({pred}) with check ({pred});",
            "",
            f'create policy "{name}_delete_own" on {target}\n  for delete using ({pred});',
        ]
    )


def replacement_sql(state: SchemaState, policy: Policy) -> str:
    target = qualified(policy.table)
    drop = f'drop policy "{policy.name}" on {target};'
    table = state.tables.get(policy.table)
    pred = predicate(state, table) if table else None
    if pred is None:
        return f"{drop}\n{NO_PREDICATE}"
    if policy.command == "insert":
        clause = f"with check ({pred})"
    elif policy.command in ("update", "all"):
        clause = f"using ({pred}) with check ({pred})"
    else:
        clause = f"using ({pred})"
    create = f'create policy "{policy.name}" on {target}'
    return f"{drop}\n{create}\n  for {policy.command} to authenticated {clause};"


def confirm_commands(table_name: str) -> str:
    return (
        "Run this against your own project with your own anon key while signed out. "
        "A pass returns `[]` or a permission error. A fail returns any row you did not create. "
        "dpr never runs this command.\n\n"
        "```bash\n"
        f'curl -s "https://<project>.supabase.co/rest/v1/{table_name}?select=*" \\\n'
        '  -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY"\n'
        "```\n\n"
        "Then sign in as user A and request a row owned by user B with A's access token. "
        "It must return nothing."
    )


def state_for(ctx: Context) -> SchemaState:
    if "rls.state" not in ctx.facts:
        base = ctx.detection.schema if isinstance(ctx.detection.schema, SchemaState) else None
        state = copy.deepcopy(base) if base is not None else SchemaState()
        if ctx.options.db_dump:
            text = Path(ctx.options.db_dump).read_text(encoding="utf-8", errors="replace")
            ctx.not_covered.extend(apply_dump(state, text, ctx.options.db_dump))
        ctx.facts["rls.state"] = state
    return ctx.facts["rls.state"]


def client_facing(ctx: Context) -> bool:
    d = ctx.detection
    return d.public_supabase_key or "supabase" in d.databases or bool(ctx.options.db_dump)


def public_tables(ctx: Context) -> list[TableDef]:
    if not client_facing(ctx):
        return []
    return [t for _, t in sorted(state_for(ctx).tables.items()) if t.schema == "public"]


def table_location(table: TableDef) -> Location:
    return table.rls_location or table.location
```

`src/dpr/reviews/rls.py`:

```python
"""Review 2, database lock check: tables, views, functions, buckets and the section."""

from __future__ import annotations

import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Part, ReviewSection, Tag
from dpr.parsing import jsts
from dpr.parsing.sqlschema import TableDef
from dpr.reviews.rls_common import (
    DASHBOARD_QUERIES,
    client_facing,
    confirm_commands,
    policies_sql,
    public_tables,
    qualified,
    sql_block,
    state_for,
    table_location,
)
from dpr.rules import Context, make_finding, rule
from dpr.walk import line_of

SUPABASE_FROM = re.compile(r"\.from\(\s*['\"`](\w+)['\"`]\s*\)")
CONFIRM_IN_DATABASE = (
    "Run these queries in the database SQL editor and compare the result with the table "
    "above. Save the output to a file and pass it with `--db-dump` to make it the source "
    "of truth.\n\n"
)
SERVER_ONLY = (
    "No public database key or Supabase client was found. The database appears to be "
    "reachable only from the server, so row level security matters less here. "
    "No RLS findings are reported."
)


def _rls_tables(ctx: Context) -> set[str]:
    return {key for key, table in state_for(ctx).tables.items() if table.rls}


@rule("RLS-TABLE-OFF", review="rls", severity="critical", exploitability="high")
def table_off(ctx: Context) -> Iterator[Finding]:
    state = state_for(ctx)
    exposed = ctx.detection.public_supabase_key
    reach = (
        "A public Supabase key is configured, so anyone holding it can read the table."
        if exposed
        else "No public key was found, which reduces how reachable it is."
    )
    for table in public_tables(ctx):
        if not table.rls:
            yield make_finding(
                "RLS-TABLE-OFF",
                tag=Tag.CONFIRMED,
                locations=[table_location(table)],
                severity="critical" if exposed else "high",
                fix=sql_block(policies_sql(state, table)),
                verify=confirm_commands(table.name),
                table=table.key,
                reach=reach,
            )


@rule("RLS-NO-POLICIES", review="rls", severity="low", exploitability="low")
def no_policies(ctx: Context) -> Iterator[Finding]:
    state = state_for(ctx)
    for table in public_tables(ctx):
        if table.rls and not state.policies_for(table.key):
            yield make_finding(
                "RLS-NO-POLICIES",
                tag=Tag.CONFIRMED,
                locations=[table_location(table)],
                fix=sql_block(policies_sql(state, table)),
                table=table.key,
            )


@rule("RLS-SELECT-ONLY", review="rls", severity="low", exploitability="low")
def select_only(ctx: Context) -> Iterator[Finding]:
    state = state_for(ctx)
    for table in public_tables(ctx):
        policies = state.policies_for(table.key)
        if table.rls and policies and all(p.command == "select" for p in policies):
            yield make_finding(
                "RLS-SELECT-ONLY",
                tag=Tag.CONFIRMED,
                locations=[policies[0].location],
                table=table.key,
            )


@rule("RLS-VIEW-BYPASS", review="rls", severity="high", exploitability="high")
def view_bypass(ctx: Context) -> Iterator[Finding]:
    if not client_facing(ctx):
        return
    protected_tables = _rls_tables(ctx)
    for key, view in sorted(state_for(ctx).views.items()):
        protected = [s for s in view.sources if s in protected_tables]
        if key.startswith("public.") and not view.security_invoker and protected:
            fix = sql_block(f"alter view {qualified(key)} set (security_invoker = true);")
            yield make_finding(
                "RLS-VIEW-BYPASS",
                tag=Tag.CONFIRMED,
                locations=[view.location],
                fix=fix,
                view=key,
                tables=", ".join(protected),
            )


@rule("RLS-DEFINER-FUNCTION", review="rls", severity="medium", exploitability="medium")
def definer_function(ctx: Context) -> Iterator[Finding]:
    if not client_facing(ctx):
        return
    protected_tables = _rls_tables(ctx)
    for key, fn in sorted(state_for(ctx).functions.items()):
        if not key.startswith("public.") or not fn.security_definer:
            continue
        protected = [t for t in fn.tables if t in protected_tables]
        what = "It runs with the owner's rights and can be called from the client."
        if protected:
            what += f" It reads {', '.join(protected)}, which have row level security."
        if not fn.sets_search_path:
            what += " It does not set search_path."
        yield make_finding(
            "RLS-DEFINER-FUNCTION",
            tag=Tag.CONFIRMED,
            locations=[fn.location],
            severity="high" if protected else "medium",
            function=key,
            what=what,
        )


@rule("RLS-PUBLIC-BUCKET", review="rls", severity="medium", exploitability="medium")
def public_bucket(ctx: Context) -> Iterator[Finding]:
    for bucket in sorted(state_for(ctx).buckets.values(), key=lambda b: b.id):
        if bucket.public:
            yield make_finding(
                "RLS-PUBLIC-BUCKET",
                tag=Tag.CONFIRMED,
                locations=[bucket.location],
                bucket=bucket.id,
            )
    for entry in ctx.index.js_files:
        if "createBucket" not in ctx.index.text(entry.rel):
            continue
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for call in jsts.calls(tree, r"(?:\w+\.)*createBucket"):
                args = jsts.arguments(call)
                public = jsts.object_pairs(args[1]).get("public") if len(args) > 1 else None
                if public is not None and jsts.node_text(public) == "true":
                    yield make_finding(
                        "RLS-PUBLIC-BUCKET",
                        tag=Tag.CONFIRMED,
                        locations=[Location(entry.rel, jsts.line(tree, call))],
                        bucket=jsts.string_value(args[0]) or "(dynamic name)",
                    )


def _breakage(ctx: Context, tables: list[TableDef]) -> list[Location]:
    names = {t.name for t in tables}
    found = []
    for entry in ctx.index.js_files:
        text = ctx.index.text(entry.rel)
        for match in SUPABASE_FROM.finditer(text):
            if match.group(1) in names:
                found.append(Location(entry.rel, line_of(text, match.start())))
    return found


def _status_row(ctx: Context, table: TableDef) -> tuple[str, ...]:
    count = len(state_for(ctx).policies_for(table.key))
    if not table.rls:
        reach = (
            "yes, every row"
            if ctx.detection.public_supabase_key
            else "yes, if a public key reaches the browser"
        )
        verdict = "exposed"
    elif count == 0:
        reach, verdict = "no, all client access denied", "locked, probably read with a service key"
    else:
        reach, verdict = "only rows the policies allow", "check policy defects"
    return (
        table.key,
        "yes" if table.rls else "no",
        str(count),
        reach,
        verdict,
        str(table_location(table)),
    )


def run(ctx: Context) -> ReviewSection | None:
    state = state_for(ctx)
    if not state.tables and not client_facing(ctx):
        ctx.not_covered.append(
            "Review 2 (rls): not applicable, no SQL tables, Supabase client or database dump found"
        )
        return None
    if not client_facing(ctx):
        return ReviewSection("rls", [Part("text", "Relevance", body=SERVER_ONLY)])
    tables = public_tables(ctx)
    parts = [
        Part(
            "table",
            "Table protection status",
            columns=(
                "Table",
                "RLS enabled",
                "Policies",
                "Reachable by anon key",
                "Verdict",
                "Evidence",
            ),
            rows=tuple(_status_row(ctx, t) for t in tables),
        ),
        Part("findings", "Policy defects"),
    ]
    gaps = [t for t in tables if not t.rls or not state.policies_for(t.key)]
    if gaps:
        body = "\n\n".join(sql_block(policies_sql(state, t)) for t in gaps)
        breakage = _breakage(ctx, gaps)
        if breakage:
            body += (
                "\n\nAdding these policies can make these queries return nothing for rows "
                "the caller does not own:\n" + "\n".join(f"- `{loc}`" for loc in breakage)
            )
        parts.append(Part("text", "Missing policies (runnable SQL)", body=body))
    example = gaps[0].name if gaps else (tables[0].name if tables else "<table>")
    confirm = confirm_commands(example)
    parts.append(Part("text", "How to confirm from outside the app", body=confirm))
    database = CONFIRM_IN_DATABASE + DASHBOARD_QUERIES
    parts.append(Part("text", "Confirm in the database", body=database))
    return ReviewSection("rls", parts)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/reviews -v`
Expected: PASS (all tests in `tests/reviews`)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/reviews/rls_common.py src/dpr/reviews/rls.py src/dpr/data/rule_text/rls_tables.yaml tests/reviews/test_rls_tables.py
git commit -m "Add RLS review for tables, views, functions and buckets with policy SQL"
```

---

### Task 22: RLS policy defect checks

**Files:**
- Create: `src/dpr/reviews/rls_policies.py`, `src/dpr/data/rule_text/rls_policies.yaml`
- Modify: `src/dpr/reviews/rls.py` (import `rls_policies` so its rules register)
- Test: `tests/reviews/test_rls_policies.py`

**Interfaces:**
- Consumes: `rls_common` helpers (Task 21), `rules` (Task 4), `Tag` (Task 2)
- Produces: registered rules `RLS-POLICY-TRUE`, `RLS-AUTHENTICATED-NOT-OWNER`, `RLS-WEAK-WITH-CHECK`, `RLS-WRONG-ROLE`, `RLS-CLIENT-OWNER`, `RLS-TENANT-UNBOUND` (review `rls`). `RLS-POLICY-TRUE` and `RLS-AUTHENTICATED-NOT-OWNER` only check tables that have an owner or tenant column, or whose columns are unknown (tables known only from a dump). This keeps intentionally shared lookup tables out of the findings.

- [ ] **Step 1: Write the failing test**

`tests/reviews/test_rls_policies.py`:

```python
from tests.reviews.helpers import findings_for, write

MIG = """create table public.profiles (id uuid primary key, user_id uuid not null, full_name text);
alter table public.profiles enable row level security;
create policy "profiles_update" on public.profiles for update using (auth.uid() = user_id) with check (true);
create policy "profiles_admin" on public.profiles for select using (auth.jwt() -> 'user_metadata' ->> 'role' = 'admin');
create policy "profiles_select_own" on public.profiles for select using (auth.uid() = user_id);
create table public.documents (id bigserial primary key, user_id uuid not null, body text);
alter table public.documents enable row level security;
create policy "documents_read" on public.documents for select using (true);
create policy "docs_auth" on public.documents for select to authenticated using (auth.role() = 'authenticated');
create policy "documents_delete" on public.documents for delete to anon using (body is not null);
create policy "documents_insert" on public.documents for insert with check (true);
create policy "documents_update_own" on public.documents for update using (auth.uid() = user_id) with check (true);
create table public.projects (id uuid primary key, org_id uuid not null, name text);
alter table public.projects enable row level security;
create policy "projects_read" on public.projects for select to authenticated using (exists (select 1 from public.members where members.user_id = auth.uid()));
create policy "projects_scoped" on public.projects for select to authenticated using (org_id in (select org_id from public.members where user_id = auth.uid()));
create table public.members (org_id uuid, user_id uuid);
create table public.posts (id int, published boolean);
alter table public.posts enable row level security;
create policy posts_read on public.posts for select to authenticated using (published);
"""


def app(tmp_path):
    write(tmp_path, "supabase/migrations/001.sql", MIG)
    write(tmp_path, ".env.example", "NEXT_PUBLIC_SUPABASE_ANON_KEY=\n")
    return tmp_path


def by_line(root, rule_id, **options):
    return {f.locations[0].line: f for f in findings_for(root, "rls", rule_id, **options)}


def test_policy_true_and_authenticated_not_owner(tmp_path):
    root = app(tmp_path)
    assert sorted(by_line(root, "RLS-POLICY-TRUE")) == [8]
    assert sorted(by_line(root, "RLS-AUTHENTICATED-NOT-OWNER")) == [9]
    assert (
        'drop policy "documents_read" on public.documents;'
        in by_line(root, "RLS-POLICY-TRUE")[8].fix
    )


def test_weak_with_check_severity(tmp_path):
    found = by_line(app(tmp_path), "RLS-WEAK-WITH-CHECK")
    assert {line: f.severity.value for line, f in found.items()} == {
        3: "low",
        11: "high",
        12: "high",
    }


def test_wrong_role_client_owner_tenant_unbound(tmp_path):
    root = app(tmp_path)
    assert sorted(by_line(root, "RLS-WRONG-ROLE")) == [10]
    assert sorted(by_line(root, "RLS-CLIENT-OWNER")) == [4]
    unbound = by_line(root, "RLS-TENANT-UNBOUND")
    assert sorted(unbound) == [15]
    assert unbound[15].tag.value == "INFERRED" and unbound[15].proof_needed


def test_dump_only_table_is_checked(tmp_path):
    root = app(tmp_path)
    dump = write(
        tmp_path,
        "pol.csv",
        "schemaname,tablename,policyname,permissive,roles,cmd,qual,with_check\n"
        "public,secrets,secrets_read,PERMISSIVE,{authenticated},SELECT,(auth.role() = 'authenticated'::text),\n",
    )
    found = findings_for(root, "rls", "RLS-AUTHENTICATED-NOT-OWNER", db_dump=str(dump))
    assert sorted(
        (f.locations[0].file.endswith("pol.csv"), f.locations[0].line) for f in found
    ) == [
        (False, 9),
        (True, 2),
    ]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/reviews/test_rls_policies.py -v`
Expected: FAIL with `KeyError: 'RLS-POLICY-TRUE'` or empty results

- [ ] **Step 3: Write the rule text and implementation**

`src/dpr/data/rule_text/rls_policies.yaml`:

```yaml
RLS-POLICY-TRUE:
  title: Policy ${policy} on ${table} allows every row
  effort_minutes: 10
  detail: The policy ${policy} uses true as its condition, so it does not check who owns a row.
  attack: Sign in as any user, or use the public key if the policy is not limited to signed-in users, and read every row of ${table}.
  blast: Every row in ${table} for the command this policy covers.
  fix: Replace the condition with an ownership check.
RLS-AUTHENTICATED-NOT-OWNER:
  title: Policy ${policy} checks sign-in, not ownership
  effort_minutes: 10
  detail: The policy ${policy} on ${table} lets any signed-in user through without checking that the row belongs to them.
  attack: Create a free account, sign in, and read every row of ${table}.
  blast: Every row in ${table}, for anyone who can create an account.
  fix: Replace the condition with an ownership check.
RLS-WEAK-WITH-CHECK:
  title: Policy ${policy} does not check ownership of new rows
  effort_minutes: 10
  detail: ${what}
  attack: Sign in and write a row to ${table} with another user's id in ${owner}.
  blast: Rows created or moved into another user's ownership in ${table}.
  fix: Make the with check condition match the ownership check.
RLS-WRONG-ROLE:
  title: Write policy ${policy} is granted to ${roles}
  effort_minutes: 5
  detail: The ${command} policy ${policy} on ${table} applies to ${roles} and never checks auth.uid() or auth.jwt(), so callers who are not signed in can use it.
  attack: Use the public key without signing in and run a ${command} against ${table}.
  blast: Rows in ${table} that the condition matches.
  fix: Grant the policy to authenticated and add an ownership check.
RLS-CLIENT-OWNER:
  title: Policy ${policy} trusts a value the client controls
  effort_minutes: 15
  detail: The policy ${policy} on ${table} reads user_metadata or request headers. Users can edit their own user_metadata, and clients set their own headers.
  attack: Update your own user_metadata (for example set role to admin) with the client library, then query ${table}.
  blast: Whatever the policy grants to the claimed value.
  fix: Base the check on auth.uid(), or on app_metadata or a server-side roles table that users cannot edit.
RLS-TENANT-UNBOUND:
  title: Policy ${policy} checks membership but not which tenant
  effort_minutes: 15
  detail: The policy ${policy} on ${table} checks that the caller belongs to some tenant but never compares the row's ${tenant}, so a member of any tenant can pass.
  proof_needed: Sign in as a member of tenant A and request a row of ${table} that belongs to tenant B.
  attack: Join or create any tenant, then read rows of ${table} from every other tenant.
  blast: Every tenant's rows in ${table}.
  fix: Compare the row's ${tenant} with the caller's memberships.
```

`src/dpr/reviews/rls_policies.py`:

```python
"""Review 2, database lock check: policy defects."""

from __future__ import annotations

import re
from collections.abc import Iterator

from dpr.model import Finding, Tag
from dpr.parsing.sqlschema import TableDef
from dpr.reviews.rls_common import (
    AUTH_REF,
    MEMBERSHIP_WORDS,
    client_facing,
    has_owner_or_unknown,
    owner_column,
    predicate_text,
    public_tables,
    replacement_sql,
    sql_block,
    state_for,
    tenant_column,
)
from dpr.rules import Context, make_finding, rule

AUTH_ROLE = re.compile(r"auth\.role\s*\(\s*\)\s*=\s*'authenticated'")
CLIENT_CLAIM = re.compile(r"user_metadata|current_setting\s*\(\s*'request\.headers'")
UID_REF = re.compile(r"auth\.uid\s*\(")
WRITE_COMMANDS = ("insert", "update", "delete", "all")


def _policies(ctx: Context):
    """Every policy on a public table. Tables known only from a dump get an empty column list."""
    if not client_facing(ctx):
        return
    state = state_for(ctx)
    tables = {t.key: t for t in public_tables(ctx)}
    ordered = sorted(
        state.policies.values(), key=lambda p: (p.location.file, p.location.line, p.name)
    )
    for policy in ordered:
        if policy.table.startswith("public."):
            table = tables.get(policy.table) or TableDef(policy.table, [], policy.location)
            yield state, table, policy


def _fix(state, policy) -> str:
    return sql_block(replacement_sql(state, policy))


@rule("RLS-POLICY-TRUE", review="rls", severity="high", exploitability="high")
def policy_true(ctx: Context) -> Iterator[Finding]:
    for state, table, policy in _policies(ctx):
        if policy.using == "true" and has_owner_or_unknown(table):
            yield make_finding(
                "RLS-POLICY-TRUE",
                tag=Tag.CONFIRMED,
                locations=[policy.location],
                fix=_fix(state, policy),
                policy=policy.name,
                table=table.key,
            )


@rule("RLS-AUTHENTICATED-NOT-OWNER", review="rls", severity="high", exploitability="high")
def authenticated_not_owner(ctx: Context) -> Iterator[Finding]:
    for state, table, policy in _policies(ctx):
        text = predicate_text(policy)
        if not text or AUTH_REF.search(text) or not has_owner_or_unknown(table):
            continue
        signed_in_only = (
            policy.roles_explicit
            and set(policy.roles) == {"authenticated"}
            and "true" not in (policy.using, policy.with_check)
        )
        if AUTH_ROLE.search(text) or signed_in_only:
            yield make_finding(
                "RLS-AUTHENTICATED-NOT-OWNER",
                tag=Tag.CONFIRMED,
                locations=[policy.location],
                fix=_fix(state, policy),
                policy=policy.name,
                table=table.key,
            )


def _mentions(text: str | None, owner: str) -> bool:
    return bool(text) and bool(AUTH_REF.search(text) or re.search(rf"\b{re.escape(owner)}\b", text))


@rule("RLS-WEAK-WITH-CHECK", review="rls", severity="high", exploitability="high")
def weak_with_check(ctx: Context) -> Iterator[Finding]:
    state = state_for(ctx)
    for table in public_tables(ctx):
        owner = owner_column(table)
        if owner is None:
            continue
        policies = state.policies_for(table.key)
        select_scoped = any(
            p.command in ("select", "all")
            and p.using
            and (UID_REF.search(p.using) or re.search(rf"\b{re.escape(owner)}\b", p.using))
            for p in policies
        )
        for policy in policies:
            if policy.command not in ("insert", "update", "all") or policy.with_check is None:
                continue
            if _mentions(policy.with_check, owner):
                continue
            if policy.command == "insert":
                severity = "high"
                what = f"The insert policy {policy.name} lets a caller create rows for any {owner}."
            else:
                severity = "low" if select_scoped else "high"
                what = (
                    f"The {policy.command} policy {policy.name} lets a caller change {owner} "
                    "to another user. "
                )
                what += (
                    "A select policy scoped to the owner blocks this in practice."
                    if select_scoped
                    else "No select policy scoped to the owner blocks it."
                )
            yield make_finding(
                "RLS-WEAK-WITH-CHECK",
                tag=Tag.CONFIRMED,
                locations=[policy.location],
                severity=severity,
                fix=_fix(state, policy),
                policy=policy.name,
                table=table.key,
                owner=owner,
                what=what,
            )


@rule("RLS-WRONG-ROLE", review="rls", severity="high", exploitability="high")
def wrong_role(ctx: Context) -> Iterator[Finding]:
    for state, table, policy in _policies(ctx):
        if owner_column(table) is None or policy.command not in WRITE_COMMANDS:
            continue
        open_roles = {"anon", "public"} & set(policy.roles)
        if policy.roles_explicit and open_roles and not AUTH_REF.search(predicate_text(policy)):
            yield make_finding(
                "RLS-WRONG-ROLE",
                tag=Tag.CONFIRMED,
                locations=[policy.location],
                fix=_fix(state, policy),
                policy=policy.name,
                table=table.key,
                roles=", ".join(sorted(open_roles)),
                command=policy.command,
            )


@rule("RLS-CLIENT-OWNER", review="rls", severity="high", exploitability="high")
def client_owner(ctx: Context) -> Iterator[Finding]:
    for state, table, policy in _policies(ctx):
        if CLIENT_CLAIM.search(predicate_text(policy)):
            yield make_finding(
                "RLS-CLIENT-OWNER",
                tag=Tag.CONFIRMED,
                locations=[policy.location],
                fix=_fix(state, policy),
                policy=policy.name,
                table=table.key,
            )


@rule("RLS-TENANT-UNBOUND", review="rls", severity="high", exploitability="high")
def tenant_unbound(ctx: Context) -> Iterator[Finding]:
    for state, table, policy in _policies(ctx):
        tenant = tenant_column(table)
        text = predicate_text(policy)
        if tenant is None or not re.search(r"\b(select|exists)\b", text):
            continue
        if not any(word in text for word in MEMBERSHIP_WORDS) or not AUTH_REF.search(text):
            continue
        if re.search(rf"\b{re.escape(tenant)}\b", text):
            continue
        yield make_finding(
            "RLS-TENANT-UNBOUND",
            tag=Tag.INFERRED,
            locations=[policy.location],
            fix=_fix(state, policy),
            policy=policy.name,
            table=table.key,
            tenant=tenant,
        )
```

Modify `src/dpr/reviews/rls.py`: insert this line between `from dpr.parsing.sqlschema import TableDef` and `from dpr.reviews.rls_common import (`, so loading the review registers the policy rules:

```python
from dpr.reviews import rls_policies  # noqa: F401  (registers the rls_policies rules)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/reviews -v`
Expected: PASS (all tests in `tests/reviews`)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/reviews/rls.py src/dpr/reviews/rls_policies.py src/dpr/data/rule_text/rls_policies.yaml tests/reviews/test_rls_policies.py
git commit -m "Add RLS policy defect checks"
```

---

### Task 23: The `review()` pipeline

**Files:**
- Create: `src/dpr/api.py`
- Test: `tests/test_api.py`

**Interfaces:**
- Consumes: `detect` (Task 16); `RepoIndex` (Task 5); `questions_for`, `resolve`, `ask_on_terminal` (Task 17); `REVIEWS`, `RUN_ORDER`, `available`, `number`, `resolve_reviews` (Task 18); `Context`, `Options`, `run_checks` (Task 4); `dedupe`, `rank` (Task 3); model types (Task 2); the leaks and RLS reviews (Tasks 19 to 22)
- Produces:
  - `dpr.api.discover(path) -> tuple[RepoIndex, Detection]` (runs the sanity check)
  - `dpr.api.review(path=".", reviews=("all",), answers=None, interactive=False, url=None, owns_host=False, login_path=None, with_audit=False, semgrep="auto", db_dump=None, today=None) -> Report`. `today` is an optional `datetime.date` for stable test output. It writes no files.
  - Validation raises `ScanError` for: `url` without `owns_host`; `semgrep` that is not `auto`, `off` or an existing folder; `db_dump` that is not an existing file.
  - `report.meta.applicability` holds one `(slug, reason)` per review in number order. `reason` is `runs`, `not selected`, `not available in this version`, or the not-applicable reason.
  - `report.not_covered` holds skipped files, answer warnings, unavailable or not applicable reviews, skipped options and failed rules, without duplicates.

- [ ] **Step 1: Write the failing test**

`tests/test_api.py`:

```python
import datetime

import pytest

from dpr import rules
from dpr.api import review
from dpr.model import ScanError
from dpr.rank import score
from tests.reviews.helpers import write


def app(tmp_path):
    write(
        tmp_path, "package.json", '{"dependencies": {"next": "14", "@supabase/supabase-js": "2"}}'
    )
    write(
        tmp_path,
        ".env.example",
        "NEXT_PUBLIC_SUPABASE_ANON_KEY=\nNEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=\n",
    )
    write(
        tmp_path, "supabase/migrations/1.sql", "create table public.notes (id int, user_id uuid);"
    )
    write(tmp_path, "app/page.tsx", "export default function Page() { return null }\n")
    return tmp_path


def files(root):
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*"))


def test_full_run(tmp_path):
    root = app(tmp_path)
    before = files(root)
    report = review(root, today=datetime.date(2026, 9, 16))
    assert files(root) == before
    assert set(report.sections) == {"leaks", "rls"}
    assert report.meta.reviews_run == ("rls", "leaks")
    assert report.meta.date == "2026-09-16"
    assert report.meta.project == root.name
    assert dict(report.meta.applicability) == {
        "inventory": "not available in this version",
        "rls": "runs",
        "auth": "not available in this version",
        "baseline": "not available in this version",
        "owasp": "not available in this version",
        "leaks": "runs",
        "abuse": "not available in this version",
    }
    assert [s for s, _ in report.meta.applicability] == [
        "inventory",
        "rls",
        "auth",
        "baseline",
        "owasp",
        "leaks",
        "abuse",
    ]
    rule_ids = {f.rule_id for f in report.findings}
    assert {"LEAK-PUBLIC-SECRET", "RLS-TABLE-OFF"} <= rule_ids
    scores = [score(f) for f in report.findings]
    assert scores == sorted(scores, reverse=True)
    assert "Review 1 (inventory): not available in this version" in report.not_covered
    assert len(report.questions) == 22
    assert all(q.open for q in report.questions)


def test_selected_reviews_only(tmp_path):
    report = review(app(tmp_path), reviews=["leaks"])
    assert set(report.sections) == {"leaks"}
    assert dict(report.meta.applicability)["rls"] == "not selected"
    assert {q.question.id for q in report.questions} == {
        "hosting_env_not_in_repo",
        "log_tool_access_retention",
    }
    assert not any(f.review == "rls" for f in report.findings)


def test_not_applicable_reason(tmp_path):
    write(tmp_path, "a.py", "x = 1\n")
    report = review(tmp_path, reviews=[2])
    assert report.sections == {}
    assert (
        dict(report.meta.applicability)["rls"]
        == "not applicable, no SQL tables, Supabase client or database dump found"
    )


def test_answers_and_warnings(tmp_path):
    report = review(app(tmp_path), reviews=["rls"], answers={"buckets_public": "No", "typo": 1})
    answered = {q.question.id: q for q in report.questions}
    assert answered["buckets_public"].open is False
    assert "unknown answer key ignored: typo" in report.not_covered


def test_validation(tmp_path):
    root = app(tmp_path)
    with pytest.raises(ScanError, match="i-own-this-host"):
        review(root, url="https://example.com")
    with pytest.raises(ScanError, match="semgrep rules folder"):
        review(root, semgrep=str(tmp_path / "nope"))
    with pytest.raises(ScanError, match="database dump"):
        review(root, db_dump=str(tmp_path / "nope.csv"))
    with pytest.raises(ScanError, match="unknown review"):
        review(root, reviews=["9"])


def test_url_note_until_baseline_exists(tmp_path):
    report = review(app(tmp_path), url="https://example.com", owns_host=True)
    assert any("Live header read skipped" in n for n in report.not_covered)


def test_sanity_check_propagates(tmp_path):
    write(tmp_path, "package.json", "{}")
    with pytest.raises(ScanError, match="package.json"):
        review(tmp_path)


def test_failing_rule_is_recorded_when_not_strict(tmp_path, monkeypatch):
    monkeypatch.delenv("DPR_STRICT")
    root = app(tmp_path)
    review(root, reviews=["leaks"])

    def boom(ctx):
        raise RuntimeError("x")

    monkeypatch.setitem(rules.CHECKS, "leaks", [*rules.CHECKS["leaks"], ("TEST-BOOM", boom)])
    report = review(root, reviews=["leaks"])
    assert "rule TEST-BOOM failed: RuntimeError" in report.not_covered
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_api.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'dpr.api'`

- [ ] **Step 3: Write the implementation**

`src/dpr/api.py`:

```python
"""The review() pipeline."""

from __future__ import annotations

import datetime
import os
import sys
from collections.abc import Iterable
from pathlib import Path

from dpr.discovery.detect import detect
from dpr.model import Detection, Finding, Report, ReportMeta, ReviewSection, ScanError
from dpr.questions.catalogue import questions_for, resolve
from dpr.questions.prompt import ask_on_terminal
from dpr.rank import dedupe, rank
from dpr.reviews import REVIEWS, RUN_ORDER, available, number, resolve_reviews
from dpr.rules import Context, Options, run_checks
from dpr.walk import RepoIndex

SKIPPED_OPTIONS = (
    (
        "url",
        "baseline",
        "Live header read skipped: it belongs to review 4 (baseline), "
        "which is not available in this version",
    ),
    (
        "with_audit",
        "owasp",
        "Dependency audit skipped: it belongs to review 5 (owasp), "
        "which is not available in this version",
    ),
)


def discover(path: str | os.PathLike[str]) -> tuple[RepoIndex, Detection]:
    index = RepoIndex(path)
    index.sanity_check()
    return index, detect(index)


def _validate(url: str | None, owns_host: bool, semgrep: str, db_dump: str | None) -> None:
    if url and not owns_host:
        raise ScanError(
            "--url needs --i-own-this-host: dpr only reads headers from a host you control"
        )
    if semgrep not in ("auto", "off") and not Path(semgrep).is_dir():
        raise ScanError(f"semgrep rules folder not found: {semgrep}")
    if db_dump and not Path(db_dump).is_file():
        raise ScanError(f"database dump not found: {db_dump}")


def _reason(slug: str, selected: list[str], modules: dict, sections: dict, notes: list[str]) -> str:
    if slug in sections:
        return "runs"
    if slug not in selected:
        return "not selected"
    if slug not in modules:
        return "not available in this version"
    prefix = f"Review {number(slug)} ({slug}): "
    return next((n[len(prefix) :] for n in notes if n.startswith(prefix)), "not applicable")


def review(
    path: str | os.PathLike[str] = ".",
    reviews: Iterable[str | int] = ("all",),
    answers: str | Path | dict | None = None,
    interactive: bool = False,
    url: str | None = None,
    owns_host: bool = False,
    login_path: str | None = None,
    with_audit: bool = False,
    semgrep: str = "auto",
    db_dump: str | None = None,
    today: datetime.date | None = None,
) -> Report:
    _validate(url, owns_host, semgrep, db_dump)
    selected = resolve_reviews(reviews)
    index, detection = discover(path)
    options = Options(
        url=url,
        owns_host=owns_host,
        login_path=login_path,
        with_audit=with_audit,
        semgrep=semgrep,
        db_dump=db_dump,
    )
    ask = ask_on_terminal if interactive and sys.stdin.isatty() else None
    results, warnings = resolve(questions_for(selected), detection, answers, interactive, ask)
    ctx = Context(
        index=index,
        detection=detection,
        options=options,
        answers={r.question.id: r for r in results},
    )
    ctx.not_covered.extend(warnings)

    modules = available()
    sections: dict[str, ReviewSection] = {}
    findings: list[Finding] = []
    for slug in RUN_ORDER:
        if slug not in selected:
            continue
        if slug not in modules:
            ctx.not_covered.append(f"Review {number(slug)} ({slug}): not available in this version")
            continue
        section = modules[slug].run(ctx)
        if section is None:
            continue
        sections[slug] = section
        findings.extend(run_checks(slug, ctx))

    for option, owner, note in SKIPPED_OPTIONS:
        if getattr(options, option) and owner not in modules:
            ctx.not_covered.append(note)

    applicability = tuple(
        (slug, _reason(slug, selected, modules, sections, ctx.not_covered)) for slug in REVIEWS
    )
    meta = ReportMeta(
        project=index.root.name,
        scope=str(path),
        revision=detection.git.revision,
        date=(today or datetime.date.today()).isoformat(),
        reviews_run=tuple(slug for slug in REVIEWS if slug in sections),
        method="Static analysis of the repository",
        applicability=applicability,
    )
    not_covered = list(dict.fromkeys([*index.skipped, *ctx.not_covered]))
    return Report(
        meta=meta,
        detection=detection,
        findings=rank(dedupe(findings)),
        sections=sections,
        questions=results,
        not_covered=not_covered,
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_api.py -v`
Expected: PASS (8 tests)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/api.py tests/test_api.py
git commit -m "Add review pipeline with selection, questions, ranking and coverage notes"
```

---

### Task 24: Markdown report

**Files:**
- Create: `src/dpr/report/__init__.py` (empty), `src/dpr/report/markdown.py`, `src/dpr/report/templates/report.md.j2`
- Test: `tests/report/__init__.py` (empty), `tests/report/test_markdown.py`

**Interfaces:**
- Consumes: `Report` and parts (Task 2); `order_for_section` (Task 3); `REVIEWS`, `TITLES`, `LABELS`, `number` (Task 18)
- Produces:
  - `dpr.report.markdown.DISCLAIMER`, `BANNED_PHRASES`
  - `dpr.report.markdown.render_markdown(report: Report) -> str`. Layout follows the skill's report template: header, disclaimer, summary counts, top three fixes, evidence tags, detection table and review applicability, one section per review in number order, answered and open questions, and what the review did not cover. Findings render as `#### <LABEL> <n>: <title>` blocks. There are never three newlines in a row.

- [ ] **Step 1: Write the failing test**

`tests/report/__init__.py`: empty file.

`tests/report/test_markdown.py`:

```python
from dpr.model import (
    Detection,
    Finding,
    Location,
    Part,
    Question,
    QuestionResult,
    Report,
    ReportMeta,
    ReviewSection,
)
from dpr.report.markdown import BANNED_PHRASES, render_markdown


def finding(rule_id, review, sev, title, **extra):
    base = dict(
        rule_id=rule_id,
        review=review,
        title=title,
        tag="CONFIRMED",
        severity=sev,
        exploitability="high",
        effort_minutes=5,
        locations=(Location("a.ts", 3),),
        detail="Detail text.",
        fix="Fix text.",
    )
    base.update(extra)
    return Finding(**base)


def report():
    q_open = Question(
        id="q1",
        reviews=("rls",),
        text="Are buckets public?",
        type="choice",
        why="Dashboards.",
        who="Admin | owner",
    )
    q_done = Question(
        id="q2", reviews=("rls",), text="Which key ships?", type="choice", why="Env.", who="Ops"
    )
    return Report(
        meta=ReportMeta(
            project="shop",
            scope=".",
            revision="abc123",
            date="2026-09-16",
            reviews_run=("rls", "leaks"),
            method="Static analysis of the repository",
            applicability=(
                ("inventory", "not available in this version"),
                ("rls", "runs"),
                ("leaks", "runs"),
            ),
        ),
        detection=Detection(
            frameworks=["next"], databases=["supabase"], languages={"javascript/typescript": 4}
        ),
        findings=[
            finding(
                "RLS-TABLE-OFF",
                "rls",
                "critical",
                "RLS off on public.notes",
                fix="```sql\nalter table public.notes enable row level security;\n```",
            ),
            finding(
                "LEAK-LOGGED-PII",
                "leaks",
                "high",
                "Log call",
                tag="INFERRED",
                proof_needed="Check it.",
                snippet="console.error(body)",
            ),
            finding(
                "LEAK-PUBLIC-SECRET", "leaks", "low", "Public secret", verify="Search the bundle."
            ),
        ],
        sections={
            "leaks": ReviewSection("leaks", [Part("findings", "Leaks")]),
            "rls": ReviewSection(
                "rls",
                [
                    Part(
                        "table",
                        "Table protection status",
                        columns=("Table", "Verdict"),
                        rows=(("public.notes", "exposed | bad"),),
                    ),
                    Part("findings", "Policy defects"),
                    Part("text", "Confirm in the database", body="Run the queries."),
                ],
            ),
        },
        questions=[
            QuestionResult(q_open, None, "none", True),
            QuestionResult(q_done, "Anon only", "answers", False),
        ],
        not_covered=["big.js: larger than 1 MB"],
    )


def test_header_summary_and_top_fixes():
    text = render_markdown(report())
    assert text.startswith(
        "# Data Protection Review: shop\n\nDate: 2026-09-16\nScope: . @ abc123\n"
    )
    assert "Reviews run: rls, leaks" in text
    assert (
        "| Critical | 1 |" in text
        and "| High | 1 |" in text
        and "| Open questions (UNKNOWN) | 1 |" in text
    )
    assert "1. RLS off on public.notes (`a.ts:3`, about 5 min)" in text
    assert "not legal advice" in text


def test_sections_in_number_order_with_tables_and_blocks():
    text = render_markdown(report())
    assert text.index("## 2. Database lock check") < text.index("## 6. Leak hunt")
    assert "| public.notes | exposed \\| bad |" in text
    assert "#### RLS 1: RLS off on public.notes" in text
    leaks = text[text.index("## 6. Leak hunt") :]
    assert leaks.index("#### LEAK 1: Public secret") < leaks.index("#### LEAK 2: Log call")
    assert "Proof needed: Check it." in text
    assert "```text\nconsole.error(body)\n```" in text
    assert "```sql\nalter table public.notes enable row level security;\n```" in text
    assert "- Review 2, Database lock check: runs" in text


def test_questions_and_not_covered():
    text = render_markdown(report())
    assert "- Which key ships? Anon only (from the answers file)" in text
    assert "| Are buckets public? | Dashboards. | Admin \\| owner |" in text
    assert "- big.js: larger than 1 MB" in text
    assert "- Systems outside this repository" in text


def test_no_triple_newlines_legal_phrases_or_em_dashes():
    text = render_markdown(report())
    assert "\n\n\n" not in text
    assert "\u2014" not in text
    assert not any(p in text.lower() for p in BANNED_PHRASES)


def test_empty_report():
    r = report()
    r.findings, r.sections, r.questions, r.not_covered = [], {}, [], []
    text = render_markdown(r)
    assert "No findings." in text
    assert "### Still open: needs a human\n\nNone." in text
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/report/test_markdown.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'dpr.report'`

- [ ] **Step 3: Write the template and implementation**

`src/dpr/report/__init__.py`: empty file.

`src/dpr/report/templates/report.md.j2`:

```jinja
# Data Protection Review: {{ meta.project }}

Date: {{ meta.date }}
Scope: {{ meta.scope }} @ {{ meta.revision }}
Reviews run: {{ reviews_run }}
Method: {{ meta.method }}

{{ disclaimer }}

## Summary

{{ summary_table }}

{{ top_fixes }}

## Evidence tags

CONFIRMED: read in the repository and cited. INFERRED: strong signal, not proven.
UNVERIFIED: needs a runtime or console check. UNKNOWN: no answer available.

## Detection

{{ detection_table }}

{{ applicability }}
{% for section in sections %}

## {{ section.number }}. {{ section.title }}
{% for part in section.parts %}

### {{ part.title }}

{{ part.body }}
{% endfor %}
{% endfor %}

## Open questions

### Answered by this review

{{ answered }}

### Still open: needs a human

{{ still_open }}

## What this review did not cover

{{ not_covered }}
```

`src/dpr/report/markdown.py`:

```python
"""Render a Report as Markdown."""

from __future__ import annotations

import re

from jinja2 import Environment, PackageLoader

from dpr.model import Finding, Part, Report
from dpr.rank import order_for_section
from dpr.reviews import LABELS, REVIEWS, TITLES, number

DISCLAIMER = (
    "This is an inventory of what the code shows, not legal advice. Compliance conclusions and "
    "lawful basis are for a qualified data protection lawyer. Open questions for that "
    "conversation are listed near the end."
)
BANNED_PHRASES = (
    "compliant with",
    "complies with",
    "satisfies article",
    "satisfies section",
    "lawful basis is",
)
SEVERITIES = ("critical", "high", "medium", "low")
SOURCE_LABELS = {
    "answers": "from the answers file",
    "interactive": "answered in the terminal",
    "detection": "detected in the repository",
}
ALWAYS_NOT_COVERED = (
    "Systems outside this repository",
    "Production configuration that differs from the repository",
    "Runtime behaviour that static analysis cannot observe",
)


def _cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _table(columns: tuple[str, ...], rows: list[tuple[str, ...]] | tuple) -> str:
    if not rows:
        return "None found."
    lines = ["| " + " | ".join(_cell(c) for c in columns) + " |", "|" + "---|" * len(columns)]
    lines += ["| " + " | ".join(_cell(c) for c in row) + " |" for row in rows]
    return "\n".join(lines)


def _block(label: str, position: int, f: Finding) -> str:
    where = ", ".join(f"`{loc}`" for loc in f.locations) or "not tied to a file"
    lines = [
        f"#### {label} {position}: {f.title}",
        "",
        f"Severity: {f.severity.value}, exploitability: {f.exploitability.value}, "
        f"tag: {f.tag.value}, effort: about {f.effort_minutes} min",
        f"Where: {where}",
        "",
        f.detail,
    ]
    if f.snippet:
        lines += ["", "```text", f.snippet, "```"]
    for heading, value in (
        ("Proof needed", f.proof_needed),
        ("Attack", f.attack),
        ("Blast radius", f.blast),
    ):
        if value:
            lines += ["", f"{heading}: {value}"]
    lines += ["", "Fix:", "", f.fix]
    if f.verify:
        lines += ["", f"Verify: {f.verify}"]
    if f.source != "dpr":
        lines += ["", f"Source: {f.source}"]
    if f.refs:
        lines += ["", "Related: " + ", ".join(f.refs)]
    return "\n".join(lines)


def _part_body(slug: str, part: Part, report: Report) -> str:
    if part.kind == "table":
        return _table(part.columns, part.rows)
    if part.kind == "findings":
        items = order_for_section(slug, report.findings)
        if not items:
            return "None found."
        return "\n\n".join(_block(LABELS[slug], i, f) for i, f in enumerate(items, start=1))
    return part.body


def _detection_table(report: Report) -> str:
    d = report.detection
    schema = d.schema
    has_policies = bool(getattr(schema, "policies", None))
    sdks = f"{len(d.sdks)}" + (f" ({', '.join(s.name for s in d.sdks)})" if d.sdks else "")
    rows = [
        ("Language / framework", ", ".join([*d.languages, *d.frameworks]) or "none detected"),
        ("Database / ORM", ", ".join([*d.databases, *d.orms]) or "none detected"),
        ("Auth provider", ", ".join(d.auth_providers) or "none detected"),
        ("Hosting", ", ".join(d.hosting) or "none detected"),
        ("API routes", str(len(d.routes))),
        ("Third-party SDKs", sdks),
        ("RLS or policy files present", "yes" if has_policies else "no"),
        ("Rate limiting present", ", ".join(d.rate_limiters) or "no"),
        ("Security headers configured", ", ".join(d.header_config) or "no"),
    ]
    return "| | |\n|---|---|\n" + "\n".join(f"| {a} | {_cell(b)} |" for a, b in rows)


def _view(report: Report) -> dict:
    counts = {s: sum(f.severity.value == s for f in report.findings) for s in SEVERITIES}
    open_questions = [q for q in report.questions if q.open]
    summary = _table(
        ("Severity", "Count"),
        [
            *[(s.capitalize(), str(counts[s])) for s in SEVERITIES],
            ("Open questions (UNKNOWN)", str(len(open_questions))),
        ],
    )
    if report.findings:
        top = "Top three fixes by risk removed per minute spent:\n\n" + "\n".join(
            f"{i}. {f.title} (`{f.locations[0] if f.locations else 'no file'}`, "
            f"about {f.effort_minutes} min)"
            for i, f in enumerate(report.findings[:3], start=1)
        )
    else:
        top = "No findings."
    sections = []
    for slug in REVIEWS:
        section = report.sections.get(slug)
        if section is not None:
            parts = [{"title": p.title, "body": _part_body(slug, p, report)} for p in section.parts]
            sections.append({"number": number(slug), "title": TITLES[slug], "parts": parts})
    answered = [q for q in report.questions if not q.open]
    return {
        "meta": report.meta,
        "reviews_run": ", ".join(report.meta.reviews_run) or "none",
        "disclaimer": DISCLAIMER,
        "summary_table": summary,
        "top_fixes": top,
        "detection_table": _detection_table(report),
        "applicability": "Reviews:\n\n"
        + "\n".join(
            f"- Review {number(slug)}, {TITLES[slug]}: {reason}"
            for slug, reason in report.meta.applicability
        ),
        "sections": sections,
        "answered": "\n".join(
            f"- {q.question.text} {q.answer} ({SOURCE_LABELS.get(q.source, q.source)})"
            for q in answered
        )
        or "None.",
        "still_open": _table(
            ("Question", "Why the repository cannot answer it", "Who can answer"),
            [(q.question.text, q.question.why, q.question.who) for q in open_questions],
        )
        if open_questions
        else "None.",
        "not_covered": "\n".join(
            f"- {item}" for item in [*ALWAYS_NOT_COVERED, *report.not_covered]
        ),
    }


def render_markdown(report: Report) -> str:
    env = Environment(
        loader=PackageLoader("dpr", "report/templates"),
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    text = env.get_template("report.md.j2").render(**_view(report))
    return re.sub(r"\n{3,}", "\n\n", text).rstrip("\n") + "\n"
```

Note: `autoescape=False` is correct here because the output is Markdown, not HTML.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/report/test_markdown.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/report tests/report
git commit -m "Add Markdown report following the skill's report template"
```

---

### Task 25: JSON report and public exports

**Files:**
- Create: `src/dpr/report/json_out.py`
- Modify: `src/dpr/__init__.py` (full replacement below)
- Test: `tests/report/test_json.py`

**Interfaces:**
- Consumes: `Report` (Task 2), `review` and `discover` (Task 23), `render_markdown` (Task 24)
- Produces:
  - `dpr.report.json_out.to_data(obj) -> object` (dataclasses to dicts, skipping fields with `metadata={"json": False}`; enums to values; tuples and lists to lists; sets to sorted lists)
  - `dpr.report.json_out.render_json(report) -> str` (`schema_version` 1 first, then `meta`, `detection`, `findings`, `sections`, `questions`, `not_covered`)
  - `dpr.review`, `dpr.discover`, `dpr.render_markdown`, `dpr.render_json` exported from the package

- [ ] **Step 1: Write the failing test**

`tests/report/test_json.py`:

```python
import json

import dpr
from tests.reviews.helpers import write


def test_render_json_shape(tmp_path):
    write(tmp_path, ".env.example", "NEXT_PUBLIC_SUPABASE_ANON_KEY=\nNEXT_PUBLIC_ADMIN_SECRET=\n")
    write(
        tmp_path, "supabase/migrations/1.sql", "create table public.notes (id int, user_id uuid);"
    )
    write(tmp_path, "app/api/notes/route.ts", "export async function GET() {}\n")
    report = dpr.review(tmp_path)
    data = json.loads(dpr.render_json(report))
    assert list(data)[:2] == ["schema_version", "meta"]
    assert data["schema_version"] == 1
    assert set(data) == {
        "schema_version",
        "meta",
        "detection",
        "findings",
        "sections",
        "questions",
        "not_covered",
    }
    assert "schema" not in data["detection"] and "packages" not in data["detection"]
    [route] = data["detection"]["routes"]
    assert set(route) == {"method", "path", "file", "line", "framework", "is_public_form"}
    first = data["findings"][0]
    assert first["tag"] in ("CONFIRMED", "INFERRED", "UNVERIFIED")
    assert isinstance(first["locations"][0], dict) and {"file", "line"} <= set(
        first["locations"][0]
    )
    assert data["meta"]["applicability"][1] == ["rls", "runs"]
    assert data["questions"][0]["question"]["id"]


def test_package_exports():
    assert callable(dpr.review) and callable(dpr.discover)
    assert callable(dpr.render_markdown) and callable(dpr.render_json)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/report/test_json.py -v`
Expected: FAIL with `AttributeError: module 'dpr' has no attribute 'review'`

- [ ] **Step 3: Write the implementation**

`src/dpr/report/json_out.py`:

```python
"""Render a Report as JSON."""

from __future__ import annotations

import dataclasses
import json
from enum import Enum
from pathlib import PurePath

from dpr.model import Report


def to_data(obj: object) -> object:
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {
            f.name: to_data(getattr(obj, f.name))
            for f in dataclasses.fields(obj)
            if f.metadata.get("json", True)
        }
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, dict):
        return {str(k): to_data(v) for k, v in obj.items()}
    if isinstance(obj, set | frozenset):
        return sorted(to_data(v) for v in obj)
    if isinstance(obj, list | tuple):
        return [to_data(v) for v in obj]
    if isinstance(obj, PurePath):
        return str(obj)
    return obj


def render_json(report: Report) -> str:
    data = {"schema_version": 1, **to_data(report)}
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"
```

Replace the whole of `src/dpr/__init__.py` with this.

`src/dpr/__init__.py`:

```python
"""dpr: deterministic data protection review."""

from dpr.api import discover, review
from dpr.report.json_out import render_json
from dpr.report.markdown import render_markdown

__version__ = "0.1.0"
__all__ = ["__version__", "discover", "render_json", "render_markdown", "review"]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest -v`
Expected: PASS (whole suite)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/__init__.py src/dpr/report/json_out.py tests/report/test_json.py
git commit -m "Add JSON report and public package exports"
```

---

### Task 26: Command line

**Files:**
- Create: `src/dpr/cli.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `review`, `discover` (Task 23); `render_markdown` (Task 24); `render_json` (Task 25); `answers_template`, `load_questions` (Task 17); `run_git` (Task 15); `REVIEWS` (Task 18); `ScanError` (Task 2)
- Produces:
  - `dpr.cli.main(argv: list[str] | None = None) -> int` (entry point `dpr` from Task 1)
  - `dpr scan [PATH] [--reviews ...] [--answers FILE] [--interactive] [--url URL --i-own-this-host] [--login-path PATH] [--with-audit] [--semgrep auto|off|DIR] [--db-dump FILE] [--format md,json] [--out DIR] [--fail-on critical|high|medium|none]`
  - `dpr questions [PATH] [--out FILE]`
  - Exit codes: `0` done, `1` a finding at or above `--fail-on`, `2` `ScanError` or bad arguments (argparse also exits with 2)
  - Files: `<out>/REPORT-<date>.md`, `<out>/report-<date>.json`; default `<out>` is `<PATH>/data-protection-review`
  - At most 15 summary lines on stdout; a gitignore tip only when the report is inside a git repository and not ignored
  - `--reviews` accepts space or comma separated values; put `PATH` before `--reviews`

- [ ] **Step 1: Write the failing test**

`tests/test_cli.py`:

```python
import json
import subprocess

import yaml

from dpr.cli import main
from tests.reviews.helpers import write


def app(tmp_path):
    root = tmp_path / "app"
    write(
        root,
        ".env.example",
        "NEXT_PUBLIC_SUPABASE_ANON_KEY=\nNEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=\n",
    )
    write(root, "supabase/migrations/1.sql", "create table public.notes (id int, user_id uuid);")
    write(root, "app/page.tsx", "export default function Page() { return null }\n")
    return root


def git(root, *args):
    subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "-c",
            "user.name=dpr",
            "-c",
            "user.email=dpr@example.invalid",
            *args,
        ],
        check=True,
        capture_output=True,
    )


def test_scan_writes_reports_and_summary(tmp_path, capsys):
    root = app(tmp_path)
    assert main(["scan", str(root)]) == 0
    out_dir = root / "data-protection-review"
    [md] = list(out_dir.glob("REPORT-*.md"))
    [js] = list(out_dir.glob("report-*.json"))
    assert md.read_text().startswith("# Data Protection Review: app")
    assert json.loads(js.read_text())["schema_version"] == 1
    lines = capsys.readouterr().out.strip().splitlines()
    assert lines[0].startswith(
        "dpr: 2 findings (critical 2, high 0, medium 0, low 0), 22 open questions"
    )
    assert lines[1] == "Top fixes:"
    assert any(line.startswith("Wrote ") and line.endswith(".md") for line in lines)
    assert len(lines) <= 15


def test_fail_on(tmp_path):
    root = app(tmp_path)
    assert main(["scan", str(root), "--fail-on", "critical", "--format", "json"]) == 1
    assert main(["scan", str(root), "--fail-on", "none", "--format", "json"]) == 0
    assert (
        main(["scan", str(root), "--reviews", "leaks", "--fail-on", "high", "--format", "md"]) == 1
    )


def test_formats_reviews_and_out(tmp_path, capsys):
    root = app(tmp_path)
    out = tmp_path / "elsewhere"
    assert main(["scan", str(root), "--reviews", "2,6", "--format", "json", "--out", str(out)]) == 0
    assert [p.suffix for p in out.iterdir()] == [".json"]
    assert "Tip:" not in capsys.readouterr().out
    assert main(["scan", str(root), "--format", "sarif"]) == 2
    assert "unknown format: sarif" in capsys.readouterr().err


def test_scan_errors_exit_2(tmp_path, capsys):
    root = app(tmp_path)
    assert main(["scan", str(root), "--url", "https://example.com"]) == 2
    assert "i-own-this-host" in capsys.readouterr().err
    assert main(["scan", str(tmp_path / "missing")]) == 2


def test_gitignore_tip(tmp_path, capsys):
    root = app(tmp_path)
    git(root, "init", "-q")
    main(["scan", str(root), "--format", "md"])
    assert 'Tip: add "data-protection-review/" to .gitignore' in capsys.readouterr().out
    (root / ".gitignore").write_text("data-protection-review/\n")
    main(["scan", str(root), "--format", "md"])
    assert "Tip:" not in capsys.readouterr().out


def test_questions_command(tmp_path, capsys):
    root = app(tmp_path)
    assert main(["questions", str(root)]) == 0
    target = root / "dpr-answers.yaml"
    assert set(yaml.safe_load(target.read_text())) and len(yaml.safe_load(target.read_text())) == 22
    assert main(["questions", str(root)]) == 2
    assert "already exists" in capsys.readouterr().err
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cli.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'dpr.cli'`

- [ ] **Step 3: Write the implementation**

`src/dpr/cli.py`:

```python
"""Command line: dpr scan and dpr questions."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dpr import __version__
from dpr.api import discover, review
from dpr.gitutil import run_git
from dpr.model import Report, ScanError
from dpr.questions.catalogue import answers_template, load_questions
from dpr.report.json_out import render_json
from dpr.report.markdown import render_markdown
from dpr.reviews import REVIEWS

FORMATS = ("md", "json")
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
FAIL_LEVELS = {"none": 0, "medium": 2, "high": 3, "critical": 4}
MAX_SUMMARY_LINES = 15


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dpr", description="Data protection review. No LLM.")
    parser.add_argument("--version", action="version", version=f"dpr {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="review a repository and write the report")
    scan.add_argument("path", nargs="?", default=".")
    scan.add_argument(
        "--reviews",
        nargs="+",
        default=["all"],
        metavar="REVIEW",
        help="all, 1 to 7, or " + ", ".join(REVIEWS),
    )
    scan.add_argument("--answers", metavar="FILE")
    scan.add_argument("--interactive", action="store_true")
    scan.add_argument("--url")
    scan.add_argument("--i-own-this-host", dest="owns_host", action="store_true")
    scan.add_argument("--login-path")
    scan.add_argument("--with-audit", action="store_true")
    scan.add_argument("--semgrep", default="auto", metavar="auto|off|DIR")
    scan.add_argument("--db-dump", metavar="FILE")
    scan.add_argument("--format", default="md,json", help="comma separated: md, json")
    scan.add_argument("--out", metavar="DIR")
    scan.add_argument("--fail-on", default="none", choices=list(FAIL_LEVELS))

    questions = commands.add_parser("questions", help="write a starter answers file")
    questions.add_argument("path", nargs="?", default=".")
    questions.add_argument("--out", metavar="FILE")
    return parser


def _formats(value: str) -> list[str]:
    tokens = [token.strip().lower() for token in value.split(",") if token.strip()]
    for token in tokens:
        if token not in FORMATS:
            raise ScanError(f"unknown format: {token} (supported: {', '.join(FORMATS)})")
    if not tokens:
        raise ScanError("no output format selected")
    return tokens


def gitignore_tip(root: Path, written: Path) -> str | None:
    try:
        rel_dir = written.resolve().parent.relative_to(root.resolve()).as_posix()
    except ValueError:
        return None
    if run_git(root, "rev-parse", "--is-inside-work-tree") is None:
        return None
    if run_git(root, "check-ignore", "-q", str(written.resolve())) is not None:
        return None
    return (
        f'Tip: add "{rel_dir}/" to .gitignore. '
        "The report maps where the data and the weaknesses are."
    )


def summary_lines(report: Report, written: list[Path], tip: str | None) -> list[str]:
    counts = {s: sum(f.severity.value == s for f in report.findings) for s in SEVERITY_RANK}
    open_count = sum(q.open for q in report.questions)
    lines = [
        f"dpr: {len(report.findings)} findings (critical {counts['critical']}, "
        f"high {counts['high']}, medium {counts['medium']}, low {counts['low']}), "
        f"{open_count} open questions"
    ]
    if report.findings:
        lines.append("Top fixes:")
        lines += [
            f"  {i}. {f.title} ({f.locations[0] if f.locations else 'no file'})"
            for i, f in enumerate(report.findings[:3], start=1)
        ]
    lines += [f"Wrote {path}" for path in written]
    if tip:
        lines.append(tip)
    return lines[:MAX_SUMMARY_LINES]


def exit_code(report: Report, fail_on: str) -> int:
    threshold = FAIL_LEVELS[fail_on]
    if threshold and any(SEVERITY_RANK[f.severity.value] >= threshold for f in report.findings):
        return 1
    return 0


def _scan(args: argparse.Namespace) -> int:
    formats = _formats(args.format)
    reviews = [part for token in args.reviews for part in token.split(",") if part]
    report = review(
        args.path,
        reviews=reviews,
        answers=args.answers,
        interactive=args.interactive,
        url=args.url,
        owns_host=args.owns_host,
        login_path=args.login_path,
        with_audit=args.with_audit,
        semgrep=args.semgrep,
        db_dump=args.db_dump,
    )
    root = Path(args.path)
    out_dir = Path(args.out) if args.out else root / "data-protection-review"
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    if "md" in formats:
        written.append(out_dir / f"REPORT-{report.meta.date}.md")
        written[-1].write_text(render_markdown(report), encoding="utf-8")
    if "json" in formats:
        written.append(out_dir / f"report-{report.meta.date}.json")
        written[-1].write_text(render_json(report), encoding="utf-8")
    for line in summary_lines(report, written, gitignore_tip(root, written[0])):
        print(line)
    return exit_code(report, args.fail_on)


def _questions(args: argparse.Namespace) -> int:
    _, detection = discover(args.path)
    target = Path(args.out) if args.out else Path(args.path) / "dpr-answers.yaml"
    if target.exists():
        raise ScanError(f"{target} already exists; remove it or pass --out")
    target.write_text(answers_template(load_questions(), detection), encoding="utf-8")
    print(f"Wrote {target}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _scan(args) if args.command == "scan" else _questions(args)
    except ScanError as exc:
        print(f"dpr: error: {exc}", file=sys.stderr)
        return 2
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_cli.py -v && uv run dpr --version`
Expected: PASS (6 tests), then `dpr 0.1.0`

- [ ] **Step 5: Commit**

```bash
git add src/dpr/cli.py tests/test_cli.py
git commit -m "Add dpr scan and dpr questions commands"
```

---

### Task 27: Fixture apps and end-to-end expectations

**Files:**
- Create: every file under `tests/fixtures/next-supabase-bad/` and `tests/fixtures/next-supabase-good/` listed below, and `tests/fixture_builder.py`
- Test: `tests/test_fixtures.py`

**Interfaces:**
- Consumes: `review` (Task 23)
- Produces:
  - `tests.fixture_builder.FIXTURES` (path), `LIVE_STRIPE` and `ENV_VALUE` (runtime-built strings that must never appear in any output), `SECRETS = (LIVE_STRIPE, ENV_VALUE)`
  - `tests.fixture_builder.build(name, tmp_path) -> Path`. It copies the fixture, writes the files that must not be committed (a key-shaped Stripe string, a built chunk, env files), and creates git history.
  - `expected.yaml` per fixture. The bad fixture lists every finding exactly. The good fixture lists rule ids that must not appear.

- [ ] **Step 1: Write the bad fixture**

`tests/fixtures/next-supabase-bad/package.json`:

```json
{
  "name": "next-supabase-bad",
  "private": true,
  "dependencies": {
    "next": "14.2.0",
    "@supabase/supabase-js": "2.45.0",
    "@prisma/client": "5.18.0",
    "@sentry/nextjs": "8.20.0",
    "stripe": "16.0.0"
  }
}
```

`tests/fixtures/next-supabase-bad/next.config.js`:

```js
module.exports = {
  productionBrowserSourceMaps: true,
}
```

`tests/fixtures/next-supabase-bad/.env.example`:

```
NEXT_PUBLIC_SUPABASE_URL=
NEXT_PUBLIC_SUPABASE_ANON_KEY=
NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=
```

`tests/fixtures/next-supabase-bad/lib/supabase.ts`:

```ts
import { createClient } from "@supabase/supabase-js"

export const supabaseAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!,
)
```

`tests/fixtures/next-supabase-bad/lib/db.ts`:

```ts
import { PrismaClient } from "@prisma/client"

export const prisma = new PrismaClient()
```

`tests/fixtures/next-supabase-bad/prisma/schema.prisma`:

```prisma
model User {
  id                Int       @id @default(autoincrement())
  email             String    @unique
  passwordHash      String
  name              String?
  metadata          Json?
  medicalConditions String?
  invoices          Invoice[]
}

model Invoice {
  id     Int  @id @default(autoincrement())
  userId Int
  amount Int
  user   User @relation(fields: [userId], references: [id])
}
```

`tests/fixtures/next-supabase-bad/app/api/users/[id]/route.ts`:

```ts
import { NextResponse } from "next/server"
import { prisma } from "@/lib/db"

export async function GET(req: Request, { params }: { params: { id: string } }) {
  const user = await prisma.user.findUnique({ where: { id: Number(params.id) } })
  return NextResponse.json(user)
}
```

`tests/fixtures/next-supabase-bad/app/api/signup/route.ts`:

```ts
import { NextResponse } from "next/server"
import { prisma } from "@/lib/db"

export async function POST(req: Request) {
  const body = await req.json()
  try {
    await prisma.user.create({ data: body })
  } catch (err) {
    console.error("signup failed", body)
    return NextResponse.json({ error: "failed" }, { status: 500 })
  }
  return NextResponse.json({ ok: true })
}
```

`tests/fixtures/next-supabase-bad/sentry.client.config.ts`:

```ts
import * as Sentry from "@sentry/nextjs"

Sentry.init({
  dsn: process.env.NEXT_PUBLIC_SENTRY_DSN,
  sendDefaultPii: true,
})
```

`tests/fixtures/next-supabase-bad/supabase/migrations/20240101000000_init.sql`:

```sql
create table public.profiles (id uuid primary key, user_id uuid not null, full_name text, phone text);
alter table public.profiles enable row level security;
create policy "profiles_update" on public.profiles for update using (auth.uid() = user_id) with check (true);
create policy "profiles_admin" on public.profiles for select using (auth.jwt() -> 'user_metadata' ->> 'role' = 'admin');
create table public.documents (id bigserial primary key, user_id uuid not null, body text, metadata jsonb);
alter table public.documents enable row level security;
create policy "documents_read" on public.documents for select using (true);
create policy "documents_auth" on public.documents for select to authenticated using (auth.role() = 'authenticated');
create policy "documents_delete" on public.documents for delete to anon using (body is not null);
create table public.invoices (id bigserial primary key, user_id uuid not null, amount int);
create view public.document_list as select id, body from public.documents;
create table public.members (org_id uuid not null, user_id uuid not null);
alter table public.members enable row level security;
create table public.projects (id uuid primary key, org_id uuid not null, name text);
alter table public.projects enable row level security;
create policy "projects_read" on public.projects for select to authenticated using (exists (select 1 from public.members where members.user_id = auth.uid()));
create function public.get_all_documents() returns setof public.documents language sql security definer as $$ select * from public.documents $$;
insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);
```

`tests/fixtures/next-supabase-bad/expected.yaml`:

```yaml
# Every finding the scan must report, and nothing else.
findings:
  - {rule: LEAK-PUBLIC-SECRET, file: .env.example, line: 3, tag: CONFIRMED}
  - {rule: LEAK-HARDCODED-KEY, file: lib/stripe.ts, line: 3, tag: CONFIRMED}
  - {rule: LEAK-KEY-IN-BUILD, file: .next/static/chunks/main.js, line: 1, tag: CONFIRMED}
  - {rule: LEAK-ENV-TRACKED, file: .env, line: 1, tag: CONFIRMED}
  - {rule: LEAK-ENV-IN-HISTORY, file: .env.production, line: 1, tag: CONFIRMED}
  - {rule: LEAK-SOURCEMAP, file: .next/static/chunks/main.js.map, line: 1, tag: CONFIRMED}
  - {rule: LEAK-SOURCEMAP, file: next.config.js, line: 2, tag: CONFIRMED}
  - {rule: LEAK-SENTRY-PII, file: sentry.client.config.ts, line: 5, tag: CONFIRMED}
  - {rule: LEAK-BROAD-RESPONSE, file: "app/api/users/[id]/route.ts", line: 6, tag: INFERRED}
  - {rule: LEAK-LOGGED-PII, file: app/api/signup/route.ts, line: 9, tag: INFERRED}
  - {rule: RLS-WEAK-WITH-CHECK, file: supabase/migrations/20240101000000_init.sql, line: 3, tag: CONFIRMED}
  - {rule: RLS-CLIENT-OWNER, file: supabase/migrations/20240101000000_init.sql, line: 4, tag: CONFIRMED}
  - {rule: RLS-POLICY-TRUE, file: supabase/migrations/20240101000000_init.sql, line: 7, tag: CONFIRMED}
  - {rule: RLS-AUTHENTICATED-NOT-OWNER, file: supabase/migrations/20240101000000_init.sql, line: 8, tag: CONFIRMED}
  - {rule: RLS-WRONG-ROLE, file: supabase/migrations/20240101000000_init.sql, line: 9, tag: CONFIRMED}
  - {rule: RLS-TABLE-OFF, file: supabase/migrations/20240101000000_init.sql, line: 10, tag: CONFIRMED}
  - {rule: RLS-VIEW-BYPASS, file: supabase/migrations/20240101000000_init.sql, line: 11, tag: CONFIRMED}
  - {rule: RLS-NO-POLICIES, file: supabase/migrations/20240101000000_init.sql, line: 13, tag: CONFIRMED}
  - {rule: RLS-SELECT-ONLY, file: supabase/migrations/20240101000000_init.sql, line: 16, tag: CONFIRMED}
  - {rule: RLS-TENANT-UNBOUND, file: supabase/migrations/20240101000000_init.sql, line: 16, tag: INFERRED}
  - {rule: RLS-DEFINER-FUNCTION, file: supabase/migrations/20240101000000_init.sql, line: 17, tag: CONFIRMED}
  - {rule: RLS-PUBLIC-BUCKET, file: supabase/migrations/20240101000000_init.sql, line: 18, tag: CONFIRMED}
```

- [ ] **Step 2: Write the good fixture**

`tests/fixtures/next-supabase-good/package.json`:

```json
{
  "name": "next-supabase-good",
  "private": true,
  "dependencies": {
    "next": "14.2.0",
    "@supabase/supabase-js": "2.45.0",
    "@prisma/client": "5.18.0",
    "@sentry/nextjs": "8.20.0",
    "stripe": "16.0.0"
  }
}
```

`tests/fixtures/next-supabase-good/.gitignore`:

```
.env
.next/
```

`tests/fixtures/next-supabase-good/next.config.js`:

```js
module.exports = {
  poweredByHeader: false,
  async headers() {
    return [{ source: "/(.*)", headers: [{ key: "X-Frame-Options", value: "DENY" }] }]
  },
}
```

`tests/fixtures/next-supabase-good/.env.example`:

```
NEXT_PUBLIC_SUPABASE_URL=
NEXT_PUBLIC_SUPABASE_ANON_KEY=
SUPABASE_SERVICE_ROLE_KEY=
STRIPE_SECRET_KEY=
```

`tests/fixtures/next-supabase-good/lib/supabase-server.ts`:

```ts
import "server-only"
import { createClient } from "@supabase/supabase-js"

export const supabaseAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!,
)
```

`tests/fixtures/next-supabase-good/lib/db.ts`:

```ts
import { PrismaClient } from "@prisma/client"

export const prisma = new PrismaClient()
```

`tests/fixtures/next-supabase-good/prisma/schema.prisma`:

```prisma
model User {
  id           Int    @id @default(autoincrement())
  email        String @unique
  passwordHash String
  name         String?
}
```

`tests/fixtures/next-supabase-good/app/api/users/[id]/route.ts`:

```ts
import { NextResponse } from "next/server"
import { prisma } from "@/lib/db"
import { auth } from "@/lib/auth"

export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await auth()
  const user = await prisma.user.findUnique({
    where: { id: Number(params.id) },
    select: { id: true, name: true },
  })
  return NextResponse.json(user)
}
```

`tests/fixtures/next-supabase-good/app/api/signup/route.ts`:

```ts
import { NextResponse } from "next/server"
import { prisma } from "@/lib/db"

export async function POST(req: Request) {
  const body = await req.json()
  try {
    await prisma.user.create({ data: { email: body.email, name: body.name } })
  } catch (err) {
    console.error("signup failed", { requestId: crypto.randomUUID() })
    return NextResponse.json({ error: "failed" }, { status: 500 })
  }
  return NextResponse.json({ ok: true })
}
```

`tests/fixtures/next-supabase-good/sentry.client.config.ts`:

```ts
import * as Sentry from "@sentry/nextjs"

Sentry.init({
  dsn: process.env.NEXT_PUBLIC_SENTRY_DSN,
  sendDefaultPii: false,
  beforeSend(event) {
    delete event.request
    return event
  },
})
```

`tests/fixtures/next-supabase-good/supabase/migrations/20240101000000_init.sql`:

```sql
create table public.profiles (id uuid primary key, user_id uuid not null, full_name text, phone text);
alter table public.profiles enable row level security;
create policy "profiles_select_own" on public.profiles for select to authenticated using (auth.uid() = user_id);
create policy "profiles_update_own" on public.profiles for update to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);
create table public.documents (id bigserial primary key, user_id uuid not null, body text);
alter table public.documents enable row level security;
create policy "documents_select_own" on public.documents for select to authenticated using (auth.uid() = user_id);
create policy "documents_insert_own" on public.documents for insert to authenticated with check (auth.uid() = user_id);
create table public.members (org_id uuid not null, user_id uuid not null);
alter table public.members enable row level security;
create policy "members_select_own" on public.members for select to authenticated using (auth.uid() = user_id);
create policy "members_insert_own" on public.members for insert to authenticated with check (auth.uid() = user_id);
create table public.projects (id uuid primary key, org_id uuid not null, name text);
alter table public.projects enable row level security;
create policy "projects_read" on public.projects for select to authenticated using (org_id in (select org_id from public.members where user_id = auth.uid()));
create policy "projects_insert" on public.projects for insert to authenticated with check (org_id in (select org_id from public.members where user_id = auth.uid()));
create view public.document_list with (security_invoker = true) as select id, body from public.documents;
insert into storage.buckets (id, name, public) values ('avatars', 'avatars', false);
```

`tests/fixtures/next-supabase-good/expected.yaml`:

```yaml
# Rule ids that must not appear anywhere in this fixture's report.
must_not_report:
  - LEAK-PUBLIC-SECRET
  - LEAK-HARDCODED-KEY
  - LEAK-KEY-IN-BUILD
  - LEAK-ENV-TRACKED
  - LEAK-ENV-IN-HISTORY
  - LEAK-SOURCEMAP
  - LEAK-SENTRY-PII
  - LEAK-BROAD-RESPONSE
  - LEAK-SSR-PROPS
  - LEAK-LOGGED-PII
  - RLS-TABLE-OFF
  - RLS-NO-POLICIES
  - RLS-SELECT-ONLY
  - RLS-POLICY-TRUE
  - RLS-AUTHENTICATED-NOT-OWNER
  - RLS-WEAK-WITH-CHECK
  - RLS-WRONG-ROLE
  - RLS-CLIENT-OWNER
  - RLS-TENANT-UNBOUND
  - RLS-VIEW-BYPASS
  - RLS-DEFINER-FUNCTION
  - RLS-PUBLIC-BUCKET
```

- [ ] **Step 3: Write the builder and the failing test**

`tests/fixture_builder.py`:

```python
"""Copy a fixture app to a temporary folder and add what must never be committed."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
LIVE_STRIPE = "sk_" + "live_" + "Fx7Qp2Lm9Zr4Tb8Kw3Yd6Hn1"
ENV_VALUE = "ENVVALUE-" + "DO-NOT-PRINT-7731"
SECRETS = (LIVE_STRIPE, ENV_VALUE)


def git(root: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "-c",
            "user.name=dpr",
            "-c",
            "user.email=dpr@example.invalid",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        check=True,
        capture_output=True,
    )


def _bad_extras(root: Path) -> None:
    (root / "lib/stripe.ts").write_text(
        'import Stripe from "stripe"\n\nexport const stripe = new Stripe("' + LIVE_STRIPE + '")\n'
    )
    chunks = root / ".next/static/chunks"
    chunks.mkdir(parents=True)
    (chunks / "main.js").write_text('var cfg={k:"' + LIVE_STRIPE + '"};')
    (chunks / "main.js.map").write_text("{}")
    git(root, "init", "-q")
    (root / ".env.production").write_text(f"OLD_TOKEN={ENV_VALUE}\n")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "initial")
    git(root, "rm", "-q", "--cached", ".env.production")
    (root / ".env.production").unlink()
    (root / ".env").write_text(f"DEBUG_LABEL={ENV_VALUE}\n")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "second")


def _good_extras(root: Path) -> None:
    (root / "lib/stripe.ts").write_text(
        'import Stripe from "stripe"\n\nexport const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)\n'
    )
    (root / ".env").write_text(f"STRIPE_SECRET_KEY={ENV_VALUE}\n")
    git(root, "init", "-q")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "initial")


def build(name: str, tmp_path: Path) -> Path:
    root = tmp_path / name
    shutil.copytree(FIXTURES / name, root)
    if name == "next-supabase-bad":
        _bad_extras(root)
    else:
        _good_extras(root)
    return root
```

`tests/test_fixtures.py`:

```python
import yaml

from dpr.api import review
from tests.fixture_builder import FIXTURES, build


def found(report):
    return {
        (f.rule_id, f.locations[0].file, f.locations[0].line, f.tag.value) for f in report.findings
    }


def test_bad_fixture_reports_exactly_the_planted_defects(tmp_path):
    root = build("next-supabase-bad", tmp_path)
    expected = yaml.safe_load((FIXTURES / "next-supabase-bad" / "expected.yaml").read_text())
    want = {(e["rule"], e["file"], e["line"], e["tag"]) for e in expected["findings"]}
    got = found(review(root))
    assert got - want == set(), "unexpected findings"
    assert want - got == set(), "missing findings"


def test_bad_fixture_severities(tmp_path):
    report = review(build("next-supabase-bad", tmp_path))
    severity = {(f.rule_id, f.locations[0].line): f.severity.value for f in report.findings}
    assert severity[("RLS-TABLE-OFF", 10)] == "critical"
    assert severity[("LEAK-BROAD-RESPONSE", 6)] == "high"
    assert severity[("RLS-WEAK-WITH-CHECK", 3)] == "high"
    assert severity[("RLS-DEFINER-FUNCTION", 17)] == "high"


def test_good_fixture_reports_none_of_the_defects(tmp_path):
    report = review(build("next-supabase-good", tmp_path))
    banned = set(
        yaml.safe_load((FIXTURES / "next-supabase-good" / "expected.yaml").read_text())[
            "must_not_report"
        ]
    )
    assert [f for f in report.findings if f.rule_id in banned] == []
    assert set(report.sections) == {"leaks", "rls"}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_fixtures.py -v`
Expected: PASS (3 tests). If the bad fixture test fails, the assertion message says whether a finding is unexpected or missing. Fix the rule, not the expectation, unless the fixture line numbers were typed wrong.

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures tests/fixture_builder.py tests/test_fixtures.py
git commit -m "Add next-supabase fixture apps with exact end-to-end expectations"
```

---

### Task 28: Safety tests

**Files:**
- Test: `tests/test_safety.py`

**Interfaces:**
- Consumes: `review` (Task 23), `render_markdown` (Task 24), `render_json` (Task 25), `main` (Task 26), `BANNED_PHRASES` (Task 24), `build`, `SECRETS` (Task 27)
- Produces: tests only. They guard the skill's non-negotiable rules for every later milestone.

- [ ] **Step 1: Write the tests**

`tests/test_safety.py`:

```python
import socket
import subprocess

import pytest

from dpr.api import review
from dpr.cli import main
from dpr.model import Tag
from dpr.report.json_out import render_json
from dpr.report.markdown import BANNED_PHRASES, render_markdown
from tests.fixture_builder import SECRETS, build


@pytest.fixture
def bad(tmp_path):
    return build("next-supabase-bad", tmp_path)


def test_no_secret_value_in_any_output(bad, tmp_path, capsys):
    report = review(bad)
    outputs = [render_markdown(report), render_json(report), repr(report.findings)]
    out_dir = tmp_path / "out"
    main(["scan", str(bad), "--out", str(out_dir)])
    outputs += [p.read_text() for p in out_dir.iterdir()]
    captured = capsys.readouterr()
    outputs += [captured.out, captured.err]
    for secret in SECRETS:
        for text in outputs:
            assert secret not in text


def test_default_run_opens_no_network_connection(bad, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("network connection attempted")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    review(bad, semgrep="off")


def test_evidence_rules_hold_for_every_finding(bad):
    for finding in review(bad).findings:
        assert finding.tag is not Tag.UNKNOWN
        if finding.tag is Tag.CONFIRMED:
            assert finding.locations
        if finding.tag is Tag.INFERRED:
            assert finding.proof_needed


def test_report_has_no_legal_verdicts_or_em_dashes(bad):
    text = render_markdown(review(bad))
    assert not any(phrase in text.lower() for phrase in BANNED_PHRASES)
    assert "\u2014" not in text


def test_review_does_not_change_the_repository(bad):
    before = subprocess.run(
        ["git", "-C", str(bad), "status", "--porcelain", "--ignored"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    listing = sorted(
        p.relative_to(bad).as_posix() for p in bad.rglob("*") if ".git/" not in p.as_posix()
    )
    review(bad)
    after = subprocess.run(
        ["git", "-C", str(bad), "status", "--porcelain", "--ignored"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert after == before
    assert (
        sorted(p.relative_to(bad).as_posix() for p in bad.rglob("*") if ".git/" not in p.as_posix())
        == listing
    )
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `uv run pytest tests/test_safety.py -v`
Expected: PASS (5 tests). These guard behaviour built in earlier tasks, so they pass on the first run. To prove each test can fail, temporarily add `print(ENV_VALUE)`-style leaks in a scratch copy only if in doubt; do not commit such a change.

- [ ] **Step 3: Commit**

```bash
git add tests/test_safety.py
git commit -m "Add safety tests for secrets, network, evidence tags and legal wording"
```

---

### Task 29: CI workflow, formatting and local test report

**Files:**
- Create: `.github/workflows/ci.yml`
- Modify: formatting of every Python file (via `ruff format`), `tasks/todo.md` (review section)

**Interfaces:**
- Consumes: the whole Milestone 1 package and tests
- Produces: CI running lint, format check and tests with coverage on every push to `feature/**`, `bugfix/**`, `develop`, `main`, and on pull requests; a local test report recorded in `tasks/todo.md`

- [ ] **Step 1: Write the workflow**

`.github/workflows/ci.yml`:

```yaml
name: ci

on:
  push:
    branches: ["feature/**", "bugfix/**", develop, main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v6
        with:
          python-version: "3.12"
      - run: uv sync --locked
      - run: uv run ruff check
      - run: uv run ruff format --check
      - run: uv run pytest -m "not semgrep" --cov=dpr --cov-report=term-missing
```

- [ ] **Step 2: Format and run everything locally**

Run: `uv run ruff format && uv run ruff check && uv run ruff format --check`
Expected: files reformatted once, then `All checks passed!` and `N files already formatted`

Run: `uv run pytest -m "not semgrep" --cov=dpr --cov-report=term-missing`
Expected: every test passes; note the total test count and coverage percentage

- [ ] **Step 3: Smoke run the CLI on the bad fixture**

Run:

```bash
uv run python -c "
import pathlib, tempfile
from tests.fixture_builder import build
root = build('next-supabase-bad', pathlib.Path(tempfile.mkdtemp()))
print(root)
" > /tmp/dpr-fixture-path.txt
uv run dpr scan "$(cat /tmp/dpr-fixture-path.txt)" --fail-on critical; echo "exit $?"
```

Expected: a summary starting `dpr: 22 findings`, two `Wrote` lines, and `exit 1` (critical findings exist). Open the written `REPORT-*.md` and read it once end to end.

- [ ] **Step 4: Record the local test report**

Append to `tasks/todo.md`, filling in the real numbers from Steps 2 and 3:

```markdown
## Milestone 1 review

- Tests: <count> passed, 0 failed (`uv run pytest -m "not semgrep" --cov=dpr`)
- Coverage: <percent>% of `src/dpr`
- Lint and format: `ruff check` and `ruff format --check` clean
- CLI smoke run on the bad fixture: 22 findings, exit code 1 with `--fail-on critical`
- Not done in this milestone: baseline, abuse, OWASP, inventory and auth reviews; SARIF; Semgrep and audit adapters; live header read; smoke runs on real repositories (Milestones 2 and 3)
```

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml tasks/todo.md src tests
git commit -m "Add CI workflow, apply formatting and record Milestone 1 test report"
```

Do not push. Do not merge into `develop`. Tell the owner the branch is ready and wait for the instruction to push and open a pull request.


## Milestone 1 review

- Tests: 153 passed, 0 failed (`uv run pytest -m "not semgrep" --cov=dpr`)
- Coverage: 96% of `src/dpr`
- Lint and format: `ruff check` and `ruff format --check` clean
- CLI smoke run on the bad fixture: 22 findings, exit code 1 with `--fail-on critical`
- Task 30 (tree-sitter row crash fix) completed early as part of Milestone 1
- Not done in this milestone: baseline, abuse, OWASP, inventory and auth reviews; SARIF; Semgrep and audit adapters; live header read; smoke runs on real repositories (Milestones 2 and 3)

---

## Milestone 2

> **Controller notes added when this plan was appended (2026-09-17):**
> - Task 30 was already completed during Milestone 1 (commit 9945eed). Do not redo it.
> - After this plan was written, the Milestone 1 whole-branch review fix wave (commits 57e9332..325dc75) changed: `Route` gained `wrappers: tuple[str, ...] = ()` and wrapped handlers are unwrapped (a wrapper call with no function argument becomes the handler itself, so check `handler.type` before walking it); a shared response-call helper in `leaks_code.py`; RLS policy rules skip server-role and restrictive policies and tag helper-function predicates INFERRED; LEAK-ENV-TRACKED severity follows the names in the file; the walker skips virtualenvs and non-regular files; the sanity check fails only when no supported source was indexed; `run_git` uses `--no-optional-locks`; `review()` guards each review's `run()`; the CLI exits 2 on unexpected errors; ruff excludes `*.md`; em dash checks in tests use `chr(0x2014)` and a guard test scans every file. Where a task below edits a file by exact old text that no longer matches, apply the edit by intent and say so in the report.

> Steps use checkbox (`- [ ]`) syntax for tracking. Task numbers continue from Milestone 1 (Tasks 1 to 29).

**Goal:** Add review 4 (security baseline), review 5 (OWASP sweep with route classification) and review 7 (abuse and bill guard), SARIF output, the live header adapter, and the `django-bad`, `fastapi-bad` and `fastapi-good` fixtures, so that `dpr`'s report on a real FastAPI, React and Terraform repository reaches the Critical, High and most Medium and Low findings the `data-protection-review` skill reports for reviews 4 to 7. Still no LLM, and still no network in a default run.

**Architecture:** Nothing in the Milestone 1 pipeline changes shape. Each new review is a module under `src/dpr/reviews/` with `run(ctx) -> ReviewSection`, plus rule modules it imports so their `@rule` checks register. Three shared analyses feed the rules and are cached per run: route access classification (`access.py`: public, authenticated or admin, and the names that hold the caller in each handler), request-keyed record lookups with one to two levels of helper resolution (`lookups.py`), and paid routes (`paid.py`). Header checks are judged per surface (each static host config and each app) from configuration, or from the live site when the owner passes `--url` with `--i-own-this-host`. Review modules may define `finish(ctx, section, findings)`, which the pipeline calls after the checks, for section parts that summarise findings. SARIF is a third renderer beside Markdown and JSON.

**Tech Stack:** unchanged from Milestone 1. No new dependency: the live header read uses stdlib `urllib`, and the Terraform reader is a small own parser.

**Spec:** `docs/superpowers/specs/2026-09-16-dpr-design.md`, sections 10.4 to 10.6, 11.3 and 16.

**Assumes Milestone 1 as built**, which differs from the Milestone 1 plan text in two helpers changed after review: `jsts.unwrap()` descends into the last named child of a `type_assertion` (`<Foo>bar`) and into the first named child of every other wrapper, and `jsts.resolve_identifier()` only accepts a `variable_declarator` whose own enclosing function is the identifier's scope (compared by start byte, end byte and type), or, at program level, a declarator with no enclosing function. Milestone 2 relies on both: SDK client resolution in `paid.py` and request value resolution in the SSRF, path traversal and mass assignment rules would otherwise pick declarators from nested functions.

### Scope: comparison with the skill

The plan was checked against the skill's report on a private comparison repository. The per-finding comparison is kept outside this repository.

Every rule id named in spec sections 10.4, 10.5 and 10.6 is also implemented (Tasks 34 to 47), with positive and negative tests, whether or not the comparison repository triggers it.

### How this plan was checked

Every code block in this plan was built and run in a scratch copy of the Milestone 1 code (with the two helper changes above) before the plan was handed over.

- Tests: 243 passed (149 from Milestone 1, 94 new), coverage 95% of `src/dpr`; `uv run ruff format` left every file unchanged, then `ruff check` and `ruff format --check` were clean.
- Plan text: all tasks were extracted from this document into a fresh copy of the Milestone 1 code; the result matched the scratch copy file for file, and its tests and lint passed. The extraction was also replayed after every single task (30 to 52): each intermediate state passed its tests with ruff clean. For every task, the Step 2 command was run on the state after that task's Step 1 and produced the failure the plan describes.
- Milestone 1 crashed on a real repository with a bus error in `tree-sitter` (Task 30 explains and fixes it).
- A scan of the private comparison repository after Task 52 exits 0 and leaves that repository unchanged.
- Fixtures after Task 51: `next-supabase-bad` 44 findings, `django-bad` 17, `fastapi-bad` 33, and none of the planted rule ids in `next-supabase-good` or `fastapi-good`.

### Global Constraints

Milestone 1's constraints still hold:

- Python `>=3.12`, managed with `uv`. Run every command through `uv run`.
- Layout `src/dpr/`, build backend `hatchling`.
- Runtime dependencies are exactly: `tree-sitter>=0.25`, `tree-sitter-javascript>=0.23`, `tree-sitter-typescript>=0.23`, `pyyaml>=6.0`, `jinja2>=3.1`. Dev: `pytest>=8`, `pytest-cov>=5`, `ruff>=0.6`. Nothing else.
- Never use `tree-sitter-language-pack` (downloads grammars at runtime).
- A default run (`semgrep="off"`, no `url`, no audits) opens no network connection.
- Never store or print a secret value. `.env*` files are read for names only; the text after `=` is discarded while reading.
- `Finding` with tag CONFIRMED must have a location. INFERRED must have `proof_needed`. UNKNOWN is never a finding.
- No legal verdict phrases anywhere in output or rule text: `compliant with`, `complies with`, `satisfies Article`, `satisfies Section`, `lawful basis is`.
- No em dash characters in code, rule text, templates, docs or commit messages.
- `dpr.review()` writes no files. Only the CLI writes.
- Tests run with `DPR_STRICT=1` (set in `tests/conftest.py`) so a failing rule raises.
- Ruff line length 100. Keep each module under about 400 lines.
- Git: work on `feature/dpr-scanner`. Commit after each task. No remote, no push. Commit messages are plain imperative sentences with no AI attribution and no `Co-Authored-By` line.
- Key-shaped test strings are assembled at runtime (for example `"sk_" + "live_" + ...`). Never commit a literal key-shaped string.

New in Milestone 2:

- Rules are general. They match framework and library patterns, never names, paths or strings from a particular repository. Every rule has positive and negative tests on small synthetic snippets, and the fixture apps prove it end to end.
- The live header read happens only when both `url` and `owns_host` are set: exactly three `HEAD` requests (https root and https login page following redirects, http root without), 10 second timeout each, stdlib `urllib`, no cookies, credentials or body. Tests never open a socket: they monkeypatch `read_headers` or pass an `opener`.
- Credential rules report where a value is, never the value. They set no snippet, or mask the literal as `<redacted:password>`. Password literals found in code are compared with other files by SHA-256 digest in memory, and the fixtures that plant them build the values at test time.
- A review module registers its rule modules with `import dpr.reviews.<module>  # noqa: F401  (registers rules)` lines, one per rule module, in sorted order before the `from` imports. Rule text lives in one YAML file per task under `src/dpr/data/rule_text/`.
- Rules that look for defects in application code skip test files (`dpr.reviews.paths.is_test`).
- A review module may define `finish(ctx, section, findings)`; the pipeline calls it after that review's checks, with that review's findings.
- Every commit leaves `uv run pytest -q` green and `uv run ruff check` and `uv run ruff format --check` clean.

### File map for Milestone 2

| File | Responsibility |
|---|---|
| `src/dpr/parsing/jsts.py` | (modified) line numbers read by index, not `Point.row` |
| `src/dpr/parsing/routes_py.py` | (modified) `APIRouter(prefix=...)` and `Blueprint(url_prefix=...)` in route paths |
| `src/dpr/parsing/pyvalues.py` | Resolve Python values to string literals: constants, names, environment fallbacks, loop items |
| `src/dpr/parsing/hcl.py` | Top-level Terraform blocks and attributes |
| `src/dpr/api.py` | (modified) skipped-option notes per review run; `finish` hook |
| `src/dpr/cli.py`, `src/dpr/__init__.py` | (modified) `--format sarif`, `dpr.render_sarif` |
| `src/dpr/report/sarif.py` | SARIF 2.1.0 renderer |
| `src/dpr/adapters/__init__.py`, `src/dpr/adapters/headers.py` | Live header read |
| `src/dpr/reviews/paths.py` | Test file detection |
| `src/dpr/reviews/access.py` | Route access classification per framework |
| `src/dpr/reviews/lookups.py` | Request-keyed record lookups, helper resolution, model ownership |
| `src/dpr/reviews/paid.py` | Paid SDK names and paid routes |
| `src/dpr/reviews/headers_static.py` | Header surfaces from configuration and app code |
| `src/dpr/reviews/baseline.py` | Review 4 section and rule module imports |
| `src/dpr/reviews/baseline_config.py` | Cookie flags, debug mode, weak password hashing, mixed content |
| `src/dpr/reviews/baseline_headers.py` | Missing headers, weak CSP, version disclosure, live checks |
| `src/dpr/reviews/baseline_accounts.py` | Committed account passwords, seed on start, short password minimum, SameSite None without CSRF |
| `src/dpr/reviews/baseline_infra.py` | Terraform database exposure, admin connection strings, HTTPS enforcement |
| `src/dpr/reviews/owasp.py` | Review 5 section, route table, categories reviewed, rule module imports |
| `src/dpr/reviews/owasp_a01.py` | Unscoped lookups, guessable IDs, unguarded methods, email ownership |
| `src/dpr/reviews/owasp_paths.py` | Path traversal in file writes |
| `src/dpr/reviews/owasp_assign.py` | Mass assignment, client-only admin guards |
| `src/dpr/reviews/owasp_inject.py` | Raw SQL, XSS sinks, command execution, HTML email |
| `src/dpr/reviews/owasp_misc.py` | Weak random tokens, secrets in URLs, client prices, SSRF |
| `src/dpr/reviews/owasp_integrity.py` | SRI, deserialisation, CI, unpinned dependencies and installs, auth failure logging, XML parsing |
| `src/dpr/reviews/abuse.py` | Review 7 section and rule module imports |
| `src/dpr/reviews/abuse_paid.py` | Paid routes without auth, limits or kill switch; public forms |
| `src/dpr/reviews/abuse_limits.py` | In-memory, unwired and proxy-keyed limiters; unbounded uploads |
| `src/dpr/reviews/abuse_cors.py` | CORS wildcard, reflection and loose patterns; exception text in responses |
| `src/dpr/reviews/leaks.py` | (modified) imports `leaks_creds` |
| `src/dpr/reviews/leaks_creds.py` | Browser-shipped gate keys, committed default credentials |
| `src/dpr/data/costs.yaml` | Cost notes and starting limits per paid category |
| `src/dpr/data/stack.yaml` | (modified) static host configs count as header config |
| `src/dpr/data/rule_text/*.yaml` | One file per task: `baseline_config`, `baseline_headers`, `baseline_accounts`, `baseline_infra`, `owasp_a01`, `owasp_files`, `owasp_inject`, `owasp_integrity`, `abuse_paid`, `abuse_limits`, `abuse_cors`, `leaks_creds` |
| `tests/...` | Unit and rule tests per task, SARIF and CLI tests, Milestone 2 safety tests |
| `tests/fixtures/django-bad/`, `tests/fixtures/fastapi-bad/`, `tests/fixtures/fastapi-good/` | New fixture apps |
| `tests/fixtures/next-supabase-bad/`, `tests/fixtures/next-supabase-good/` | (modified) Milestone 2 defects and their fixes |
| `tests/fixture_builder.py`, `tests/test_fixtures.py` | (modified) extras per fixture, parametrised exact comparison |

The spec's `reviews/baseline.py`, `reviews/owasp.py` and `reviews/abuse.py` are split into rule modules to keep each file under about 400 lines, as Milestone 1 did for leaks and RLS. The fixture list adds `fastapi-bad` beside the spec's `fastapi-good`, so every FastAPI rule is proven end to end on a bad twin.

### Refinements to the spec found while planning

- **Header checks per surface.** "Not set in any header config" would let a static site that sets `X-Frame-Options` hide an API that sets nothing. Each surface is judged on its own, and one finding per header lists every surface that lacks it. Vercel and Netlify configs count HSTS as set, because both platforms send it by default.
- **Baseline and abuse rules carry an OWASP category** (A01, A02, A04, A05, A07), so SARIF properties and a later Semgrep dedupe can use it. Review 5's "Categories reviewed" part counts only its own rules and cross-references the others.
- **`ABUSE-INMEMORY-LIMITER` also applies to multi-process deploys**, not only serverless hosting: two gunicorn workers keep two counters just as two functions do. Evidence of more than one process is cited as a second location.
- **`OWASP-A01-UNSCOPED-QUERY`**: a later comparison or non-logging call that uses both the caller and the loaded record counts as an ownership check and clears the finding; a later call that receives only the caller makes it INFERRED. Records are reported only for models that belong to someone (user-like models, owner or tenant columns, or a parent key to an owned model); reference data is skipped. Helper calls that cannot be resolved to one definition are not reported, because there is no model to judge. Form and body fields are not treated as record identifiers.
- **`OWASP-A01-GUESSABLE-ID`** is reported only for owned models, for the same reason.
- **`ABUSE-FORM-NO-CHALLENGE`** needs the route to be public and not a `GET`; the spec's `is_public_form` flag alone also marks signed-in upload routes. One finding per file lists every route.
- **`ABUSE-ERROR-LEAK`** covers catch-all exceptions (`Exception`, `BaseException`, bare `except`); messages of narrow exceptions such as `ValueError` are usually written for users.
- **`OWASP-A02-SECRET-IN-URL`** does not report `token=` in one-time links (reset, verify, confirm, invite, magic, activate, unsubscribe): that is the standard delivery for single-use tokens, and their storage and expiry belong to the auth review.
- **`OWASP-A03-RAW-SQL`** skips Alembic and `migrations/` folders: their formatted SQL is built from constants at deploy time.
- **Route paths include router prefixes** for FastAPI and Flask, so tables read `/auth/register`.
- **Pipeline `finish` hook**, so sections can summarise their own findings without changing `run()`.
- **Rules added beyond the spec's tables**, from the comparison report's gaps: `BASE-LITERAL-PASSWORD-HASH`, `BASE-SEED-ON-START`, `BASE-SHORT-PASSWORD-MIN`, `BASE-SAMESITE-NONE-NO-CSRF`, `BASE-DB-NETWORK-OPEN`, `BASE-DB-ADMIN-LOGIN`, `BASE-HTTPS-NOT-ENFORCED`, `OWASP-A01-EMAIL-OWNERSHIP`, `OWASP-A01-PATH-TRAVERSAL`, `OWASP-A03-HTML-EMAIL`, `OWASP-A05-XML-PARSER`, `OWASP-A08-UNPINNED-DEPS`, `OWASP-A08-UNPINNED-INSTALL`, `ABUSE-LIMITER-NOT-APPLIED`, `ABUSE-LIMITER-PROXY-IP`, `ABUSE-UPLOAD-UNBOUNDED`, `LEAK-PUBLIC-GATE-KEY`, `LEAK-DEFAULT-CREDENTIAL`.
- **tree-sitter 0.26 `Point.row`** corrupts memory past line 256 (Task 30). Any future helper must index points (`start_point[0]`) rather than read `.row` or `.column`.

---

### Task 30: Fix the tree-sitter line number crash

Running Milestone 1 on a real FastAPI and React repository crashed the whole process with a bus error. The cause is in `tree-sitter` 0.26.0: reading `Point.row` returns an integer without taking a reference, so for any row above 256 (integers up to 256 are shared, immortal objects) the value is freed while still in use and the garbage collector later walks corrupted memory. Indexing the point as a tuple (`start_point[0]`) takes the reference correctly. Every Milestone 1 fixture file is shorter than 256 lines, which is why no Milestone 1 test caught it.

**Files:**
- Modify: `src/dpr/parsing/jsts.py` (one line in `line()`)
- Test: `tests/parsing/test_jsts_lines.py`

**Interfaces:**
- Consumes: `jsts.parse_source`, `jsts.calls`, `jsts.line` (Task 7)
- Produces: `jsts.line(tree, node)` safe for any line number. Behaviour is otherwise unchanged.

- [ ] **Step 1: Write the failing test**

The test runs the loop in a child process, so a crash shows up as a failed assertion instead of killing pytest.

`tests/parsing/test_jsts_lines.py`:

```python
import subprocess
import sys

SCRIPT = """
import gc
import dpr
from dpr.parsing import jsts

code = "\\n" * 600 + "call(1)\\n"
tree = jsts.parse_source("big.ts", code)
[node] = list(jsts.calls(tree, "call"))
lines = []
for i in range(3000):
    lines.append(jsts.line(tree, node))
    if i % 100 == 0:
        gc.collect()
print(lines[0], len(set(lines)))
"""


def test_line_numbers_past_256_do_not_corrupt_memory():
    result = subprocess.run(
        [sys.executable, "-c", SCRIPT], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr[-500:]
    assert result.stdout.split() == ["601", "1"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/parsing/test_jsts_lines.py -v`
Expected: FAIL with `assert -11 == 0` (the child process died with a segmentation fault; on some runs the code is `-10`, a bus error)

- [ ] **Step 3: Fix `line()`**

Modify `src/dpr/parsing/jsts.py`, replace:

```python
    return node.start_point.row + 1 + tree.line_offset
```

with:

```python
    return node.start_point[0] + 1 + tree.line_offset
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/parsing -q`
Expected: PASS (all parsing tests, including `test_line_numbers_past_256_do_not_corrupt_memory`)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/parsing/jsts.py tests/parsing/test_jsts_lines.py
git commit -m "Read tree-sitter rows by index to avoid a use-after-free past line 256"
```

---

### Task 31: Register the baseline, OWASP and abuse reviews

The three review modules start with a findings part only. Later tasks add rules by importing rule modules from them. The Milestone 1 tests that asserted these reviews were "not available in this version" change here, once. The bad fixture test keeps its exact comparison for leaks and RLS rules until Task 49 extends the fixture.

**Files:**
- Create: `src/dpr/reviews/baseline.py`, `src/dpr/reviews/owasp.py`, `src/dpr/reviews/abuse.py`
- Modify: `src/dpr/api.py` (skipped option notes depend on whether the owning review ran), `tests/test_api.py`, `tests/test_fixtures.py`

**Interfaces:**
- Consumes: `Part`, `ReviewSection` (Task 2), `Context` (Task 4), `available()` (Task 18)
- Produces: `dpr.reviews.baseline.run`, `dpr.reviews.owasp.run`, `dpr.reviews.abuse.run`, each `run(ctx: Context) -> ReviewSection`; `review()` now reports all of reviews 2, 4, 5, 6 and 7 as `runs` when applicable

- [ ] **Step 1: Update the Milestone 1 tests to the new applicability**

Modify `tests/test_api.py`, replace:

```python
    assert set(report.sections) == {"leaks", "rls"}
    assert report.meta.reviews_run == ("rls", "leaks")
```

with:

```python
    assert set(report.sections) == {"leaks", "rls", "baseline", "owasp", "abuse"}
    assert report.meta.reviews_run == ("rls", "baseline", "owasp", "leaks", "abuse")
```

Modify `tests/test_api.py`, replace:

```python
        "baseline": "not available in this version",
        "owasp": "not available in this version",
        "leaks": "runs",
        "abuse": "not available in this version",
```

with:

```python
        "baseline": "runs",
        "owasp": "runs",
        "leaks": "runs",
        "abuse": "runs",
```

Modify `tests/test_api.py`, replace:

```python
def test_url_note_until_baseline_exists(tmp_path):
    report = review(app(tmp_path), url="https://example.com", owns_host=True)
    assert any("Live header read skipped" in n for n in report.not_covered)
```

with:

```python
def test_url_note_when_baseline_does_not_run(tmp_path):
    report = review(app(tmp_path), reviews=["leaks"], url="https://example.com", owns_host=True)
    assert (
        "Live header read skipped: it belongs to review 4 (baseline), which did not run"
        in report.not_covered
    )
```

Modify `tests/test_fixtures.py`, replace:

```python
    got = found(review(root))
```

with:

```python
    got = {item for item in found(review(root)) if item[0].startswith(("LEAK-", "RLS-"))}
```

Modify `tests/test_fixtures.py`, replace:

```python
    assert set(report.sections) == {"leaks", "rls"}
```

with:

```python
    assert set(report.sections) == {"leaks", "rls", "baseline", "owasp", "abuse"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_api.py tests/test_fixtures.py -q`
Expected: FAIL in `test_full_run`, `test_url_note_when_baseline_does_not_run` and `test_good_fixture_reports_none_of_the_defects` (the three reviews are still "not available in this version")

- [ ] **Step 3: Create the review modules and adjust the skipped option notes**

`src/dpr/reviews/baseline.py`:

```python
"""Review 4, security baseline: headers, cookies, transport, password storage."""

from __future__ import annotations

from dpr.model import Part, ReviewSection
from dpr.rules import Context


def run(ctx: Context) -> ReviewSection:
    return ReviewSection("baseline", [Part("findings", "Fix list")])
```

`src/dpr/reviews/owasp.py`:

```python
"""Review 5, OWASP sweep: own rules weighted to broken access control."""

from __future__ import annotations

from dpr.model import Part, ReviewSection
from dpr.rules import Context


def run(ctx: Context) -> ReviewSection:
    return ReviewSection("owasp", [Part("findings", "Findings")])
```

`src/dpr/reviews/abuse.py`:

```python
"""Review 7, abuse and bill guard: paid routes, limits, forms, CORS and error text."""

from __future__ import annotations

from dpr.model import Part, ReviewSection
from dpr.rules import Context


def run(ctx: Context) -> ReviewSection:
    return ReviewSection("abuse", [Part("findings", "Guards")])
```

Modify `src/dpr/api.py`, replace:

```python
        "Live header read skipped: it belongs to review 4 (baseline), "
        "which is not available in this version",
```

with:

```python
        "Live header read skipped: it belongs to review 4 (baseline), which did not run",
```

Modify `src/dpr/api.py`, replace:

```python
        "Dependency audit skipped: it belongs to review 5 (owasp), "
        "which is not available in this version",
```

with:

```python
        "Dependency audit skipped: it belongs to review 5 (owasp), which did not run",
```

Modify `src/dpr/api.py`, replace:

```python
        if getattr(options, option) and owner not in modules:
```

with:

```python
        if getattr(options, option) and owner not in sections:
```

- [ ] **Step 4: Run the whole suite**

Run: `uv run pytest -q`
Expected: PASS (every Milestone 1 test plus Task 30's)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/reviews/baseline.py src/dpr/reviews/owasp.py src/dpr/reviews/abuse.py src/dpr/api.py tests/test_api.py tests/test_fixtures.py
git commit -m "Register baseline, OWASP and abuse reviews and note skipped options per review run"
```

---
### Task 32: SARIF output

**Files:**
- Create: `src/dpr/report/sarif.py`
- Modify: `src/dpr/__init__.py` (export `render_sarif`), `src/dpr/cli.py` (`--format sarif`), `tests/test_cli.py` (the old "sarif is unknown" assertion)
- Test: `tests/report/test_sarif.py`, `tests/test_cli_sarif.py`

**Interfaces:**
- Consumes: `Report`, `Finding` (Task 2), `dpr.__version__` (Task 1)
- Produces: `dpr.render_sarif(report: Report) -> str` (SARIF 2.1.0 JSON, one run, tool `dpr`, one rule per `rule_id` in first-seen order, levels critical and high `error`, medium `warning`, low `note`, result properties `tag`, `severity`, `exploitability`, `review` and `owasp` when set, no questions); `dpr scan --format sarif` writes `<out>/report-YYYY-MM-DD.sarif`

- [ ] **Step 1: Write the failing tests**

`tests/report/test_sarif.py`:

```python
import json

import dpr
from dpr.model import Detection, Finding, Location, Report, ReportMeta
from dpr.report.sarif import render_sarif


def finding(rule_id, severity, **extra):
    base = dict(
        rule_id=rule_id,
        review="owasp",
        title=f"Title {rule_id}",
        tag="CONFIRMED",
        severity=severity,
        exploitability="high",
        effort_minutes=5,
        locations=(Location("app/a.py", 7),),
        detail="Detail.",
        fix="Fix.",
        owasp="A01",
    )
    base.update(extra)
    return Finding(**base)


def report(findings):
    meta = ReportMeta("shop", ".", "abc", "2026-09-17", ("owasp",), "Static analysis", ())
    return Report(meta, Detection(), findings, {}, [], [])


def test_sarif_shape_levels_and_rules():
    findings = [
        finding("OWASP-A01-UNSCOPED-QUERY", "critical"),
        finding("OWASP-A01-UNSCOPED-QUERY", "high", locations=(Location("app/b.py", 3),)),
        finding("ABUSE-ERROR-LEAK", "medium", review="abuse", owasp=None),
        finding(
            "BASE-HEADER-MISSING-HSTS",
            "low",
            review="baseline",
            tag="UNVERIFIED",
            locations=(),
            owasp=None,
        ),
    ]
    data = json.loads(render_sarif(report(findings)))
    assert data["version"] == "2.1.0"
    [run] = data["runs"]
    assert run["tool"]["driver"]["name"] == "dpr"
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == [
        "OWASP-A01-UNSCOPED-QUERY",
        "ABUSE-ERROR-LEAK",
        "BASE-HEADER-MISSING-HSTS",
    ]
    levels = [r["level"] for r in run["results"]]
    assert levels == ["error", "error", "warning", "note"]
    first = run["results"][0]
    assert first["ruleIndex"] == 0 and run["results"][2]["ruleIndex"] == 1
    region = first["locations"][0]["physicalLocation"]
    assert region["artifactLocation"]["uri"] == "app/a.py"
    assert region["region"]["startLine"] == 7
    assert first["properties"] == {
        "tag": "CONFIRMED",
        "severity": "critical",
        "exploitability": "high",
        "review": "owasp",
        "owasp": "A01",
    }
    assert "locations" not in run["results"][3]
    assert "owasp" not in run["results"][2]["properties"]


def test_sarif_excludes_questions_and_is_exported(tmp_path):
    data = json.loads(render_sarif(report([])))
    assert data["runs"][0]["results"] == []
    assert "questions" not in json.dumps(data)
    assert dpr.render_sarif is render_sarif
```

`tests/test_cli_sarif.py`:

```python
import json

from dpr.cli import main
from tests.reviews.helpers import write


def test_scan_writes_sarif(tmp_path, capsys):
    root = tmp_path / "app"
    write(root, ".env.example", "NEXT_PUBLIC_ADMIN_SECRET=\n")
    write(root, "app/page.tsx", "export default function Page() { return null }\n")
    out = tmp_path / "out"
    assert main(["scan", str(root), "--format", "md,sarif", "--out", str(out)]) == 0
    [sarif] = list(out.glob("report-*.sarif"))
    data = json.loads(sarif.read_text())
    assert data["version"] == "2.1.0"
    assert any(r["ruleId"] == "LEAK-PUBLIC-SECRET" for r in data["runs"][0]["results"])
    assert sorted(p.suffix for p in out.iterdir()) == [".md", ".sarif"]
    assert main(["scan", str(root), "--format", "xml", "--out", str(out)]) == 2
    assert "unknown format: xml (supported: md, json, sarif)" in capsys.readouterr().err
```

Modify `tests/test_cli.py`, replace:

```python
    assert main(["scan", str(root), "--format", "sarif"]) == 2
    assert "unknown format: sarif" in capsys.readouterr().err
```

with:

```python
    assert main(["scan", str(root), "--format", "xml"]) == 2
    assert "unknown format: xml" in capsys.readouterr().err
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/report/test_sarif.py tests/test_cli_sarif.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'dpr.report.sarif'`

- [ ] **Step 3: Write the renderer and wire it in**

`render_sarif` imports `__version__` inside the function because `dpr/__init__.py` imports this module before it defines `__version__`.

`src/dpr/report/sarif.py`:

```python
"""Render a Report as SARIF 2.1.0."""

from __future__ import annotations

import json

from dpr.model import Finding, Report

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def _properties(f: Finding) -> dict:
    props = {
        "tag": f.tag.value,
        "severity": f.severity.value,
        "exploitability": f.exploitability.value,
        "review": f.review,
    }
    if f.owasp:
        props["owasp"] = f.owasp
    return props


def _rule(f: Finding) -> dict:
    return {
        "id": f.rule_id,
        "name": f.rule_id,
        "shortDescription": {"text": f.title},
        "help": {"text": f.fix},
        "properties": {"review": f.review, **({"owasp": f.owasp} if f.owasp else {})},
    }


def _location(file: str, line: int) -> dict:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": file},
            "region": {"startLine": max(line, 1)},
        }
    }


def _result(f: Finding, rule_index: int) -> dict:
    text = f.title if not f.detail else f"{f.title}. {f.detail}"
    result = {
        "ruleId": f.rule_id,
        "ruleIndex": rule_index,
        "level": LEVELS[f.severity.value],
        "message": {"text": text},
        "properties": _properties(f),
    }
    if f.locations:
        result["locations"] = [_location(loc.file, loc.line) for loc in f.locations]
    return result


def render_sarif(report: Report) -> str:
    from dpr import __version__

    rules: list[dict] = []
    index: dict[str, int] = {}
    results = []
    for f in report.findings:
        if f.rule_id not in index:
            index[f.rule_id] = len(rules)
            rules.append(_rule(f))
        results.append(_result(f, index[f.rule_id]))
    data = {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "dpr",
                        "version": __version__,
                        "informationUri": "https://example.invalid/dpr",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"
```

Modify `src/dpr/__init__.py`, replace:

```python
from dpr.report.markdown import render_markdown

__version__ = "0.1.0"
__all__ = ["__version__", "discover", "render_json", "render_markdown", "review"]
```

with:

```python
from dpr.report.markdown import render_markdown
from dpr.report.sarif import render_sarif

__version__ = "0.1.0"
__all__ = ["__version__", "discover", "render_json", "render_markdown", "render_sarif", "review"]
```

Modify `src/dpr/cli.py`, replace:

```python
from dpr.report.markdown import render_markdown
from dpr.reviews import REVIEWS

FORMATS = ("md", "json")
```

with:

```python
from dpr.report.markdown import render_markdown
from dpr.report.sarif import render_sarif
from dpr.reviews import REVIEWS

FORMATS = ("md", "json", "sarif")
```

Modify `src/dpr/cli.py`, replace:

```python
    scan.add_argument("--format", default="md,json", help="comma separated: md, json")
```

with:

```python
    scan.add_argument("--format", default="md,json", help="comma separated: md, json, sarif")
```

Modify `src/dpr/cli.py`, replace:

```python
        written[-1].write_text(render_json(report), encoding="utf-8")
```

with:

```python
        written[-1].write_text(render_json(report), encoding="utf-8")
    if "sarif" in formats:
        written.append(out_dir / f"report-{report.meta.date}.sarif")
        written[-1].write_text(render_sarif(report), encoding="utf-8")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest -q`
Expected: PASS (all tests, including 3 new ones)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/report/sarif.py src/dpr/__init__.py src/dpr/cli.py tests/report/test_sarif.py tests/test_cli_sarif.py tests/test_cli.py
git commit -m "Add SARIF 2.1.0 output to the API and the scan command"
```

---
### Task 33: Route access classification

Every A01 rule and every abuse rule asks the same two questions about a route: does it require a signed-in caller, and which names in the handler hold that caller. This task answers both once per route and caches the answer. It also teaches the FastAPI and Flask route extractor to prepend `APIRouter(prefix=...)` and `Blueprint(url_prefix=...)`, so route paths in the report read `/auth/register` rather than `/register`.

**Files:**
- Create: `src/dpr/reviews/access.py`
- Modify: `src/dpr/parsing/routes_py.py` (router prefixes)
- Test: `tests/reviews/test_access.py`, `tests/parsing/test_routes_prefix.py`

**Interfaces:**
- Consumes: `Route` (Task 2), `Context` (Task 4), `jsts` (Task 7), `pyast` (Task 8), `detect` (Task 16)
- Produces (in `dpr.reviews.access`):
  - `PUBLIC`, `AUTHENTICATED`, `ADMIN` level strings
  - `Access(level: str, subjects: tuple[str, ...] = (), evidence: str = "")` frozen dataclass; `subjects` are expressions that name the caller inside the handler (`current_user`, `session`, `request.user`, `req.user`)
  - `access(ctx: Context, route: Route) -> Access`, cached in `ctx.facts["access"]`
  - `path_params(route: Route) -> list[str]` for `{id}`, `<int:id>`, `(?P<id>...)`, `:id` and `*rest` segments
  - `fastapi_aliases(ctx) -> dict[str, str]`: `Annotated[..., Depends(fn)]` alias name to dependency function name, cached in `ctx.index.cache`
- Decisions, per framework:
  - FastAPI: a parameter annotation or default with `Depends(fn)` or `Security(fn)`, directly or through an `Annotated` alias, a decorator `dependencies=[...]`, or `APIRouter(dependencies=[...])` in the same file. A dependency name that mentions `admin` or `superuser` and no other role word than `staff` is admin (`get_admin_user`, `get_staff_or_admin_user`); a name with another role word (`get_manager_or_admin_user`, `AgentOrAbove`) or an auth word (`user`, `auth`, `session`, `token`, `current`, `verify`, `require` and similar) is authenticated. Subjects are the parameter names.
  - Flask: `login_required`, `jwt_required`, `roles_required` and similar decorators; admin when the decorator text names admin.
  - Django and DRF: `login_required`, `permission_required`, `user_passes_test`, `staff_member_required` (admin), `permission_classes` (`IsAdminUser` admin, `AllowAny` public), login mixins, and a settings `DEFAULT_PERMISSION_CLASSES` with `IsAuthenticated` for DRF routes.
  - Next.js: an auth call in the handler (`auth()`, `getServerSession()`, `supabase.auth.getUser()` and similar), admin when the handler also checks an admin role; otherwise a root `middleware.ts` that calls auth and whose `matcher` covers the path.
  - Express and Fastify: middleware arguments between the path and the handler, or an earlier `router.use(...)` in the same file, whose names carry an auth or admin word.

- [ ] **Step 1: Write the failing tests**

`tests/reviews/test_access.py`:

```python
from dpr import rules
from dpr.discovery.detect import detect
from dpr.reviews.access import access, path_params
from dpr.walk import RepoIndex
from tests.reviews.helpers import write


def classify(root):
    index = RepoIndex(root)
    ctx = rules.Context(index=index, detection=detect(index))
    return {(r.method, r.path): access(ctx, r) for r in ctx.detection.routes}


def test_fastapi_aliases_router_dependencies_and_admin(tmp_path):
    write(
        tmp_path,
        "app/deps.py",
        "from typing import Annotated\nfrom fastapi import Depends\n"
        "CurrentUser = Annotated[dict, Depends(get_current_user)]\n"
        "AdminUser = Annotated[dict, Depends(get_admin_user)]\n"
        "ManagerOrAdmin = Annotated[dict, Depends(get_manager_or_admin_user)]\n"
        "StaffOrAdmin = Annotated[dict, Depends(get_staff_or_admin_user)]\n",
    )
    write(
        tmp_path,
        "app/items.py",
        "from fastapi import APIRouter, Depends\nfrom app.deps import AdminUser, CurrentUser, ManagerOrAdmin\n"
        "router = APIRouter()\n"
        "@router.get('/items/{item_id}')\nasync def one(item_id: str, me: CurrentUser): ...\n"
        "@router.delete('/items/{item_id}')\nasync def drop(item_id: str, boss: AdminUser): ...\n"
        "@router.put('/items/{item_id}')\nasync def edit(item_id: str, who: ManagerOrAdmin): ...\n"
        "@router.patch('/items/{item_id}')\nasync def tune(item_id: str, who: StaffOrAdmin): ...\n"
        "@router.post('/login')\nasync def login(db=Depends(get_db)): ...\n"
        "@router.get('/me', dependencies=[Depends(verify_token)])\nasync def me(): ...\n"
        "@router.get('/old')\nasync def old(user=Depends(get_current_user)): ...\n",
    )
    write(
        tmp_path,
        "app/secure.py",
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter(dependencies=[Depends(require_auth)])\n"
        "@router.get('/reports')\nasync def reports(): ...\n",
    )
    found = classify(tmp_path)
    assert found[("GET", "/items/{item_id}")].level == "authenticated"
    assert found[("GET", "/items/{item_id}")].subjects == ("me",)
    assert found[("DELETE", "/items/{item_id}")].level == "admin"
    assert found[("PUT", "/items/{item_id}")].level == "authenticated"
    assert found[("PATCH", "/items/{item_id}")].level == "admin"
    assert found[("POST", "/login")].level == "public"
    assert found[("GET", "/me")].level == "authenticated"
    assert found[("GET", "/old")].subjects == ("user",)
    assert found[("GET", "/reports")].evidence == "Depends(require_auth)"


def test_flask_and_django(tmp_path):
    write(
        tmp_path,
        "web/app.py",
        "from flask import Flask\nfrom flask_login import login_required\napp = Flask(__name__)\n"
        "@app.route('/notes/<int:note_id>')\n@login_required\ndef note(note_id): ...\n"
        "@app.route('/admin/users')\n@roles_required('admin')\ndef users(): ...\n"
        "@app.route('/contact', methods=['POST'])\ndef contact(): ...\n",
    )
    write(
        tmp_path,
        "shop/urls.py",
        "from django.urls import path\nfrom . import views\nurlpatterns = [\n"
        "    path('invoices/<int:pk>/', views.invoice),\n    path('open/', views.open_view),\n"
        "    path('staff/', views.staff),\n    path('api/', views.InvoiceApi.as_view()),\n]\n",
    )
    write(
        tmp_path,
        "shop/views.py",
        "from django.contrib.auth.decorators import login_required\n"
        "@login_required\ndef invoice(request, pk): ...\n"
        "def open_view(request): ...\n"
        "@staff_member_required\ndef staff(request): ...\n"
        "class InvoiceApi(APIView):\n    permission_classes = [IsAuthenticated]\n",
    )
    found = classify(tmp_path)
    assert found[("GET", "/notes/<int:note_id>")].level == "authenticated"
    assert found[("GET", "/admin/users")].level == "admin"
    assert found[("POST", "/contact")].level == "public"
    assert found[("ANY", "/invoices/<int:pk>")].subjects == ("request.user", "self.request.user")
    assert found[("ANY", "/open")].level == "public"
    assert found[("ANY", "/staff")].level == "admin"
    assert found[("ANY", "/api")].level == "authenticated"


def test_next_handlers_and_middleware(tmp_path):
    write(
        tmp_path,
        "app/api/invoices/[id]/route.ts",
        "export async function GET(req: Request, { params }: any) {\n"
        "  const session = await auth()\n  return Response.json({})\n}\n"
        "export async function DELETE(req: Request) {\n  return Response.json({})\n}\n",
    )
    write(
        tmp_path,
        "app/api/admin/stats/route.ts",
        "export async function GET() {\n  const { data: { user } } = await supabase.auth.getUser()\n"
        "  if (user.role !== 'admin') return new Response(null, { status: 403 })\n}\n",
    )
    write(
        tmp_path,
        "app/api/account/route.ts",
        "export async function POST() {\n  return Response.json({})\n}\n",
    )
    write(
        tmp_path,
        "middleware.ts",
        "export default auth\nexport const config = { matcher: ['/api/account/:path*'] }\n",
    )
    found = classify(tmp_path)
    assert found[("GET", "/api/invoices/:id")].subjects == ("session",)
    assert found[("DELETE", "/api/invoices/:id")].level == "public"
    assert found[("GET", "/api/admin/stats")].level == "admin"
    assert found[("GET", "/api/admin/stats")].subjects == ("user",)
    assert found[("POST", "/api/account")].evidence == "middleware matcher"


def test_express_route_and_use_middleware(tmp_path):
    write(
        tmp_path,
        "server/routes.js",
        "const router = require('express').Router()\n"
        "router.get('/public', (req, res) => res.send('ok'))\n"
        "router.get('/orders/:orderId', requireAuth, (req, res) => res.send('ok'))\n"
        "router.use(authenticate)\n"
        "router.delete('/orders/:orderId', isAdmin, (req, res) => res.send('ok'))\n"
        "router.post('/orders', (req, res) => res.send('ok'))\n",
    )
    found = classify(tmp_path)
    assert found[("GET", "/public")].level == "public"
    assert found[("GET", "/orders/:orderId")].level == "authenticated"
    assert found[("DELETE", "/orders/:orderId")].level == "admin"
    assert found[("POST", "/orders")].level == "authenticated"
    assert found[("POST", "/orders")].subjects[0] == "req.user"


def test_path_params():
    from dpr.model import Route

    def params(path):
        return path_params(Route("GET", path, "a", 1, "x"))

    assert params("/items/{item_id}/files/{name:path}") == ["item_id", "name"]
    assert params("/invoices/<int:pk>/<slug>") == ["pk", "slug"]
    assert params("/orders/:orderId/lines/*rest") == ["orderId", "rest"]
    assert params("/plain") == []
```

`tests/parsing/test_routes_prefix.py`:

```python
from dpr.parsing.routes_py import decorator_routes
from dpr.walk import RepoIndex
from tests.reviews.helpers import write


def test_router_and_blueprint_prefixes(tmp_path):
    write(
        tmp_path,
        "api/auth.py",
        "from fastapi import APIRouter\nrouter = APIRouter(prefix='/auth/', tags=['a'])\n"
        "other = APIRouter()\n"
        "@router.post('/register')\nasync def register(): ...\n"
        "@other.get('/health')\nasync def health(): ...\n",
    )
    write(
        tmp_path,
        "web/views.py",
        "from flask import Blueprint\nbp = Blueprint('notes', __name__, url_prefix='/notes')\n"
        "@bp.route('/<int:note_id>')\ndef note(note_id): ...\n",
    )
    paths = sorted(r.path for r in decorator_routes(RepoIndex(tmp_path)))
    assert paths == ["/auth/register", "/health", "/notes/<int:note_id>"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/reviews/test_access.py tests/parsing/test_routes_prefix.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'dpr.reviews.access'` during collection

- [ ] **Step 3: Write the classifier and the prefix support**

`src/dpr/reviews/access.py`:

```python
"""Route access: public, authenticated or admin, and the names that hold the caller."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from dpr.model import Route
from dpr.parsing import jsts, pyast
from dpr.rules import Context

PUBLIC, AUTHENTICATED, ADMIN = "public", "authenticated", "admin"
AUTH_WORD = re.compile(
    r"(?i)user|auth|login|session|token|principal|identity|staff|agent|member|account|verify"
    r"|require|current|jwt|bearer|api_?key|oauth|protect|ensure|logged|passport"
)
ADMIN_WORD = re.compile(r"(?i)admin|superuser|super_user")
PY_DEP = re.compile(r"(?:\w+\.)*(?:Depends|Security)")
FLASK_DECORATORS = re.compile(
    r"(?:\w+\.)*(login_required|jwt_required|fresh_jwt_required|auth_required|token_required"
    r"|requires_auth|roles_required|roles_accepted|admin_required|permission_required)"
)
DJANGO_DECORATORS = re.compile(
    r"(?:\w+\.)*(login_required|permission_required|user_passes_test|staff_member_required"
    r"|superuser_required)"
)
DJANGO_MIXINS = re.compile(r"(LoginRequired|PermissionRequired|UserPassesTest)Mixin")
JS_AUTH_CALL = re.compile(
    r"\b(auth|getServerSession|getSession|currentUser|getAuth|requireAuth|requireUser"
    r"|getCurrentUser|verifyToken|getToken|validateRequest|getKindeServerSession|getUser"
    r"|withAuth)\s*\("
)
JS_ADMIN_CHECK = re.compile(r"""isAdmin|role\s*[!=]==?\s*['"]admin['"]|['"]admin['"]\s*[!=]==?""")
EXPRESS_SUBJECTS = ("req.user", "req.auth", "req.session", "request.user")
DJANGO_SUBJECTS = ("request.user", "self.request.user")
FLASK_SUBJECTS = ("current_user", "g.user", "get_jwt_identity")


@dataclass(frozen=True)
class Access:
    level: str
    subjects: tuple[str, ...] = ()
    evidence: str = ""


def _dep_level(name: str) -> str | None:
    roles = set(
        re.findall(
            r"admin|superuser|staff|manager|agent|member|client|customer|editor"
            r"|viewer|owner|above|any",
            name.lower(),
        )
    )
    if roles and roles <= {"admin", "superuser", "staff"} and ADMIN_WORD.search(name):
        return ADMIN
    if AUTH_WORD.search(name) or ADMIN_WORD.search(name):
        return AUTHENTICATED
    return None


def _strongest(levels: list[str]) -> str:
    if ADMIN in levels:
        return ADMIN
    return AUTHENTICATED if AUTHENTICATED in levels else PUBLIC


def _dep_names(node: ast.AST | None, aliases: dict[str, str]) -> list[str]:
    names = []
    for sub in ast.walk(node) if node is not None else []:
        if isinstance(sub, ast.Call) and PY_DEP.fullmatch(pyast.dotted(sub.func) or ""):
            if sub.args:
                names.append((pyast.dotted(sub.args[0]) or "").split(".")[-1])
        elif isinstance(sub, ast.Name) and sub.id in aliases:
            names.append(aliases[sub.id])
    return [n for n in names if n]


def fastapi_aliases(ctx: Context) -> dict[str, str]:
    key = ("fastapi-aliases", "")
    if key in ctx.index.cache:
        return ctx.index.cache[key]
    aliases: dict[str, str] = {}
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if "Annotated" not in text or "Depends" not in text and "Security" not in text:
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for name, value in pyast.assignments(tree.body if tree else []).items():
            if isinstance(value, ast.Subscript) and pyast.dotted(value.value) in (
                "Annotated",
                "typing.Annotated",
            ):
                found = _dep_names(value.slice, {})
                if found:
                    aliases[name] = found[0]
    ctx.index.cache[key] = aliases
    return aliases


def _router_deps(tree: ast.Module, aliases: dict[str, str]) -> list[str]:
    names = []
    for value in pyast.assignments(tree.body).values():
        if isinstance(value, ast.Call) and re.fullmatch(
            r"(?:\w+\.)?(APIRouter|FastAPI)", pyast.dotted(value.func) or ""
        ):
            names += _dep_names(pyast.kwarg(value, "dependencies"), aliases)
    return names


def _fastapi(ctx: Context, route: Route) -> Access:
    aliases = fastapi_aliases(ctx)
    fn = route.handler
    levels: list[tuple[str, str]] = []
    subjects = []
    params = [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
    defaults = [None] * (len(fn.args.posonlyargs) + len(fn.args.args) - len(fn.args.defaults))
    defaults += [*fn.args.defaults, *fn.args.kw_defaults]
    for param, default in zip(params, defaults, strict=True):
        for name in _dep_names(param.annotation, aliases) + _dep_names(default, aliases):
            level = _dep_level(name)
            if level:
                levels.append((level, name))
                subjects.append(param.arg)
    for dec in fn.decorator_list:
        if isinstance(dec, ast.Call):
            for name in _dep_names(pyast.kwarg(dec, "dependencies"), aliases):
                if _dep_level(name):
                    levels.append((_dep_level(name), name))
    for name in _router_deps(route.tree, aliases):
        if _dep_level(name):
            levels.append((_dep_level(name), name))
    if not levels:
        return Access(PUBLIC, (), "no authentication dependency")
    level = _strongest([lv for lv, _ in levels])
    names = ", ".join(dict.fromkeys(name for _, name in levels))
    return Access(level, tuple(dict.fromkeys(subjects)), f"Depends({names})")


def _decorator_names(node: ast.AST) -> list[tuple[str, ast.AST]]:
    found = []
    for dec in getattr(node, "decorator_list", []):
        target = dec.func if isinstance(dec, ast.Call) else dec
        found.append(((pyast.dotted(target) or ""), dec))
    return found


def _flask(route: Route) -> Access:
    for name, dec in _decorator_names(route.handler):
        match = FLASK_DECORATORS.fullmatch(name)
        if not match:
            continue
        text = ast.unparse(dec)
        admin = "admin" in text.lower()
        return Access(ADMIN if admin else AUTHENTICATED, FLASK_SUBJECTS, f"@{match.group(1)}")
    return Access(PUBLIC, (), "no login decorator")


def _drf_default(ctx: Context) -> bool:
    key = ("drf-default-auth", "")
    if key not in ctx.index.cache:
        ctx.index.cache[key] = any(
            "DEFAULT_PERMISSION_CLASSES" in ctx.index.text(f.rel)
            and "IsAuthenticated" in ctx.index.text(f.rel)
            for f in ctx.index.named("settings.py", "base.py", "production.py")
        )
    return ctx.index.cache[key]


def _django(ctx: Context, route: Route) -> Access:
    node = route.handler
    if node is None:
        return Access(PUBLIC, (), "view not resolved")
    for name, dec in _decorator_names(node):
        match = DJANGO_DECORATORS.fullmatch(name)
        if match:
            admin = match.group(1) in ("staff_member_required", "superuser_required")
            return Access(ADMIN if admin else AUTHENTICATED, DJANGO_SUBJECTS, f"@{match.group(1)}")
        if name.endswith("permission_classes"):
            text = ast.unparse(dec)
            if "IsAdminUser" in text:
                return Access(ADMIN, DJANGO_SUBJECTS, "IsAdminUser")
            if "AllowAny" in text:
                return Access(PUBLIC, (), "AllowAny")
            return Access(AUTHENTICATED, DJANGO_SUBJECTS, "permission_classes")
    if isinstance(node, ast.ClassDef):
        if any(DJANGO_MIXINS.search(b) for b in pyast.base_names(node)):
            return Access(AUTHENTICATED, DJANGO_SUBJECTS, "login mixin")
        value = pyast.assignments(node.body).get("permission_classes")
        if value is not None:
            text = ast.unparse(value)
            if "IsAdminUser" in text:
                return Access(ADMIN, DJANGO_SUBJECTS, "IsAdminUser")
            if "AllowAny" not in text:
                return Access(AUTHENTICATED, DJANGO_SUBJECTS, "permission_classes")
            return Access(PUBLIC, (), "AllowAny")
    if route.framework == "drf" and _drf_default(ctx):
        return Access(AUTHENTICATED, DJANGO_SUBJECTS, "DEFAULT_PERMISSION_CLASSES")
    return Access(PUBLIC, (), "no login decorator or permission class")


def _js_subjects(handler) -> tuple[str, ...]:
    names = []
    for decl in jsts.walk(handler, {"variable_declarator"}):
        value = jsts.node_text(decl.child_by_field_name("value"))
        if not JS_AUTH_CALL.search(value) and "auth.getUser" not in value:
            continue
        target = decl.child_by_field_name("name")
        if target is not None and target.type == "identifier":
            names.append(jsts.node_text(target))
        elif target is not None:
            for ident in jsts.walk(target, {"shorthand_property_identifier_pattern", "identifier"}):
                names.append(jsts.node_text(ident))
    return tuple(dict.fromkeys(names))


def _matcher_covers(text: str, path: str) -> bool:
    patterns = re.findall(r"""['"](/[^'"]*)['"]""", text[text.find("matcher") :])
    if "matcher" not in text or not patterns:
        return True
    for pattern in patterns:
        prefix = re.split(r"[:(\[*]", pattern, maxsplit=1)[0].rstrip("/")
        if "(?!" in pattern or not prefix or path == prefix or path.startswith(prefix + "/"):
            return True
    return False


def _next_middleware(ctx: Context, path: str) -> bool:
    for entry in ctx.index.named("middleware.ts", "middleware.js"):
        if entry.rel not in (
            "middleware.ts",
            "middleware.js",
            "src/middleware.ts",
            "src/middleware.js",
        ):
            continue
        text = ctx.index.text(entry.rel)
        if re.search(r"auth|clerkMiddleware|withAuth|getToken|updateSession|session", text):
            if _matcher_covers(text, path):
                return True
    return False


def _next(ctx: Context, route: Route) -> Access:
    handler = route.handler
    text = jsts.node_text(handler) if handler is not None else ""
    if JS_AUTH_CALL.search(text) or "auth.getUser" in text:
        level = ADMIN if JS_ADMIN_CHECK.search(text) else AUTHENTICATED
        return Access(level, _js_subjects(handler), "auth call in handler")
    if _next_middleware(ctx, route.path):
        return Access(AUTHENTICATED, (), "middleware matcher")
    return Access(PUBLIC, (), "no auth call and no middleware matcher")


def _express(route: Route) -> Access:
    tree = route.tree
    names: list[str] = []
    for call in jsts.calls(tree, r"(?:\w+\.)*(?:get|post|put|patch|delete|all|use)"):
        if jsts.line(tree, call) > route.line:
            continue
        args = jsts.arguments(call)
        is_route = jsts.line(tree, call) == route.line
        middle = args[1:-1] if is_route else args
        if not is_route and not jsts.callee(call).endswith(".use"):
            continue
        names += [jsts.node_text(a) for a in middle if a.type != "string"]
    auth = [n for n in names if AUTH_WORD.search(n) or ADMIN_WORD.search(n)]
    if not auth:
        return Access(PUBLIC, (), "no auth middleware")
    admin = any(ADMIN_WORD.search(n) or "role" in n.lower() for n in auth)
    return Access(ADMIN if admin else AUTHENTICATED, EXPRESS_SUBJECTS, ", ".join(auth[:3]))


def _classify(ctx: Context, route: Route) -> Access:
    if route.framework == "fastapi" and isinstance(route.handler, ast.AST):
        return _fastapi(ctx, route)
    if route.framework == "flask" and isinstance(route.handler, ast.AST):
        return _flask(route)
    if route.framework in ("django", "drf"):
        return _django(ctx, route)
    if route.framework.startswith("next"):
        return _next(ctx, route)
    if route.framework in ("express", "fastify") and route.tree is not None:
        return _express(route)
    return Access(PUBLIC, (), "framework not classified")


def access(ctx: Context, route: Route) -> Access:
    cache = ctx.facts.setdefault("access", {})
    if route not in cache:
        cache[route] = _classify(ctx, route)
    return cache[route]


def path_params(route: Route) -> list[str]:
    path = route.path
    found = re.findall(r"\{(\w+)(?::[^}]*)?\}", path)
    found += re.findall(r"<(?:\w+:)?(\w+)>", path)
    found += re.findall(r"\(\?P<(\w+)>", path)
    found += re.findall(r"(?:^|/):(\w+)", path)
    found += re.findall(r"(?:^|/)\*(\w+)", path)
    return list(dict.fromkeys(found))
```

Modify `src/dpr/parsing/routes_py.py`, replace:

```python
def decorator_routes(index: RepoIndex) -> list[Route]:
```

with:

```python
def _router_prefixes(tree: ast.Module) -> dict[str, str]:
    found = {}
    for name, value in pyast.assignments(tree.body).items():
        if not isinstance(value, ast.Call):
            continue
        kind = (pyast.dotted(value.func) or "").split(".")[-1]
        keyword = {"APIRouter": "prefix", "Blueprint": "url_prefix"}.get(kind)
        prefix = pyast.constant(pyast.kwarg(value, keyword), None) if keyword else None
        if isinstance(prefix, str):
            found[name] = prefix.rstrip("/")
    return found


def decorator_routes(index: RepoIndex) -> list[Route]:
```

Modify `src/dpr/parsing/routes_py.py`, replace:

```python
        for fn in pyast.functions(tree):
            for dec in fn.decorator_list:
```

with:

```python
        prefixes = _router_prefixes(tree)
        for fn in pyast.functions(tree):
            for dec in fn.decorator_list:
```

Modify `src/dpr/parsing/routes_py.py`, replace:

```python
                for method in methods:
                    routes.append(
                        Route(method, path, entry.rel, fn.lineno, framework, handler=fn, tree=tree)
                    )
```

with:

```python
                full = prefixes.get(pyast.dotted(dec.func.value) or "", "") + path
                for method in methods:
                    routes.append(
                        Route(method, full, entry.rel, fn.lineno, framework, handler=fn, tree=tree)
                    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest -q`
Expected: PASS (all tests, including 6 new ones)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/reviews/access.py src/dpr/parsing/routes_py.py tests/reviews/test_access.py tests/parsing/test_routes_prefix.py
git commit -m "Classify route access per framework and read router prefixes"
```

---
### Task 34: Baseline cookie flags, debug mode, weak hashing and mixed content

**Files:**
- Create: `src/dpr/reviews/baseline_config.py`, `src/dpr/data/rule_text/baseline_config.yaml`
- Modify: `src/dpr/reviews/baseline.py` (import the rule module)
- Test: `tests/reviews/test_baseline_config.py`

**Interfaces:**
- Consumes: `Location`, `Tag` (Task 2); `rule`, `make_finding`, `Context` (Task 4); `line_of` (Task 5); `snippet` (Task 6); `jsts` (Task 7); `pyast` (Task 8); `findings_for`, `write` (Task 19)
- Produces:
  - Registered rules (review `baseline`): `BASE-COOKIE-HTTPONLY`, `BASE-COOKIE-SECURE`, `BASE-COOKIE-SAMESITE` (owasp A05), `BASE-DEBUG-ON` (A05), `BASE-WEAK-HASH` (A02), `BASE-MIXED-CONTENT` (A02)
  - `ctx.facts["cookie_findings"]`: every cookie finding from one parse, shared by the three cookie rules
- Rules:
  - Cookie flags come from `cookies().set`, `response.cookies.set`, `res.cookie`, `Set-Cookie` header literals, Python `*.set_cookie(...)` and Django `SESSION_COOKIE_*` / `CSRF_COOKIE_*` settings. A missing `httpOnly` or `secure` counts as off. A missing SameSite counts as not set, except for Starlette and FastAPI whose default is `lax`. A spread options object, `**kwargs`, or a non-literal flag value is skipped rather than guessed. Severity is high when the cookie name looks like a session (`sid`, `session`, `token`, `auth`, `jwt`), otherwise low; a missing SameSite is always low.
  - `BASE-DEBUG-ON` (INFERRED, high): Django settings `DEBUG = True`, `FastAPI(debug=True)`, `Flask(...)` or `app.run(debug=True)`, and a `*Settings` class whose `debug` field defaults to `True`.
  - `BASE-WEAK-HASH` (critical): `hashlib.md5/sha1/sha224/sha256` or `crypto.createHash('md5'|'sha1'|'sha256')` where the call or the enclosing function name mentions a password (INFERRED); Django `PASSWORD_HASHERS` whose first entry is an MD5 or SHA1 hasher (CONFIRMED).
  - `BASE-MIXED-CONTENT` (INFERRED, low): `src` or `href` starting with `http://` in markup files, except localhost and `www.w3.org`; one finding per file with up to five locations.

- [ ] **Step 1: Write the failing tests**

`tests/reviews/test_baseline_config.py`:

```python
from tests.reviews.helpers import findings_for, write


def locs(found):
    return sorted((str(f.locations[0]), f.severity.value) for f in found)


def test_js_cookie_flags(tmp_path):
    write(
        tmp_path,
        "app/api/login/route.ts",
        "import { cookies } from 'next/headers'\n"
        "export async function POST() {\n"
        "  cookies().set('session', 'x', { path: '/' })\n"
        "  cookies().set('theme', 'dark', { httpOnly: true, secure: true, sameSite: 'lax' })\n"
        "  cookies().set({ name: 'token', value: 'y', httpOnly: true, secure: true, sameSite: 'none' })\n"
        "  cookies().set('flag', 'z', { ...defaults })\n"
        "}\n",
    )
    write(
        tmp_path,
        "server/app.js",
        "app.post('/x', (req, res) => {\n"
        "  res.cookie('sid', 'v', { httpOnly: true, secure: process.env.PROD === '1', sameSite: 'strict' })\n"
        "  res.setHeader('Set-Cookie', 'auth=abc; Path=/; Secure; SameSite=Lax')\n"
        "})\n",
    )
    assert locs(findings_for(tmp_path, "baseline", "BASE-COOKIE-HTTPONLY")) == [
        ("app/api/login/route.ts:3", "high"),
        ("server/app.js:3", "high"),
    ]
    assert locs(findings_for(tmp_path, "baseline", "BASE-COOKIE-SECURE")) == [
        ("app/api/login/route.ts:3", "high"),
    ]
    assert locs(findings_for(tmp_path, "baseline", "BASE-COOKIE-SAMESITE")) == [
        ("app/api/login/route.ts:3", "low"),
        ("app/api/login/route.ts:5", "high"),
    ]


def test_python_cookie_flags_and_django_settings(tmp_path):
    write(
        tmp_path,
        "api/auth.py",
        "from fastapi import Response\n"
        "def login(response: Response):\n"
        "    response.set_cookie('access_token', 't', httponly=True, secure=True)\n"
        "    response.set_cookie('prefs', 'p')\n"
        "    response.set_cookie(**cookie_settings())\n"
        "    response.set_cookie('refresh_token', 'r', httponly=True, secure=settings.secure, samesite='none')\n",
    )
    write(
        tmp_path,
        "site/settings.py",
        "INSTALLED_APPS = []\nSESSION_COOKIE_SECURE = False\nSESSION_COOKIE_HTTPONLY = True\n"
        "CSRF_COOKIE_SAMESITE = 'None'\n",
    )
    assert locs(findings_for(tmp_path, "baseline", "BASE-COOKIE-HTTPONLY")) == [
        ("api/auth.py:4", "low")
    ]
    assert locs(findings_for(tmp_path, "baseline", "BASE-COOKIE-SECURE")) == [
        ("api/auth.py:4", "low"),
        ("site/settings.py:2", "high"),
    ]
    assert locs(findings_for(tmp_path, "baseline", "BASE-COOKIE-SAMESITE")) == [
        ("api/auth.py:6", "high"),
        ("site/settings.py:4", "low"),
    ]


def test_debug_on(tmp_path):
    write(tmp_path, "proj/settings.py", "INSTALLED_APPS = []\nDEBUG = True\n")
    write(tmp_path, "other/settings.py", "INSTALLED_APPS = []\nDEBUG = env.bool('DEBUG', False)\n")
    write(tmp_path, "api/main.py", "from fastapi import FastAPI\napp = FastAPI(debug=True)\n")
    write(
        tmp_path,
        "api/config.py",
        "from pydantic_settings import BaseSettings\n"
        "class Settings(BaseSettings):\n    debug: bool = True\n    name: str = 'x'\n"
        "class Other(BaseSettings):\n    debug: bool = False\n",
    )
    write(tmp_path, "notes.py", "DEBUG = True\n")
    found = findings_for(tmp_path, "baseline", "BASE-DEBUG-ON")
    assert sorted(str(f.locations[0]) for f in found) == [
        "api/config.py:3",
        "api/main.py:2",
        "proj/settings.py:2",
    ]
    assert {f.tag.value for f in found} == {"INFERRED"}


def test_weak_hash(tmp_path):
    write(
        tmp_path,
        "accounts/hashing.py",
        "import hashlib\n"
        "def hash_password(raw):\n    return hashlib.md5(raw.encode()).hexdigest()\n"
        "def etag(body):\n    return hashlib.sha256(body).hexdigest()\n"
        "digest = hashlib.sha1(password.encode())\n",
    )
    write(
        tmp_path,
        "site/settings.py",
        "PASSWORD_HASHERS = [\n    'django.contrib.auth.hashers.MD5PasswordHasher',\n"
        "    'django.contrib.auth.hashers.PBKDF2PasswordHasher',\n]\n",
    )
    write(
        tmp_path,
        "safe/settings.py",
        "PASSWORD_HASHERS = ['django.contrib.auth.hashers.Argon2PasswordHasher', 'x.MD5PasswordHasher']\n",
    )
    write(
        tmp_path,
        "lib/users.js",
        "const crypto = require('crypto')\n"
        "function savePassword(pw) { return crypto.createHash('sha1').update(pw).digest('hex') }\n"
        "const fileId = crypto.createHash('md5').update(buffer).digest('hex')\n",
    )
    found = findings_for(tmp_path, "baseline", "BASE-WEAK-HASH")
    assert sorted((str(f.locations[0]), f.tag.value) for f in found) == [
        ("accounts/hashing.py:3", "INFERRED"),
        ("accounts/hashing.py:6", "INFERRED"),
        ("lib/users.js:2", "INFERRED"),
        ("site/settings.py:2", "CONFIRMED"),
    ]
    assert found[0].severity.value == "critical"


def test_mixed_content(tmp_path):
    write(
        tmp_path,
        "public/index.html",
        '<html xmlns="http://www.w3.org/1999/xhtml">\n'
        '<script src="http://cdn.example.com/a.js"></script>\n'
        '<link href="https://fonts.example.com/b.css">\n'
        '<img src="http://localhost:3000/x.png">\n',
    )
    write(
        tmp_path,
        "src/Logo.tsx",
        'export const Logo = () => <img src="https://cdn.example.com/l.png" />\n',
    )
    [f] = findings_for(tmp_path, "baseline", "BASE-MIXED-CONTENT")
    assert [str(loc) for loc in f.locations] == ["public/index.html:2"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/reviews/test_baseline_config.py -q`
Expected: FAIL in all 5 tests (no baseline rules are registered yet, so each comparison or unpacking meets an empty result)

- [ ] **Step 3: Write the rule text and the rules**

`src/dpr/data/rule_text/baseline_config.yaml`:

```yaml
BASE-COOKIE-HTTPONLY:
  title: Cookie ${name} is readable by page scripts
  effort_minutes: 2
  detail: The HttpOnly flag is ${now} where ${name} is set, so any script running on the page can read the cookie.
  attack: Find one cross-site scripting bug, read document.cookie, and replay the value from another browser.
  blast: The account behind the cookie, when it carries a session.
  fix: Set httpOnly true (httponly=True in Python, SESSION_COOKIE_HTTPONLY = True in Django) where the cookie is set.
  verify: Log in, then run document.cookie in the browser console and confirm the cookie is not listed.
BASE-COOKIE-SECURE:
  title: Cookie ${name} can travel over plain HTTP
  effort_minutes: 2
  detail: The Secure flag is ${now} where ${name} is set, so the browser also sends it over unencrypted connections.
  attack: On a shared or hostile network, trigger one plain HTTP request to the site and read the cookie from the traffic.
  blast: The account behind the cookie, when it carries a session.
  fix: Set secure true (secure=True in Python, SESSION_COOKIE_SECURE = True and CSRF_COOKIE_SECURE = True in Django) for every deployed environment.
  verify: curl -sSI against the login response and confirm the Set-Cookie line includes Secure.
BASE-COOKIE-SAMESITE:
  title: Cookie ${name} has a weak SameSite setting
  effort_minutes: 2
  detail: SameSite is ${now} where ${name} is set, so other sites can make the browser send it with their requests.
  attack: Host a page that submits a form or request to this site; the browser attaches the cookie and the action runs as the signed-in user.
  blast: Every state-changing action the cookie authorises.
  fix: Set sameSite to lax (strict for cookies only used on this site). If None is required for a cross-site frontend, pair it with a CSRF token or an Origin check on every state-changing route.
  verify: curl -sSI against the response that sets the cookie and confirm SameSite=Lax or Strict.
BASE-DEBUG-ON:
  title: Debug mode may be on in production
  effort_minutes: 5
  detail: ${what}
  proof_needed: Check the value the production environment actually sets for debug.
  attack: Trigger an error and read the debug page, stack trace, settings and SQL it shows.
  blast: Source paths, settings, environment details and sometimes secrets shown on error pages.
  fix: Default debug to False in code and turn it on only through a local environment variable.
  verify: Request a URL that raises an error on the deployed site and confirm a generic error page.
BASE-WEAK-HASH:
  title: Passwords hashed with ${algorithm}
  effort_minutes: 60
  detail: ${algorithm} is a fast general-purpose hash. A stolen table of these hashes can be cracked at billions of guesses per second.
  proof_needed: Confirm this hash is used to store or compare user passwords.
  attack: Take a database dump or backup and crack the hashes offline with a GPU.
  blast: Every password stored with this hash, and every other site where users reused them.
  fix: Use Argon2id, scrypt or bcrypt through the framework's password hasher (Django PBKDF2 or Argon2 first in PASSWORD_HASHERS), and rehash on next login.
  verify: Create a user and confirm the stored hash starts with an Argon2, bcrypt or PBKDF2 prefix.
BASE-MIXED-CONTENT:
  title: Page loads assets over plain HTTP
  effort_minutes: 5
  detail: ${count} src or href value(s) start with http://, so browsers block them or load them without encryption on an HTTPS page.
  proof_needed: Check whether these URLs reach the deployed pages.
  fix: Change the URLs to https:// or to relative paths.
  verify: Open the deployed page with the browser console open and confirm no mixed content warnings.
```

`src/dpr/reviews/baseline_config.py`:

```python
"""Review 4, baseline: cookie flags, debug mode, weak password hashing, mixed content."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Tag
from dpr.parsing import jsts, pyast
from dpr.redact import snippet
from dpr.rules import Context, make_finding, rule
from dpr.walk import line_of

SESSION_LIKE = re.compile(r"(?i)sid|session|token|auth|jwt")
JS_COOKIE_CALL = re.compile(r"\(?(?:await)?cookies\(\)\)?\.set|\w+\.cookies\.set|\w+\.cookie")
JS_HEADER_CALL = re.compile(r"\w+\.(?:setHeader|header|set|append)")
FLAGS = {
    "httponly": "BASE-COOKIE-HTTPONLY",
    "secure": "BASE-COOKIE-SECURE",
    "samesite": "BASE-COOKIE-SAMESITE",
}
DJANGO_COOKIE_SETTINGS = {
    "SESSION_COOKIE_HTTPONLY": ("httponly", "high"),
    "SESSION_COOKIE_SECURE": ("secure", "high"),
    "CSRF_COOKIE_SECURE": ("secure", "low"),
    "SESSION_COOKIE_SAMESITE": ("samesite", "high"),
    "CSRF_COOKIE_SAMESITE": ("samesite", "low"),
}
WEAK_HASHES = re.compile(r"hashlib\.(md5|sha1|sha224|sha256)")
PASSWORD_WORD = re.compile(r"(?i)password|passwd|pwd")
WEAK_HASHERS = re.compile(r"MD5|SHA1", re.IGNORECASE)
MIXED = re.compile(
    r"""\b(?:src|href)\s*=\s*["']http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|www\.w3\.org)"""
)
MARKUP = (".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte", ".j2", ".jinja", ".jinja2")


def _cookie_findings(
    ctx: Context, rel: str, line: int, name: str, flags: dict[str, object]
) -> Iterator[Finding]:
    """flags maps httponly, secure, samesite to True, False, a SameSite string, or None."""
    session = bool(SESSION_LIKE.search(name))
    text = ctx.index.text(rel)
    for flag, value in flags.items():
        if flag == "samesite":
            bad = value is None or str(value).lower() == "none"
            severity = "high" if session and value is not None else "low"
            now = "not set" if value is None else "None"
        else:
            bad = value is False
            severity = "high" if session else "low"
            now = "missing or false"
        if bad:
            yield make_finding(
                FLAGS[flag],
                tag=Tag.CONFIRMED,
                locations=[Location(rel, line)],
                severity=severity,
                snippet=snippet(text, line),
                name=name,
                now=now,
            )


def _js_value(node) -> object:
    node = jsts.unwrap(node)
    if node is None:
        return None
    if node.type in ("true", "false"):
        return node.type == "true"
    text = jsts.string_value(node)
    return text if text is not None else "<dynamic>"


def _js_options(obj) -> dict[str, object] | None:
    if obj is not None and jsts.has_spread(obj):
        return None
    pairs = {k.lower(): v for k, v in jsts.object_pairs(obj).items()} if obj is not None else {}
    flags = {}
    for flag in FLAGS:
        value = _js_value(pairs.get(flag)) if flag in pairs else None
        if flag != "samesite" and flag not in pairs:
            value = False
        if value == "<dynamic>":
            continue
        flags[flag] = value
    return flags


def _set_cookie_literal(text: str) -> tuple[str, dict[str, object]]:
    parts = [p.strip() for p in text.split(";")]
    attrs = {p.split("=", 1)[0].lower(): (p.split("=", 1) + [""])[1] for p in parts[1:] if p}
    flags = {"httponly": "httponly" in attrs, "secure": "secure" in attrs}
    flags["samesite"] = attrs.get("samesite")
    return parts[0].split("=", 1)[0], flags


def _js_cookies(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.js_files:
        text = ctx.index.text(entry.rel)
        if "cookie" not in text.lower():
            continue
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for call in jsts.calls(tree, JS_COOKIE_CALL):
                args = jsts.arguments(call)
                if not args:
                    continue
                if jsts.unwrap(args[0]).type == "object":
                    pairs = jsts.object_pairs(args[0])
                    name = jsts.string_value(pairs.get("name")) or "cookie"
                    options = args[0]
                else:
                    name = jsts.string_value(args[0]) or jsts.node_text(args[0])
                    options = args[2] if len(args) > 2 else None
                flags = _js_options(options)
                if flags is not None:
                    line = jsts.line(tree, call)
                    yield from _cookie_findings(ctx, entry.rel, line, name, flags)
            for call in jsts.calls(tree, JS_HEADER_CALL):
                args = jsts.arguments(call)
                if len(args) < 2 or (jsts.string_value(args[0]) or "").lower() != "set-cookie":
                    continue
                raw = jsts.node_text(jsts.unwrap(args[1])).strip("'\"`")
                if "=" in raw:
                    name, flags = _set_cookie_literal(raw)
                    line = jsts.line(tree, call)
                    yield from _cookie_findings(ctx, entry.rel, line, name, flags)


def _py_cookies(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if "set_cookie" not in text and "COOKIE_" not in text:
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        if tree is None:
            continue
        starlette = "starlette" in text or "fastapi" in text
        for call in pyast.calls(tree, r"(?:\w+\.)+set_cookie"):
            if any(k.arg is None for k in call.keywords):
                continue
            key = call.args[0] if call.args else pyast.kwarg(call, "key")
            name = pyast.constant(key, None) if key is not None else None
            name = name if isinstance(name, str) else (ast.unparse(key) if key else "cookie")
            flags: dict[str, object] = {}
            for flag in FLAGS:
                node = pyast.kwarg(call, flag)
                value = pyast.constant(node, "<dynamic>") if node is not None else None
                if node is None and flag != "samesite":
                    value = False
                if node is None and flag == "samesite" and starlette:
                    value = "lax"
                if value != "<dynamic>":
                    flags[flag] = value
            yield from _cookie_findings(ctx, entry.rel, call.lineno, name, flags)
        if "INSTALLED_APPS" not in text and "MIDDLEWARE" not in text:
            continue
        for stmt in tree.body:
            if not isinstance(stmt, ast.Assign) or not isinstance(stmt.targets[0], ast.Name):
                continue
            setting = DJANGO_COOKIE_SETTINGS.get(stmt.targets[0].id)
            value = pyast.constant(stmt.value, "<dynamic>")
            if setting is None or value == "<dynamic>":
                continue
            flag, severity = setting
            bad = value is False if flag != "samesite" else str(value).lower() == "none"
            if bad:
                yield make_finding(
                    FLAGS[flag],
                    tag=Tag.CONFIRMED,
                    locations=[Location(entry.rel, stmt.lineno)],
                    severity=severity,
                    snippet=snippet(text, stmt.lineno),
                    name=stmt.targets[0].id,
                    now=f"set to {value}",
                )


def _cookie_rule(flag: str):
    def check(ctx: Context) -> Iterator[Finding]:
        if "cookie_findings" not in ctx.facts:
            ctx.facts["cookie_findings"] = [*_js_cookies(ctx), *_py_cookies(ctx)]
        for finding in ctx.facts["cookie_findings"]:
            if finding.rule_id == FLAGS[flag]:
                yield finding

    return check


for _flag, _rule_id in FLAGS.items():
    rule(_rule_id, review="baseline", severity="high", exploitability="medium", owasp="A05")(
        _cookie_rule(_flag)
    )


def _debug(ctx: Context, rel: str, line: int, what: str) -> Finding:
    return make_finding(
        "BASE-DEBUG-ON",
        tag=Tag.INFERRED,
        locations=[Location(rel, line)],
        snippet=snippet(ctx.index.text(rel), line),
        what=what,
    )


@rule("BASE-DEBUG-ON", review="baseline", severity="high", exploitability="medium", owasp="A05")
def debug_on(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if "debug" not in text.lower():
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        if tree is None:
            continue
        django = "INSTALLED_APPS" in text
        for stmt in tree.body:
            if (
                django
                and isinstance(stmt, ast.Assign)
                and isinstance(stmt.targets[0], ast.Name)
                and stmt.targets[0].id == "DEBUG"
                and pyast.constant(stmt.value) is True
            ):
                yield _debug(ctx, entry.rel, stmt.lineno, "Django settings set DEBUG = True.")
        for call in pyast.calls(tree, r"(?:\w+\.)?(?:FastAPI|Flask|run)"):
            if pyast.constant(pyast.kwarg(call, "debug")) is True:
                yield _debug(
                    ctx, entry.rel, call.lineno, "The app is created or run with debug=True."
                )
        for cls in pyast.class_defs(tree):
            if not any(b.endswith("Settings") for b in pyast.base_names(cls)):
                continue
            for stmt in cls.body:
                if (
                    isinstance(stmt, ast.AnnAssign)
                    and isinstance(stmt.target, ast.Name)
                    and stmt.target.id.lower() == "debug"
                    and pyast.constant(stmt.value) is True
                ):
                    what = "The settings class turns debug on unless the environment sets it."
                    yield _debug(ctx, entry.rel, stmt.lineno, what)


def _password_context(call_text: str, fn: ast.AST | None) -> bool:
    name = getattr(fn, "name", "") or ""
    return bool(PASSWORD_WORD.search(call_text) or PASSWORD_WORD.search(name))


@rule(
    "BASE-WEAK-HASH", review="baseline", severity="critical", exploitability="medium", owasp="A02"
)
def weak_hash(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if "hashlib" not in text and "PASSWORD_HASHERS" not in text:
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        if tree is None:
            continue
        for call in pyast.calls(tree, WEAK_HASHES):
            algorithm = (pyast.dotted(call.func) or "").split(".")[-1]
            if _password_context(ast.unparse(call), pyast.function_at(tree, call.lineno)):
                yield make_finding(
                    "BASE-WEAK-HASH",
                    tag=Tag.INFERRED,
                    locations=[Location(entry.rel, call.lineno)],
                    snippet=snippet(text, call.lineno),
                    algorithm=algorithm,
                )
        hashers = pyast.assignments(tree.body).get("PASSWORD_HASHERS")
        if isinstance(hashers, ast.List | ast.Tuple) and hashers.elts:
            first = pyast.constant(hashers.elts[0], "")
            if isinstance(first, str) and WEAK_HASHERS.search(first.rsplit(".", 1)[-1]):
                yield make_finding(
                    "BASE-WEAK-HASH",
                    tag=Tag.CONFIRMED,
                    locations=[Location(entry.rel, hashers.elts[0].lineno)],
                    snippet=snippet(text, hashers.elts[0].lineno),
                    algorithm=first.rsplit(".", 1)[-1],
                )
    for entry in ctx.index.js_files:
        text = ctx.index.text(entry.rel)
        if "createHash" not in text:
            continue
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for call in jsts.calls(tree, r"(?:\w+\.)?createHash"):
                args = jsts.arguments(call)
                algorithm = (jsts.string_value(args[0]) or "") if args else ""
                if algorithm.lower() not in ("md5", "sha1", "sha256"):
                    continue
                statement = call
                while statement.parent is not None and statement.parent.type not in (
                    "statement_block",
                    "program",
                ):
                    statement = statement.parent
                fn = jsts.enclosing_function(call)
                fn_name = jsts.node_text(fn.child_by_field_name("name")) if fn else ""
                if PASSWORD_WORD.search(jsts.node_text(statement) + " " + fn_name):
                    line = jsts.line(tree, call)
                    yield make_finding(
                        "BASE-WEAK-HASH",
                        tag=Tag.INFERRED,
                        locations=[Location(entry.rel, line)],
                        snippet=snippet(text, line),
                        algorithm=algorithm,
                    )


@rule("BASE-MIXED-CONTENT", review="baseline", severity="low", exploitability="low", owasp="A02")
def mixed_content(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.files:
        if not entry.rel.lower().endswith(MARKUP):
            continue
        text = ctx.index.text(entry.rel)
        lines = sorted({line_of(text, m.start()) for m in MIXED.finditer(text)})
        if lines:
            yield make_finding(
                "BASE-MIXED-CONTENT",
                tag=Tag.INFERRED,
                locations=[Location(entry.rel, n) for n in lines[:5]],
                snippet=snippet(text, lines[0]),
                count=len(lines),
            )
```

Modify `src/dpr/reviews/baseline.py`, replace:

```python
from dpr.model import Part, ReviewSection
```

with:

```python
import dpr.reviews.baseline_config  # noqa: F401  (registers rules)
from dpr.model import Part, ReviewSection
```

Rule modules are registered with plain `import dpr.reviews.<module>` lines. Ruff keeps plain imports as separate sorted lines ahead of `from` imports, so each later task adds one line without reshaping the block.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest -q`
Expected: PASS (all tests, including 5 new ones)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/reviews/baseline_config.py src/dpr/reviews/baseline.py src/dpr/data/rule_text/baseline_config.yaml tests/reviews/test_baseline_config.py
git commit -m "Add baseline checks for cookie flags, debug mode, weak password hashing and mixed content"
```

---
### Task 35: Live header adapter

The only network code in this milestone. It is called from the baseline review, and only when `url` is set; `review()` already raises `ScanError` when `url` is set without `owns_host` (Task 23). It sends exactly three `HEAD` requests with a 10 second timeout each: the https root and the https login page following redirects, and the http root without following redirects. It never sends cookies, credentials or a body. A request that fails becomes a `HeaderRead` with `error` set, never an exception.

**Files:**
- Create: `src/dpr/adapters/__init__.py`, `src/dpr/adapters/headers.py`
- Test: `tests/adapters/__init__.py` (empty), `tests/adapters/test_headers.py`

**Interfaces:**
- Consumes: `ScanError` (Task 2)
- Produces (in `dpr.adapters.headers`):
  - `HeaderRead(label: str, url: str, status: int | None = None, headers: dict[str, str] = {}, final_url: str | None = None, error: str | None = None)` with header names lowercased
  - `targets(url: str, login_path: str) -> list[tuple[str, str, bool]]` (label, URL, follow redirects); raises `ScanError` for a URL without a host
  - `read_headers(url: str, login_path: str = "/login", opener: Opener | None = None, timeout: float = 10.0) -> list[HeaderRead]`
  - `urllib_open(url: str, follow: bool, timeout: float) -> tuple[int, dict[str, str], str]` (stdlib `urllib`, `HEAD`, no redirect handler when `follow` is false; an HTTP error status is returned, not raised)
  - `Opener = Callable[[str, bool, float], tuple[int, dict[str, str], str]]`, the seam tests use instead of the network

- [ ] **Step 1: Write the failing tests**

`tests/adapters/__init__.py`: empty file.

`tests/adapters/test_headers.py`:

```python
import urllib.error

import pytest

from dpr.adapters.headers import read_headers, targets
from dpr.model import ScanError


class FakeOpener:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def __call__(self, url, follow, timeout):
        self.calls.append((url, follow, timeout))
        result = self.responses[url]
        if isinstance(result, Exception):
            raise result
        return result


def test_exactly_three_head_targets():
    assert targets("https://app.example.com/some/page", "account/login") == [
        ("https root", "https://app.example.com/", True),
        ("https login page", "https://app.example.com/account/login", True),
        ("http root", "http://app.example.com/", False),
    ]
    with pytest.raises(ScanError, match="not a usable URL"):
        targets("https://", "/login")


def test_read_headers_lowercases_and_records_failures():
    opener = FakeOpener(
        {
            "https://app.example.com/": (200, {"Strict-Transport-Security": "max-age=1"}, "x"),
            "https://app.example.com/login": urllib.error.URLError("timed out"),
            "http://app.example.com/": (301, {"Location": "https://app.example.com/"}, "y"),
        }
    )
    reads = read_headers("app.example.com", "/login", opener=opener)
    assert [c[1] for c in opener.calls] == [True, True, False]
    assert all(c[2] == 10.0 for c in opener.calls)
    assert reads[0].headers == {"strict-transport-security": "max-age=1"}
    assert reads[1].status is None and reads[1].error == "timed out"
    assert reads[2].status == 301 and reads[2].headers["location"].startswith("https://")


def test_urllib_open_sends_head_without_following(monkeypatch):
    from dpr.adapters import headers

    seen = {}

    class Response:
        status = 200
        headers = {"Server": "nginx"}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def geturl(self):
            return seen["url"]

    class Opener:
        def __init__(self, handlers):
            self.handlers = handlers

        def open(self, request, timeout):
            seen.update(url=request.full_url, method=request.get_method(), timeout=timeout)
            seen["handlers"] = self.handlers
            return Response()

    monkeypatch.setattr(
        headers.urllib.request, "build_opener", lambda *h: Opener([type(x).__name__ for x in h])
    )
    status, got, final = headers.urllib_open("http://app.example.com/", False, 10.0)
    assert (status, got, final) == (200, {"Server": "nginx"}, "http://app.example.com/")
    assert seen["method"] == "HEAD" and seen["timeout"] == 10.0
    assert seen["handlers"] == ["_NoRedirect"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/adapters -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'dpr.adapters'`

- [ ] **Step 3: Write the adapter**

`src/dpr/adapters/__init__.py`:

```python
"""Optional adapters that reach outside the repository. None of them run by default."""
```

`src/dpr/adapters/headers.py`:

```python
"""Live header read: exactly three HEAD requests to a host the owner controls."""

from __future__ import annotations

import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from dpr.model import ScanError

TIMEOUT_SECONDS = 10.0
USER_AGENT = "dpr header read (owner-confirmed host)"
Opener = Callable[[str, bool, float], tuple[int, dict[str, str], str]]


@dataclass(frozen=True)
class HeaderRead:
    label: str
    url: str
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    final_url: str | None = None
    error: str | None = None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def urllib_open(url: str, follow: bool, timeout: float) -> tuple[int, dict[str, str], str]:
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
    handlers = [] if follow else [_NoRedirect()]
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, dict(response.headers.items()), response.geturl()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers.items()), url


def targets(url: str, login_path: str) -> list[tuple[str, str, bool]]:
    parts = urlsplit(url if "://" in url else f"https://{url}")
    if not parts.hostname:
        raise ScanError(f"not a usable URL for a header read: {url}")
    host = parts.netloc
    login = "/" + login_path.lstrip("/")
    return [
        ("https root", f"https://{host}/", True),
        ("https login page", f"https://{host}{login}", True),
        ("http root", f"http://{host}/", False),
    ]


def read_headers(
    url: str,
    login_path: str = "/login",
    opener: Opener | None = None,
    timeout: float = TIMEOUT_SECONDS,
) -> list[HeaderRead]:
    open_url = opener or urllib_open
    reads = []
    for label, target, follow in targets(url, login_path):
        try:
            status, headers, final = open_url(target, follow, timeout)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", None) or type(exc).__name__
            reads.append(HeaderRead(label, target, error=str(reason)))
            continue
        lowered = {k.lower(): v for k, v in headers.items()}
        reads.append(HeaderRead(label, target, status, lowered, final))
    return reads
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/adapters -q`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/adapters tests/adapters
git commit -m "Add the live header adapter with exactly three HEAD requests"
```

---
### Task 36: Baseline security headers, CSP, version disclosure and the live checks

Header findings are judged per surface, not per repository. A surface is something that serves responses and can set headers: a static host config (`staticwebapp.config.json`, `vercel.json`, `firebase.json` with hosting, `netlify.toml`, `_headers`, nginx `add_header`), a Next.js app (`next.config.*`), a FastAPI, Flask or Starlette app, an Express app, or Django settings. A header counts as set for an app surface when its name appears as a string literal in that app's code, when `helmet()` (all but Permissions-Policy), Flask-Talisman or `secure` is used, or through Django's security middleware settings. The app's files are those under the nearest folder with a manifest. Vercel and Netlify send HSTS by default, so those configs count it as set. This per-surface view is why a monorepo whose static site sets some headers still reports an API that sets none.

Without `--url`, header findings are UNVERIFIED and point at each surface that lacks the header. With `--url` and `--i-own-this-host`, the https root response decides: CONFIRMED, located at the URL. The same three reads drive `BASE-NO-HTTPS-REDIRECT` (http root) and `BASE-CACHE-AUTH` (login page). A failed read is listed in "What this review did not cover" and the static result stands.

**Files:**
- Create: `src/dpr/reviews/headers_static.py`, `src/dpr/reviews/baseline_headers.py`, `src/dpr/data/rule_text/baseline_headers.yaml`
- Modify: `src/dpr/reviews/baseline.py` (replace the whole file: section parts and the live read)
- Test: `tests/reviews/test_baseline_headers.py`

**Interfaces:**
- Consumes: `Location`, `Tag`, `Part`, `ReviewSection` (Task 2); `rule`, `make_finding`, `Context`, `Options` (Task 4); `line_of` (Task 5); `jsts`, `pyast` (Tasks 7, 8); `review()` (Task 23); `HeaderRead`, `read_headers` (Task 35)
- Produces:
  - `dpr.reviews.headers_static`: `HEADERS` (key to lowercase header name, keys `HSTS`, `CSP`, `XCTO`, `FRAME`, `REFERRER`, `PERMISSIONS`); `Surface(name, kind, location, headers: frozenset[str], root)`; `surfaces(ctx) -> list[Surface]` cached in `ctx.facts["header_surfaces"]`; `csp_values(ctx) -> list[tuple[str, Location]]`; `app_root(ctx, rel) -> str`
  - `dpr.reviews.baseline_headers`: `login_path(ctx) -> str` (option, else a route ending in `/login` or `/signin`, else `/login`); `live_reads(ctx) -> list[HeaderRead] | None` cached in `ctx.facts["live_headers"]`, `None` unless both `url` and `owns_host` are set; `weak_csp_reason(policy) -> str | None`
  - Registered rules (review `baseline`, owasp A05 unless noted): `BASE-HEADER-MISSING-HSTS` (high), `-CSP` (medium), `-XCTO`, `-FRAME`, `-REFERRER`, `-PERMISSIONS` (low), `BASE-CSP-WEAK` (medium, CONFIRMED), `BASE-VERSION-DISCLOSURE` (low; INFERRED from config, CONFIRMED live), `BASE-NO-HTTPS-REDIRECT` (high, A02, live only), `BASE-CACHE-AUTH` (low, live only)
  - Baseline section parts in order: text "How headers were checked", table "Live header read" (only with a URL), table "Security headers by surface" (only when surfaces exist), findings "Fix list", text "Password storage and account enumeration" (names a managed auth provider when one is detected, and refers enumeration to AUTH-CASE-2 and AUTH-CASE-4)

- [ ] **Step 1: Write the failing tests**

`tests/reviews/test_baseline_headers.py`:

```python
import pytest

from dpr import reviews, rules
from dpr.adapters.headers import HeaderRead
from dpr.api import review
from dpr.discovery.detect import detect
from dpr.reviews import baseline, baseline_headers
from dpr.reviews.baseline_headers import weak_csp_reason
from dpr.reviews.headers_static import surfaces
from dpr.walk import RepoIndex
from tests.reviews.helpers import findings_for, write

SWA = '{\n  "globalHeaders": {\n    "X-Frame-Options": "DENY",\n    "Referrer-Policy": "no-referrer"\n  }\n}\n'


def context(root, **options):
    reviews.available()
    index = RepoIndex(root)
    return rules.Context(index=index, detection=detect(index), options=rules.Options(**options))


def repo(root):
    write(root, "web/package.json", "{}")
    write(root, "web/staticwebapp.config.json", SWA)
    write(root, "web/src/main.tsx", "export {}\n")
    write(root, "api/requirements.txt", "fastapi\n")
    write(
        root,
        "api/app/main.py",
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "@app.middleware('http')\nasync def headers(request, call_next):\n"
        "    response = await call_next(request)\n"
        "    response.headers['Strict-Transport-Security'] = 'max-age=31536000'\n"
        "    response.headers['X-Content-Type-Options'] = 'nosniff'\n"
        "    return response\n",
    )
    write(root, "site/package.json", "{}")
    write(root, "site/next.config.js", "module.exports = { reactStrictMode: true }\n")
    write(
        root,
        "site/vercel.json",
        '{"headers": [{"source": "/(.*)", "headers": [{"key": "Permissions-Policy", "value": "camera=()"}]}]}',
    )
    write(root, "legacy/package.json", "{}")
    write(
        root,
        "legacy/server.js",
        "const express = require('express')\nconst app = express()\napp.use(helmet())\n",
    )
    return root


def test_surfaces_collect_headers_per_app(tmp_path):
    found = {s.name: s for s in surfaces(context(repo(tmp_path)))}
    assert set(found) == {
        "api/app/main.py",
        "legacy/server.js",
        "site/next.config.js",
        "site/vercel.json",
        "web/staticwebapp.config.json",
    }
    assert found["web/staticwebapp.config.json"].headers == {"x-frame-options", "referrer-policy"}
    assert found["web/staticwebapp.config.json"].location.line == 2
    assert found["api/app/main.py"].headers == {
        "strict-transport-security",
        "x-content-type-options",
    }
    assert found["api/app/main.py"].kind == "FastAPI app"
    assert "permissions-policy" not in found["legacy/server.js"].headers
    assert "content-security-policy" in found["legacy/server.js"].headers
    assert found["site/vercel.json"].headers == {"strict-transport-security", "permissions-policy"}


def test_missing_headers_are_unverified_without_url(tmp_path):
    root = repo(tmp_path)
    [hsts] = findings_for(root, "baseline", "BASE-HEADER-MISSING-HSTS")
    assert hsts.tag.value == "UNVERIFIED" and hsts.severity.value == "high"
    assert [str(loc) for loc in hsts.locations] == [
        "site/next.config.js:1",
        "web/staticwebapp.config.json:2",
    ]
    assert "web/staticwebapp.config.json (static host config)" in hsts.detail
    [csp] = findings_for(root, "baseline", "BASE-HEADER-MISSING-CSP")
    assert len(csp.locations) == 4 and csp.severity.value == "medium"
    assert findings_for(root, "baseline", "BASE-HEADER-MISSING-FRAME")[0].severity.value == "low"


def test_django_settings_surface(tmp_path):
    write(
        tmp_path,
        "proj/settings.py",
        "INSTALLED_APPS = []\nMIDDLEWARE = ['django.middleware.security.SecurityMiddleware',\n"
        "  'django.middleware.clickjacking.XFrameOptionsMiddleware']\nSECURE_HSTS_SECONDS = 31536000\n",
    )
    [surface] = surfaces(context(tmp_path))
    assert surface.headers == {
        "strict-transport-security",
        "x-content-type-options",
        "referrer-policy",
        "x-frame-options",
    }


def test_weak_csp_reason():
    assert weak_csp_reason("default-src 'self'; script-src 'self' 'unsafe-inline'") == (
        "script-src allows 'unsafe-inline'"
    )
    assert weak_csp_reason("default-src * data:") == "default-src allows any origin (*)"
    assert weak_csp_reason("default-src 'self'; style-src 'unsafe-inline'") is None


def test_csp_weak_and_version_disclosure_from_config(tmp_path):
    root = repo(tmp_path)
    write(
        root,
        "site/next.config.js",
        "module.exports = { async headers() { return [{ source: '/(.*)', headers: [\n"
        "  { key: 'Content-Security-Policy', value: \"default-src 'self'; script-src 'self' 'unsafe-inline'\" },\n"
        "] }] } }\n",
    )
    write(root, "other/package.json", "{}")
    write(root, "other/app.js", "const express = require('express')\nconst app = express()\n")
    [weak] = findings_for(root, "baseline", "BASE-CSP-WEAK")
    assert str(weak.locations[0]) == "site/next.config.js:2"
    found = findings_for(root, "baseline", "BASE-VERSION-DISCLOSURE")
    assert sorted(str(f.locations[0]) for f in found) == ["other/app.js:2", "site/next.config.js:1"]
    write(root, "site/next.config.js", "module.exports = { poweredByHeader: false }\n")
    assert [
        str(f.locations[0]) for f in findings_for(root, "baseline", "BASE-VERSION-DISCLOSURE")
    ] == ["other/app.js:2"]


READS = [
    HeaderRead(
        "https root",
        "https://app.example.com/",
        200,
        {
            "server": "nginx/1.25.3",
            "content-security-policy": "default-src *",
            "x-frame-options": "DENY",
        },
    ),
    HeaderRead(
        "https login page", "https://app.example.com/login", 200, {"cache-control": "private"}
    ),
    HeaderRead("http root", "http://app.example.com/", 200, {}),
]


@pytest.fixture
def live(monkeypatch):
    calls = []

    def fake(url, login_path):
        calls.append((url, login_path))
        return READS

    monkeypatch.setattr(baseline_headers, "read_headers", fake)
    return calls


def test_live_reads_confirm_findings(tmp_path, live):
    root = repo(tmp_path)
    options = {"url": "https://app.example.com", "owns_host": True}
    [hsts] = findings_for(root, "baseline", "BASE-HEADER-MISSING-HSTS", **options)
    assert hsts.tag.value == "CONFIRMED" and str(hsts.locations[0]) == "https://app.example.com/:1"
    assert findings_for(root, "baseline", "BASE-HEADER-MISSING-FRAME", **options) == []
    assert findings_for(root, "baseline", "BASE-CSP-WEAK", **options)[0].tag.value == "CONFIRMED"
    assert (
        findings_for(root, "baseline", "BASE-NO-HTTPS-REDIRECT", **options)[0].severity.value
        == "high"
    )
    assert len(findings_for(root, "baseline", "BASE-CACHE-AUTH", **options)) == 1
    version = findings_for(root, "baseline", "BASE-VERSION-DISCLOSURE", **options)
    assert any(f.tag.value == "CONFIRMED" for f in version)
    assert live[0] == ("https://app.example.com", "/login")


def test_login_path_from_routes_and_option(tmp_path):
    write(tmp_path, "app/api/auth/signin/route.ts", "export async function POST() {}\n")
    assert baseline_headers.login_path(context(tmp_path)) == "/api/auth/signin"
    assert baseline_headers.login_path(context(tmp_path, login_path="/enter")) == "/enter"
    write(tmp_path / "other", "a.py", "x = 1\n")
    assert baseline_headers.login_path(context(tmp_path / "other")) == "/login"


def test_section_tables_and_failures(tmp_path, live, monkeypatch):
    root = repo(tmp_path)
    ctx = context(root)
    titles = [p.title for p in baseline.run(ctx).parts]
    assert titles == [
        "How headers were checked",
        "Security headers by surface",
        "Fix list",
        "Password storage and account enumeration",
    ]
    failed = [HeaderRead("https root", "https://app.example.com/", error="timed out"), *READS[1:]]
    monkeypatch.setattr(baseline_headers, "read_headers", lambda url, login: failed)
    ctx = context(root, url="https://app.example.com", owns_host=True)
    section = baseline.run(ctx)
    table = next(p for p in section.parts if p.title == "Live header read")
    assert table.rows[0][2:] == ("failed", "timed out")
    assert "Live header read of https://app.example.com/ failed: timed out" in ctx.not_covered


def test_default_review_never_reads_headers(tmp_path, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("live header read without a URL")

    monkeypatch.setattr(baseline_headers, "read_headers", refuse)
    report = review(repo(tmp_path))
    assert "baseline" in report.sections
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/reviews/test_baseline_headers.py -q`
Expected: FAIL with `ImportError: cannot import name 'baseline_headers' from 'dpr.reviews'`

- [ ] **Step 3: Write the surfaces, the rules, the rule text and the section**

`src/dpr/reviews/headers_static.py`:

```python
"""Security header surfaces read from configuration and app code, without a network call."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from dpr.model import Location
from dpr.parsing import jsts, pyast
from dpr.rules import Context
from dpr.walk import line_of

HEADERS = {
    "HSTS": "strict-transport-security",
    "CSP": "content-security-policy",
    "XCTO": "x-content-type-options",
    "FRAME": "x-frame-options",
    "REFERRER": "referrer-policy",
    "PERMISSIONS": "permissions-policy",
}
ALL = frozenset(HEADERS.values())
HELMET = ALL - {"permissions-policy"}
MANIFESTS = ("package.json", "pyproject.toml", "requirements.txt", "manage.py")
HEADER_LITERAL = re.compile(
    r"""["'`](strict-transport-security|content-security-policy|x-content-type-options"""
    r"""|x-frame-options|referrer-policy|permissions-policy)["'`]""",
    re.IGNORECASE,
)
STRING_LITERAL = re.compile(r""""(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\]|\\.)*`""")
PLATFORM_HSTS = {"vercel.json", "netlify.toml"}


@dataclass(frozen=True)
class Surface:
    name: str
    kind: str
    location: Location
    headers: frozenset[str]
    root: str


def app_root(ctx: Context, rel: str) -> str:
    names = {f.rel for f in ctx.index.files}
    folder = PurePosixPath(rel).parent
    while True:
        prefix = "" if str(folder) == "." else f"{folder}/"
        if any(f"{prefix}{m}" in names for m in MANIFESTS):
            return str(folder) if prefix else ""
        if str(folder) == ".":
            return ""
        folder = folder.parent


def _under(rel: str, root: str) -> bool:
    return not root or rel.startswith(root + "/")


def _code_headers(ctx: Context, root: str) -> frozenset[str]:
    found: set[str] = set()
    for entry in [*ctx.index.js_files, *ctx.index.py_files]:
        if not _under(entry.rel, root):
            continue
        text = ctx.index.text(entry.rel)
        found.update(m.group(1).lower() for m in HEADER_LITERAL.finditer(text))
        if "frame-ancestors" in text:
            found.add("x-frame-options")
        if "helmet(" in text:
            found |= HELMET
        if re.search(r"\bTalisman\(|\bsecure\.Secure\(|SecureHeaders\(", text):
            found |= ALL
    return frozenset(found)


def _json_headers(text: str, name: str) -> frozenset[str]:
    try:
        data = json.loads(text)
    except ValueError:
        return frozenset()
    keys: list[str] = []
    if name == "staticwebapp.config.json":
        keys += list((data.get("globalHeaders") or {}).keys())
        for route in data.get("routes") or []:
            keys += list((route.get("headers") or {}).keys())
    else:
        groups = data.get("headers") or []
        if name == "firebase.json":
            groups = (data.get("hosting") or {}).get("headers") or []
        for group in groups:
            keys += [h.get("key", "") for h in group.get("headers") or []]
    return frozenset(k.lower() for k in keys)


def _static_surfaces(ctx: Context) -> list[Surface]:
    found = []
    for entry in ctx.index.named("staticwebapp.config.json", "vercel.json", "firebase.json"):
        text = ctx.index.text(entry.rel)
        headers = _json_headers(text, entry.name)
        if entry.name == "firebase.json" and '"hosting"' not in text:
            continue
        if entry.name in PLATFORM_HSTS:
            headers |= {"strict-transport-security"}
        marker = (
            text.find('"globalHeaders"') if '"globalHeaders"' in text else text.find('"headers"')
        )
        line = line_of(text, marker) if marker >= 0 else 1
        found.append(
            Surface(entry.rel, "static host config", Location(entry.rel, line), headers, "")
        )
    for entry in ctx.index.named("netlify.toml", "_headers", "nginx.conf", "*.nginx.conf"):
        text = ctx.index.text(entry.rel)
        names = re.findall(r"(?im)^\s*(?:add_header\s+)?([A-Za-z-]+)\s*[:=\s]", text)
        headers = frozenset(n.lower() for n in names if n.lower() in ALL)
        if entry.name in PLATFORM_HSTS:
            headers |= {"strict-transport-security"}
        if entry.name != "netlify.toml" and not headers and "add_header" not in text:
            continue
        found.append(Surface(entry.rel, "static host config", Location(entry.rel, 1), headers, ""))
    return found


def _django_headers(text: str) -> frozenset[str]:
    found: set[str] = set()
    if "SecurityMiddleware" in text:
        found |= {"x-content-type-options", "referrer-policy"}
        if re.search(r"SECURE_HSTS_SECONDS\s*=\s*[1-9]", text):
            found.add("strict-transport-security")
        if re.search(r"SECURE_CONTENT_TYPE_NOSNIFF\s*=\s*False", text):
            found.discard("x-content-type-options")
    if "XFrameOptionsMiddleware" in text:
        found.add("x-frame-options")
    if "CSPMiddleware" in text or "CONTENT_SECURITY_POLICY" in text:
        found.add("content-security-policy")
    if "PERMISSIONS_POLICY" in text:
        found.add("permissions-policy")
    return frozenset(found)


def _app_surfaces(ctx: Context) -> list[Surface]:
    found = []
    for entry in ctx.index.named("next.config.*"):
        root = app_root(ctx, entry.rel)
        text = ctx.index.text(entry.rel)
        headers = frozenset(m.group(1).lower() for m in HEADER_LITERAL.finditer(text))
        headers |= _code_headers(ctx, root)
        found.append(Surface(entry.rel, "Next.js app", Location(entry.rel, 1), headers, root))
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if "INSTALLED_APPS" in text and "MIDDLEWARE" in text:
            found.append(
                Surface(
                    entry.rel, "Django settings", Location(entry.rel, 1), _django_headers(text), ""
                )
            )
            continue
        if not re.search(r"\b(FastAPI|Flask|Starlette)\(", text):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for call in pyast.calls(tree, r"(?:\w+\.)?(?:FastAPI|Flask|Starlette)") if tree else []:
            root = app_root(ctx, entry.rel)
            kind = f"{pyast.dotted(call.func).split('.')[-1]} app"
            location = Location(entry.rel, call.lineno)
            found.append(Surface(entry.rel, kind, location, _code_headers(ctx, root), root))
            break
    for entry in ctx.index.js_files:
        text = ctx.index.text(entry.rel)
        if "express" not in text:
            continue
        for tree in jsts.parse_file(ctx.index, entry.rel):
            calls = list(jsts.calls(tree, r"express"))
            if calls:
                root = app_root(ctx, entry.rel)
                location = Location(entry.rel, jsts.line(tree, calls[0]))
                found.append(
                    Surface(entry.rel, "Express app", location, _code_headers(ctx, root), root)
                )
    return found


def surfaces(ctx: Context) -> list[Surface]:
    if "header_surfaces" not in ctx.facts:
        ctx.facts["header_surfaces"] = sorted(
            [*_static_surfaces(ctx), *_app_surfaces(ctx)], key=lambda s: s.name
        )
    return ctx.facts["header_surfaces"]


def csp_values(ctx: Context) -> list[tuple[str, Location]]:
    found = []
    roots = {s.root for s in surfaces(ctx)}
    candidates = [s.location.file for s in surfaces(ctx)]
    candidates += [
        f.rel
        for f in [*ctx.index.js_files, *ctx.index.py_files]
        if any(_under(f.rel, root) for root in roots)
    ]
    for rel in dict.fromkeys(candidates):
        text = ctx.index.text(rel)
        for match in STRING_LITERAL.finditer(text):
            policy = match.group(0)[1:-1]
            if "default-src" in policy or "script-src" in policy:
                found.append((policy, Location(rel, line_of(text, match.start()))))
    return found
```

`src/dpr/reviews/baseline_headers.py`:

```python
"""Review 4, baseline: security headers, CSP strength, version disclosure, HTTPS redirect."""

from __future__ import annotations

import re
from collections.abc import Iterator

from dpr.adapters.headers import HeaderRead, read_headers
from dpr.model import Finding, Location, Tag
from dpr.reviews.headers_static import HEADERS, csp_values, surfaces
from dpr.rules import Context, make_finding, rule

SEVERITY = {"HSTS": "high", "CSP": "medium"}
LOGIN_PATH = re.compile(r"(?i)/(?:log-?in|sign-?in)$")
VERSION = re.compile(r"\d")


def login_path(ctx: Context) -> str:
    if ctx.options.login_path:
        return ctx.options.login_path
    for route in ctx.detection.routes:
        if LOGIN_PATH.search(route.path) and route.method in ("GET", "ANY", "POST"):
            return route.path
    return "/login"


def live_reads(ctx: Context) -> list[HeaderRead] | None:
    """Read live headers once per run, only when a URL was given with owner confirmation."""
    if not ctx.options.url or not ctx.options.owns_host:
        return None
    if "live_headers" not in ctx.facts:
        reads = read_headers(ctx.options.url, login_path(ctx))
        for read in reads:
            if read.error:
                ctx.not_covered.append(f"Live header read of {read.url} failed: {read.error}")
        ctx.facts["live_headers"] = reads
    return ctx.facts["live_headers"]


def _read(ctx: Context, label: str) -> HeaderRead | None:
    for read in live_reads(ctx) or []:
        if read.label == label and read.status is not None:
            return read
    return None


def _missing(ctx: Context, key: str) -> Iterator[Finding]:
    header = HEADERS[key]
    root = _read(ctx, "https root")
    if root is not None:
        present = header in root.headers or (
            key == "FRAME" and "frame-ancestors" in root.headers.get(HEADERS["CSP"], "")
        )
        if not present:
            yield make_finding(
                f"BASE-HEADER-MISSING-{key}",
                tag=Tag.CONFIRMED,
                locations=[Location(root.url, 1)],
                severity=SEVERITY.get(key, "low"),
                header=header,
                where=f"the live response from {root.url}",
            )
        return
    lacking = [s for s in surfaces(ctx) if header not in s.headers]
    if lacking:
        where = "; ".join(f"{s.name} ({s.kind})" for s in lacking)
        yield make_finding(
            f"BASE-HEADER-MISSING-{key}",
            tag=Tag.UNVERIFIED,
            locations=[s.location for s in lacking][:10],
            severity=SEVERITY.get(key, "low"),
            header=header,
            where=where,
        )


def _header_rule(key: str):
    def check(ctx: Context) -> Iterator[Finding]:
        yield from _missing(ctx, key)

    return check


for _key in HEADERS:
    rule(
        f"BASE-HEADER-MISSING-{_key}",
        review="baseline",
        severity=SEVERITY.get(_key, "low"),
        exploitability="low",
        owasp="A05",
    )(_header_rule(_key))


def _directive(policy: str, name: str) -> str | None:
    for part in policy.split(";"):
        tokens = part.strip().split()
        if tokens and tokens[0].lower() == name:
            return " ".join(tokens[1:])
    return None


def weak_csp_reason(policy: str) -> str | None:
    script = _directive(policy, "script-src")
    default = _directive(policy, "default-src")
    effective = script if script is not None else default
    if effective is not None and "'unsafe-inline'" in effective:
        return "script-src allows 'unsafe-inline'"
    if default is not None and "*" in default.split():
        return "default-src allows any origin (*)"
    return None


@rule("BASE-CSP-WEAK", review="baseline", severity="medium", exploitability="medium", owasp="A05")
def csp_weak(ctx: Context) -> Iterator[Finding]:
    root = _read(ctx, "https root")
    if root is not None and HEADERS["CSP"] in root.headers:
        reason = weak_csp_reason(root.headers[HEADERS["CSP"]])
        if reason:
            yield make_finding(
                "BASE-CSP-WEAK", tag=Tag.CONFIRMED, locations=[Location(root.url, 1)], reason=reason
            )
    for policy, location in csp_values(ctx):
        reason = weak_csp_reason(policy)
        if reason:
            yield make_finding(
                "BASE-CSP-WEAK", tag=Tag.CONFIRMED, locations=[location], reason=reason
            )


@rule(
    "BASE-VERSION-DISCLOSURE",
    review="baseline",
    severity="low",
    exploitability="low",
    owasp="A05",
)
def version_disclosure(ctx: Context) -> Iterator[Finding]:
    root = _read(ctx, "https root")
    if root is not None:
        for name in ("server", "x-powered-by"):
            if VERSION.search(root.headers.get(name, "")):
                yield make_finding(
                    "BASE-VERSION-DISCLOSURE",
                    tag=Tag.CONFIRMED,
                    locations=[Location(root.url, 1)],
                    what=f"The live response sends a {name} header with a version number.",
                )
    for surface in surfaces(ctx):
        text = ctx.index.text(surface.location.file)
        if surface.kind == "Next.js app" and not re.search(r"poweredByHeader\s*:\s*false", text):
            what = (
                "next.config does not set poweredByHeader: false, so X-Powered-By: Next.js is sent."
            )
        elif surface.kind == "Express app" and not _express_hides(ctx, surface.root):
            what = "The Express app neither calls app.disable('x-powered-by') nor uses helmet."
        else:
            continue
        yield make_finding(
            "BASE-VERSION-DISCLOSURE",
            tag=Tag.INFERRED,
            locations=[surface.location],
            what=what,
        )


def _express_hides(ctx: Context, root: str) -> bool:
    for entry in ctx.index.js_files:
        if root and not entry.rel.startswith(root + "/"):
            continue
        text = ctx.index.text(entry.rel)
        if re.search(r"disable\(\s*['\"]x-powered-by['\"]", text) or "helmet(" in text:
            return True
    return False


@rule(
    "BASE-NO-HTTPS-REDIRECT",
    review="baseline",
    severity="high",
    exploitability="medium",
    owasp="A02",
)
def no_https_redirect(ctx: Context) -> Iterator[Finding]:
    http = _read(ctx, "http root")
    if http is None:
        return
    location = http.headers.get("location", "")
    if http.status not in (301, 302, 303, 307, 308) or not location.startswith("https://"):
        yield make_finding(
            "BASE-NO-HTTPS-REDIRECT",
            tag=Tag.CONFIRMED,
            locations=[Location(http.url, 1)],
            status=http.status,
        )


@rule("BASE-CACHE-AUTH", review="baseline", severity="low", exploitability="low", owasp="A05")
def cache_auth(ctx: Context) -> Iterator[Finding]:
    login = _read(ctx, "https login page")
    if login is not None and "no-store" not in login.headers.get("cache-control", "").lower():
        yield make_finding("BASE-CACHE-AUTH", tag=Tag.CONFIRMED, locations=[Location(login.url, 1)])
```

`src/dpr/data/rule_text/baseline_headers.yaml`:

```yaml
BASE-HEADER-MISSING-HSTS:
  title: Strict-Transport-Security is not set
  effort_minutes: 10
  detail: No ${header} header was found for ${where}.
  attack: On a hostile network, intercept a first plain HTTP visit and keep the victim on HTTP to read or change traffic.
  blast: Sessions and form data of anyone who reaches the site over an intercepted connection.
  fix: 'Send Strict-Transport-Security: max-age=31536000; includeSubDomains from every surface listed: the host config (for example staticwebapp.config.json globalHeaders or vercel.json headers), a response middleware in the API, or SECURE_HSTS_SECONDS in Django.'
  verify: curl -sSI https://your-host/ | grep -i strict-transport-security
BASE-HEADER-MISSING-CSP:
  title: Content-Security-Policy is not set
  effort_minutes: 240
  detail: No ${header} header was found for ${where}. A policy takes real testing time, so rank it after the quick fixes.
  attack: Any injected script runs with full access to the page, because nothing limits where scripts load from.
  blast: Whatever the signed-in page can read or do.
  fix: "Start with Content-Security-Policy-Report-Only: default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self', add the script, style, font and connect origins the app really uses, watch the reports, then switch to enforcing."
  verify: curl -sSI https://your-host/ | grep -i content-security-policy
BASE-HEADER-MISSING-XCTO:
  title: X-Content-Type-Options is not set
  effort_minutes: 5
  detail: No ${header} header was found for ${where}.
  attack: Upload or reflect content that a browser sniffs as script or HTML instead of the declared type.
  blast: Pages that serve user-supplied files or reflected content.
  fix: 'Send X-Content-Type-Options: nosniff from every surface listed.'
  verify: curl -sSI https://your-host/ | grep -i x-content-type-options
BASE-HEADER-MISSING-FRAME:
  title: Frame protection is not set
  effort_minutes: 5
  detail: No ${header} header or CSP frame-ancestors directive was found for ${where}.
  attack: Load the site in an invisible frame on another page and trick a signed-in user into clicking a real button.
  blast: Any one-click action on authenticated pages.
  fix: "Send X-Frame-Options: DENY, or Content-Security-Policy: frame-ancestors 'none', from every surface listed."
  verify: curl -sSI https://your-host/ | grep -iE "x-frame-options|frame-ancestors"
BASE-HEADER-MISSING-REFERRER:
  title: Referrer-Policy is not set
  effort_minutes: 5
  detail: No ${header} header was found for ${where}.
  blast: Full URLs, including tokens or IDs in paths and query strings, sent to third-party sites the page links to or loads from.
  fix: 'Send Referrer-Policy: strict-origin-when-cross-origin from every surface listed.'
  verify: curl -sSI https://your-host/ | grep -i referrer-policy
BASE-HEADER-MISSING-PERMISSIONS:
  title: Permissions-Policy is not set
  effort_minutes: 5
  detail: No ${header} header was found for ${where}.
  blast: Camera, microphone and location prompts available to any script or frame running on the page.
  fix: 'Send Permissions-Policy: camera=(), microphone=(), geolocation=() from every surface listed, allowing only the features the app uses.'
  verify: curl -sSI https://your-host/ | grep -i permissions-policy
BASE-CSP-WEAK:
  title: Content-Security-Policy is weak
  effort_minutes: 60
  detail: The policy here is weak because ${reason}, which lets injected script run.
  attack: Inject an inline script through any XSS bug; the policy does not stop it.
  blast: Whatever the signed-in page can read or do.
  fix: Remove 'unsafe-inline' from script-src by moving inline scripts to files or using nonces or hashes, and replace any * source with explicit origins.
  verify: curl -sSI https://your-host/ | grep -i content-security-policy
BASE-VERSION-DISCLOSURE:
  title: Server or framework version disclosed
  effort_minutes: 5
  detail: ${what}
  proof_needed: Check the headers the deployed site actually sends; a proxy or platform may remove or add them.
  attack: Read the header and look up known vulnerabilities for that exact version.
  fix: Remove the header (poweredByHeader false in next.config, app.disable('x-powered-by') or helmet in Express, server_tokens off in nginx).
  verify: curl -sSI https://your-host/ | grep -iE "^(server|x-powered-by):"
BASE-NO-HTTPS-REDIRECT:
  title: Plain HTTP does not redirect to HTTPS
  effort_minutes: 10
  detail: The http root answered with status ${status} and no redirect to an https:// URL.
  attack: Link a victim to the http:// address on a hostile network and read or change the unencrypted response.
  blast: Sessions and form data sent over the plain HTTP connection.
  fix: Redirect every plain HTTP request to HTTPS with a 301 at the host or proxy (for example https_only on Azure App Service, force HTTPS on the CDN).
  verify: curl -sSI http://your-host/ and confirm a 301 with an https:// Location.
BASE-CACHE-AUTH:
  title: Login page can be cached
  effort_minutes: 5
  detail: The login page response has no Cache-Control no-store, so browsers and shared proxies may keep it.
  blast: Authenticated pages restored from cache on shared machines, including after logout.
  fix: 'Send Cache-Control: no-store on the login page and on every authenticated response.'
  verify: curl -sSI https://your-host/login | grep -i cache-control
```

Replace the whole of `src/dpr/reviews/baseline.py`:

`src/dpr/reviews/baseline.py`:

```python
"""Review 4, security baseline: headers, cookies, transport, password storage."""

from __future__ import annotations

import dpr.reviews.baseline_config  # noqa: F401  (registers rules)
from dpr.model import Part, ReviewSection
from dpr.reviews.baseline_headers import live_reads
from dpr.reviews.headers_static import HEADERS, surfaces
from dpr.rules import Context

MANAGED_AUTH = {
    "supabase-auth": "Supabase Auth",
    "clerk": "Clerk",
    "auth0": "Auth0",
    "firebase-auth": "Firebase Authentication",
}
HOW_CHECKED_STATIC = (
    "No URL was given, so headers come from configuration and app code. Configured is not the "
    "same as served: a CDN, proxy or platform can add or strip headers. Header findings are "
    "UNVERIFIED until checked against the live site with --url and --i-own-this-host."
)
HOW_CHECKED_LIVE = (
    "Headers were read from the live site named with --url, which the owner confirmed they "
    "control: one HEAD request each to the https root, the https login page and the http root."
)
ENUMERATION = (
    "Account enumeration through login, signup and reset messages belongs to review 3 cases 2 "
    "and 4 (AUTH-CASE-2 and AUTH-CASE-4). This review does not repeat it."
)


def _surface_rows(ctx: Context) -> tuple[tuple[str, ...], ...]:
    return tuple(
        (s.name, s.kind, *("yes" if h in s.headers else "no" for h in HEADERS.values()))
        for s in surfaces(ctx)
    )


def run(ctx: Context) -> ReviewSection:
    reads = live_reads(ctx)
    parts = [
        Part(
            "text",
            "How headers were checked",
            body=HOW_CHECKED_LIVE if reads else HOW_CHECKED_STATIC,
        )
    ]
    if reads:
        rows = tuple(
            (r.label, r.url, str(r.status) if r.status is not None else "failed", r.error or "read")
            for r in reads
        )
        parts.append(
            Part("table", "Live header read", ("Request", "URL", "Status", "Result"), rows)
        )
    if surfaces(ctx):
        columns = ("Surface", "Kind", *HEADERS.values())
        parts.append(Part("table", "Security headers by surface", columns, _surface_rows(ctx)))
    parts.append(Part("findings", "Fix list"))
    managed = [MANAGED_AUTH[p] for p in ctx.detection.auth_providers if p in MANAGED_AUTH]
    notes = ENUMERATION
    if managed:
        notes = (
            f"Password storage is delegated to {', '.join(managed)}. That check is delegated to "
            "the provider, not passed by this repository. " + ENUMERATION
        )
    parts.append(Part("text", "Password storage and account enumeration", body=notes))
    return ReviewSection("baseline", parts)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest -q`
Expected: PASS (all tests, including 9 new ones)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/reviews/headers_static.py src/dpr/reviews/baseline_headers.py src/dpr/reviews/baseline.py src/dpr/data/rule_text/baseline_headers.yaml tests/reviews/test_baseline_headers.py
git commit -m "Add per-surface security header checks, CSP strength, version disclosure and live header findings"
```

---
### Task 37: Committed account passwords, seeding on start, password length and CSRF

This task covers the two critical baseline findings of the comparison report (a migration and a seed that hash passwords written in the repository, and a start script that runs the seed on every deploy), plus a short password minimum and SameSite=None cookies with no CSRF defence anywhere.

A password literal is found by resolving the first argument of a password hashing call: a string constant, a name assigned a constant in the same function or at module level, `os.environ.get(NAME, DEFAULT)` or `os.getenv` with a constant default (reported as INFERRED, high), a `dict` item in a `for` loop over a module-level list of dict literals, or `.encode()` on any of those. The literal is never stored in a finding: the snippet masks it as `<redacted:password>`, and copies of it in other files (a README, a print statement, a smoke test) are found by comparing SHA-256 digests of same-length tokens and are added as extra locations. Test files are skipped.

**Files:**
- Create: `src/dpr/reviews/paths.py`, `src/dpr/parsing/pyvalues.py`, `src/dpr/reviews/baseline_accounts.py`, `src/dpr/data/rule_text/baseline_accounts.yaml`
- Modify: `src/dpr/reviews/baseline.py` (import the rule module)
- Test: `tests/reviews/test_baseline_accounts.py`, `tests/parsing/test_pyvalues.py`

**Interfaces:**
- Consumes: `Location`, `Tag` (Task 2); `rule`, `make_finding`, `Context` (Task 4); `line_of` (Task 5); `snippet` (Task 6); `jsts`, `pyast` (Tasks 7, 8); `review()` (Task 23); `render_json`, `render_markdown` (Tasks 24, 25)
- Produces:
  - `dpr.reviews.paths.is_test(rel: str) -> bool` (`tests/`, `__tests__/`, `spec/`, `fixtures/`, `e2e/`, `test_*.py`, `*_test.py`, `conftest.py`, `*.test.ts(x)`, `*.spec.js` and similar)
  - `dpr.parsing.pyvalues.Literal(value: str, env_fallback: bool = False)`; `resolve(tree: ast.Module, node: ast.AST | None, line: int) -> Literal | None`
  - `dpr.reviews.baseline_accounts.literal_password_sites(ctx) -> dict[str, list[tuple[int, Literal]]]`, cached in `ctx.facts["literal_password_sites"]` (in memory only, never rendered)
  - Registered rules (review `baseline`): `BASE-LITERAL-PASSWORD-HASH` (A07; CONFIRMED critical, or INFERRED high when every site is an environment fallback; one finding per file), `BASE-SEED-ON-START` (A05, INFERRED; critical with `refs` to `BASE-LITERAL-PASSWORD-HASH` when the seed module it starts hashes a committed literal, else high), `BASE-SHORT-PASSWORD-MIN` (A07, CONFIRMED low; `len(password) < N` in a password validator, `min_length=N` on a password field, Django `MinimumLengthValidator`, zod, yup or Joi `password: ... .min(N)`, for 2 <= N < 8), `BASE-SAMESITE-NONE-NO-CSRF` (A01, INFERRED low; a `samesite` setting of `none` in code or config and no CSRF package, no Django, and no `csrf` anywhere in non-test code)
- Start files for `BASE-SEED-ON-START`: `startup.sh`, `start.sh`, `entrypoint.sh`, `docker-entrypoint.sh`, `run.sh`, `boot.sh`, `prestart.sh` and `Procfile` (every command line), and `Dockerfile` `CMD`/`ENTRYPOINT`, `render.yaml` `startCommand`, `package.json` `start`/`prestart`/`poststart`/`predeploy`/`postdeploy` scripts, compose `command` and similar keyed lines. `echo` lines and comments are skipped. `python -m a.b.seed` resolves to `a/b/seed.py`, preferring a file under the start file's folder.

- [ ] **Step 1: Write the failing tests**

The two password strings that the output test checks for are joined at runtime, so the check compares against values that never appear whole in a committed file.

`tests/parsing/test_pyvalues.py`:

```python
import ast

from dpr.parsing.pyvalues import Literal, resolve
from dpr.reviews.paths import is_test

CODE = """
import os
TOP = 'alpha'
ITEMS = [{'name': 'x', 'secret': 'bravo'}]
def f(arg):
    local = 'charlie'
    use(local)
    use(TOP)
    use(os.getenv('X', 'delta'))
    use(arg)
    for item in ITEMS:
        use(item['secret'])
    use('echo'.encode())
    use(later)
    later = 'too late'
"""


def uses(tree):
    return [
        n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "use"
    ]


def test_resolve_literals():
    tree = ast.parse(CODE)
    values = [
        resolve(tree, call.args[0], call.lineno)
        for call in sorted(uses(tree), key=lambda c: c.lineno)
    ]
    assert values == [
        Literal("charlie"),
        Literal("alpha"),
        Literal("delta", env_fallback=True),
        None,
        Literal("bravo"),
        Literal("echo"),
        None,
    ]


def test_is_test_paths():
    for rel in (
        "tests/a.py",
        "app/test_x.py",
        "x_test.py",
        "conftest.py",
        "web/a.test.tsx",
        "src/__tests__/b.js",
    ):
        assert is_test(rel), rel
    for rel in ("app/testing_utils.py", "src/contest.ts", "latest/a.py"):
        assert not is_test(rel), rel
```

`tests/reviews/test_baseline_accounts.py`:

```python
from dpr.api import review
from dpr.report.json_out import render_json
from dpr.report.markdown import render_markdown
from tests.reviews.helpers import findings_for, write

SEED_PW = "Demo" + "Adm1n" + "#2031"
SHARED_PW = "Reset" + "Me" + "!2031"


def seed_app(root):
    write(root, "api/requirements.txt", "fastapi\n")
    write(
        root,
        "api/app/db/seed.py",
        "from app.core.security import get_password_hash\n"
        "async def seed_users(db):\n"
        f"    admin_pw = '{SEED_PW}'\n"
        "    db.add(User(email='admin@example.invalid', password_hash=get_password_hash(admin_pw)))\n"
        "    other = get_password_hash(data.password)\n",
    )
    write(
        root,
        "api/scripts/migrate.py",
        "from passlib.context import CryptContext\npwd_context = CryptContext(schemes=['bcrypt'])\n"
        f"PLACEHOLDER = '{SHARED_PW}'\nPLACEHOLDER_HASH = pwd_context.hash(PLACEHOLDER)\n",
    )
    write(
        root,
        "api/scripts/users.py",
        f"USERS = [{{'email': 'a@example.invalid', 'password': '{SEED_PW}'}}]\n"
        "def run():\n    for user in USERS:\n        make_password(user['password'])\n",
    )
    write(
        root,
        "api/app/db/demo_seed.py",
        "import os\nDEFAULT = 'Fallback' + 'Only'\n"
        f"DEFAULT_PW = '{SHARED_PW}x'\n"
        "def seed():\n    pw = os.environ.get('SEED_ADMIN_PASSWORD', DEFAULT_PW)\n"
        "    return get_password_hash(pw)\n",
    )
    write(root, "api/tests/test_security.py", "get_password_hash('password123')\n")
    write(root, "README.md", f"# App\n\nDemo login: admin@example.invalid / {SEED_PW}\n")
    write(
        root,
        "web/lib/users.js",
        "const bcrypt = require('bcrypt')\nconst hashed = bcrypt.hashSync('Str1ng-Pw-2031', 10)\n",
    )
    return root


def test_literal_password_hash(tmp_path):
    root = seed_app(tmp_path)
    found = {
        f.locations[0].file: f for f in findings_for(root, "baseline", "BASE-LITERAL-PASSWORD-HASH")
    }
    assert set(found) == {
        "api/app/db/demo_seed.py",
        "api/app/db/seed.py",
        "api/scripts/migrate.py",
        "api/scripts/users.py",
        "web/lib/users.js",
    }
    seed = found["api/app/db/seed.py"]
    assert (seed.tag.value, seed.severity.value) == ("CONFIRMED", "critical")
    assert [str(loc) for loc in seed.locations] == [
        "api/app/db/seed.py:4",
        "README.md:3",
        "api/scripts/users.py:1",
    ]
    assert "module level" in found["api/scripts/migrate.py"].detail
    fallback = found["api/app/db/demo_seed.py"]
    assert (fallback.tag.value, fallback.severity.value) == ("INFERRED", "high")
    assert fallback.proof_needed


def test_password_text_never_reaches_output(tmp_path):
    root = seed_app(tmp_path)
    write(root, "api/scripts/inline.py", f"h = get_password_hash('{SEED_PW}')\n")
    report = review(root)
    outputs = render_markdown(report) + render_json(report)
    assert SEED_PW not in outputs and SHARED_PW not in outputs
    inline = [
        f for f in report.findings if f.locations and f.locations[0].file == "api/scripts/inline.py"
    ]
    assert inline and "<redacted:password>" in inline[0].snippet


def test_seed_on_start(tmp_path):
    root = seed_app(tmp_path)
    write(
        root,
        "api/startup.sh",
        "#!/bin/bash\n# Seed reference data\necho 'Seeding...'\n"
        "PYTHONPATH=. python -m app.db.seed || echo done\ngunicorn app.main:app --workers 2\n",
    )
    write(
        root,
        "render.yaml",
        "services:\n  - startCommand: python -m other.seed && uvicorn app:app\n    buildCommand: pip install seed-lib\n",
    )
    write(
        root, "web/package.json", '{"scripts": {"start": "node server.js", "seed": "node seed.js"}}'
    )
    write(root, "worker/start.sh", "python -m app.db.demo_seed\n")
    found = sorted(
        findings_for(root, "baseline", "BASE-SEED-ON-START"), key=lambda f: str(f.locations[0])
    )
    assert [(str(f.locations[0]), f.severity.value) for f in found] == [
        ("api/startup.sh:4", "critical"),
        ("render.yaml:2", "high"),
        ("worker/start.sh:1", "high"),
    ]
    assert found[0].refs == ("BASE-LITERAL-PASSWORD-HASH",)
    assert found[0].tag.value == "INFERRED"


def test_short_password_minimum(tmp_path):
    write(
        tmp_path,
        "app/schemas.py",
        "from pydantic import BaseModel, Field, field_validator\n"
        "class AdminCreate(BaseModel):\n    password: str\n"
        "    @field_validator('password')\n    @classmethod\n    def check(cls, v):\n"
        "        if len(v) < 6:\n            raise ValueError('short')\n        return v\n"
        "class Signup(BaseModel):\n    password: str = Field(min_length=12)\n"
        "    @field_validator('password')\n    @classmethod\n    def check(cls, v):\n"
        "        if len(v) < 8:\n            raise ValueError('short')\n        return v\n"
        "class Reset(BaseModel):\n    new_password: str = Field(min_length=4)\n"
        "def name_check(name):\n    if len(name) < 3:\n        raise ValueError('x')\n",
    )
    write(
        tmp_path,
        "site/settings.py",
        "AUTH_PASSWORD_VALIDATORS = [\n    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',\n"
        "     'OPTIONS': {'min_length': 6}},\n]\n",
    )
    write(
        tmp_path,
        "web/schema.ts",
        "export const s = z.object({ email: z.string().min(3), password: z.string().min(6) })\n"
        "export const login = z.object({ password: z.string().min(1) })\n",
    )
    found = findings_for(tmp_path, "baseline", "BASE-SHORT-PASSWORD-MIN")
    assert sorted((str(f.locations[0]), f.title) for f in found) == [
        ("app/schemas.py:19", "Passwords can be as short as 4 characters"),
        ("app/schemas.py:7", "Passwords can be as short as 6 characters"),
        ("site/settings.py:2", "Passwords can be as short as 6 characters"),
        ("web/schema.ts:1", "Passwords can be as short as 6 characters"),
    ]


def test_samesite_none_without_csrf(tmp_path):
    write(
        tmp_path,
        "infra/main.tf",
        'resource "x" "y" {\n  app_settings = {\n    COOKIE_SAMESITE = "none"\n  }\n}\n',
    )
    write(
        tmp_path, "api/security.py", "def cookie():\n    return {'samesite': settings.samesite}\n"
    )
    [f] = findings_for(tmp_path, "baseline", "BASE-SAMESITE-NONE-NO-CSRF")
    assert str(f.locations[0]) == "infra/main.tf:3" and f.tag.value == "INFERRED"
    write(
        tmp_path,
        "api/csrf.py",
        "def verify_csrf(request):\n    return request.headers.get('x-csrf-token')\n",
    )
    assert findings_for(tmp_path, "baseline", "BASE-SAMESITE-NONE-NO-CSRF") == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/parsing/test_pyvalues.py tests/reviews/test_baseline_accounts.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'dpr.parsing.pyvalues'` during collection

- [ ] **Step 3: Write the helpers, the rules and the rule text**

`src/dpr/reviews/paths.py`:

```python
"""Path helpers shared by review rules."""

from __future__ import annotations

import re

TEST_PATH = re.compile(
    r"(?:^|/)(?:tests?|__tests__|specs?|fixtures?|e2e|cypress|__mocks__)/"
    r"|(?:^|/)test_[^/]*\.py$|_test\.py$|(?:^|/)conftest\.py$"
    r"|\.(?:test|spec)\.[cm]?[jt]sx?$"
)


def is_test(rel: str) -> bool:
    return bool(TEST_PATH.search(rel))
```

`src/dpr/parsing/pyvalues.py`:

```python
"""Resolve simple Python values to string literals: constants, names and env fallbacks."""

from __future__ import annotations

import ast
from dataclasses import dataclass

from dpr.parsing import pyast

ENV_GET = ("os.environ.get", "os.getenv", "environ.get", "getenv")


@dataclass(frozen=True)
class Literal:
    value: str
    env_fallback: bool = False


def _assigned(body: list[ast.stmt], name: str, before: int) -> ast.expr | None:
    found = None
    for stmt in body:
        if stmt.lineno >= before:
            break
        for node in ast.walk(stmt):
            if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == name for t in node.targets
            ):
                found = node.value
            elif (
                isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
                and node.target.id == name
                and node.value is not None
            ):
                found = node.value
    return found


def _loop_items(tree: ast.Module, fn: ast.AST | None, name: str, line: int) -> list[ast.expr]:
    for node in ast.walk(fn or tree):
        if (
            isinstance(node, ast.For)
            and isinstance(node.target, ast.Name)
            and node.target.id == name
            and node.lineno <= line <= (node.end_lineno or node.lineno)
        ):
            source = node.iter
            if isinstance(source, ast.Name):
                source = pyast.assignments(tree.body).get(source.id)
            if isinstance(source, ast.List | ast.Tuple):
                return list(source.elts)
    return []


def resolve(tree: ast.Module, node: ast.AST | None, line: int, depth: int = 0) -> Literal | None:
    if node is None or depth > 4:
        return None
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "encode":
            return resolve(tree, node.func.value, line, depth + 1)
    if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value:
        return Literal(node.value)
    if isinstance(node, ast.Call) and pyast.dotted(node.func) in ENV_GET and len(node.args) > 1:
        inner = resolve(tree, node.args[1], line, depth + 1)
        return Literal(inner.value, True) if inner else None
    fn = pyast.function_at(tree, line)
    if isinstance(node, ast.Name):
        value = _assigned(fn.body, node.id, line) if fn is not None else None
        if value is None:
            value = pyast.assignments(tree.body).get(node.id)
        return resolve(tree, value, line, depth + 1)
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
        key = pyast.constant(node.slice, None)
        for item in _loop_items(tree, fn, node.value.id, line):
            if isinstance(item, ast.Dict) and isinstance(key, str):
                for k, v in zip(item.keys, item.values, strict=True):
                    if pyast.constant(k, None) == key:
                        found = resolve(tree, v, line, depth + 1)
                        if found:
                            return found
    return None
```

`src/dpr/reviews/baseline_accounts.py`:

```python
"""Review 4, baseline: committed account passwords, seeding on start, password length, CSRF."""

from __future__ import annotations

import ast
import hashlib
import re
from collections.abc import Iterator
from pathlib import PurePosixPath

from dpr.model import Finding, Location, Tag
from dpr.parsing import jsts, pyast, pyvalues
from dpr.redact import snippet
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule
from dpr.walk import line_of

PY_HASH = re.compile(
    r"(?:[\w()]+\.)*(get_password_hash|hash_password|make_password|generate_password_hash"
    r"|hashpw|hash)"
)
HASHER_OWNER = re.compile(r"(?i)pwd|password|context|bcrypt|argon|hasher|crypt")
JS_HASH = re.compile(r"(?:\w+\.)*(hash|hashSync|hashPassword)")
START_FILES = (
    "startup.sh",
    "start.sh",
    "entrypoint.sh",
    "docker-entrypoint.sh",
    "run.sh",
    "boot.sh",
    "prestart.sh",
    "Procfile",
    "Dockerfile",
    "render.yaml",
    "fly.toml",
    "railway.json",
    "railway.toml",
    "app.yaml",
    "package.json",
    "docker-compose.yml",
    "docker-compose.yaml",
)
SEED_COMMAND = re.compile(
    r"(?i)(?:^|[\s/.:_-])seed(?:s|_\w+|\.py|\.js|\.ts)?(?=$|[\s.:_)\"'-])|\bloaddata\b"
)
START_LINE = re.compile(
    r"(?i)^\s*(?:-\s*)?(?:CMD|ENTRYPOINT|startCommand|releaseCommand|release_command|command|cmd"
    r"|\"(?:start|prestart|poststart|predeploy|postdeploy)\")\b"
)
TOKEN = re.compile(r"[^\s\"'`,;()\[\]{}<>]+")
SAMESITE_NONE = re.compile(r"""(?i)\b\w*same_?site\w*["']?\s*[:=]\s*["']none["']""")
CSRF_PACKAGES = {
    "fastapi-csrf-protect",
    "starlette-csrf",
    "csurf",
    "csrf-csrf",
    "lusca",
    "flask-wtf",
    "@edge-csrf/nextjs",
}
CONFIG_SUFFIXES = (".tf", ".yaml", ".yml", ".json", ".toml", ".py", ".ts", ".js", ".mjs", ".cjs")


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _py_hash_sites(tree: ast.Module) -> Iterator[tuple[ast.Call, pyvalues.Literal]]:
    for call in pyast.calls(tree, PY_HASH):
        name = pyast.dotted(call.func) or ""
        if name.split(".")[-1] == "hash" and not HASHER_OWNER.search(name):
            continue
        literal = pyvalues.resolve(tree, call.args[0] if call.args else None, call.lineno)
        if literal is not None:
            yield call, literal


def _js_hash_sites(ctx: Context, rel: str) -> Iterator[tuple[int, pyvalues.Literal]]:
    for tree in jsts.parse_file(ctx.index, rel):
        for call in jsts.calls(tree, JS_HASH):
            name = jsts.callee(call)
            if name.split(".")[-1] != "hashPassword" and not HASHER_OWNER.search(name):
                continue
            args = jsts.arguments(call)
            value = jsts.string_value(args[0]) if args else None
            if value is None and args and jsts.unwrap(args[0]).type == "identifier":
                resolved = jsts.resolve_identifier(jsts.unwrap(args[0]))
                value = jsts.string_value(resolved) if resolved is not None else None
            if value:
                yield jsts.line(tree, call), pyvalues.Literal(value)


def literal_password_sites(ctx: Context) -> dict[str, list[tuple[int, pyvalues.Literal]]]:
    """Files whose password hashing calls receive text written in the repository."""
    if "literal_password_sites" in ctx.facts:
        return ctx.facts["literal_password_sites"]
    sites: dict[str, list[tuple[int, pyvalues.Literal]]] = {}
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel) or not re.search(r"hash|password", text):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for call, literal in _py_hash_sites(tree) if tree else []:
            sites.setdefault(entry.rel, []).append((call.lineno, literal))
    for entry in ctx.index.js_files:
        if is_test(entry.rel) or "hash" not in ctx.index.text(entry.rel).lower():
            continue
        for line, literal in _js_hash_sites(ctx, entry.rel):
            sites.setdefault(entry.rel, []).append((line, literal))
    ctx.facts["literal_password_sites"] = sites
    return sites


def _copies(ctx: Context, owner: str, literals: list[pyvalues.Literal]) -> list[Location]:
    digests = {_digest(lit.value) for lit in literals}
    lengths = {len(lit.value) for lit in literals}
    found = []
    for entry in ctx.index.files:
        if entry.rel == owner:
            continue
        text = ctx.index.text(entry.rel)
        for match in TOKEN.finditer(text):
            token = match.group(0)
            if len(token) in lengths and _digest(token) in digests:
                found.append(Location(entry.rel, line_of(text, match.start())))
    return found


def _masked(text: str, line: int, literals: list[pyvalues.Literal]) -> str:
    value = snippet(text, line)
    for lit in literals:
        value = value.replace(lit.value, "<redacted:password>")
    return value


@rule(
    "BASE-LITERAL-PASSWORD-HASH",
    review="baseline",
    severity="critical",
    exploitability="high",
    owasp="A07",
)
def literal_password_hash(ctx: Context) -> Iterator[Finding]:
    for rel, sites in sorted(literal_password_sites(ctx).items()):
        literals = [lit for _, lit in sites]
        direct = [line for line, lit in sites if not lit.env_fallback]
        copies = _copies(ctx, rel, literals)
        lines = sorted({line for line, _ in sites})
        text = ctx.index.text(rel)
        shared = ""
        if rel.endswith(".py"):
            tree = pyast.parse_file(ctx.index, rel)
            if any(pyast.function_at(tree, line) is None for line in lines):
                shared = " The hash is computed once at module level and reused for every account."
        where = f" The same text also appears in {len(copies)} other place(s)." if copies else ""
        yield make_finding(
            "BASE-LITERAL-PASSWORD-HASH",
            tag=Tag.CONFIRMED if direct else Tag.INFERRED,
            locations=[*(Location(rel, n) for n in lines), *copies][:10],
            severity="critical" if direct else "high",
            snippet=_masked(text, lines[0], literals),
            proof_needed=None
            if direct
            else "Check that the environment variable is set in every deployed environment.",
            file=rel,
            count=len(lines),
            extra=shared + where,
        )


def _seed_target(ctx: Context, start: str, line: str) -> list[str]:
    module = re.search(r"-m\s+([\w.]*seed\w*)", line)
    script = re.search(r"([\w./-]*seed\w*\.(?:py|js|ts|mjs))", line)
    suffix = (
        module.group(1).replace(".", "/") + ".py" if module else (script.group(1) if script else "")
    )
    if not suffix:
        return []
    matches = [f.rel for f in ctx.index.files if f.rel.endswith(suffix.lstrip("./"))]
    folder = str(PurePosixPath(start).parent)
    local = [m for m in matches if folder == "." or m.startswith(folder + "/")]
    return local or matches


@rule("BASE-SEED-ON-START", review="baseline", severity="high", exploitability="high", owasp="A05")
def seed_on_start(ctx: Context) -> Iterator[Finding]:
    sites = literal_password_sites(ctx)
    for entry in ctx.index.named(*START_FILES):
        text = ctx.index.text(entry.rel)
        shell = entry.name.endswith(".sh") or entry.name == "Procfile"
        for number, raw in enumerate(text.splitlines(), start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith(("#", "echo ", "//")):
                continue
            if not shell and not START_LINE.search(raw):
                continue
            if not SEED_COMMAND.search(stripped):
                continue
            targets = _seed_target(ctx, entry.rel, stripped)
            with_passwords = [
                t for t in targets if any(not lit.env_fallback for _, lit in sites.get(t, []))
            ]
            detail = (
                f" The seed file {with_passwords[0]} hashes passwords written in the repository."
                if with_passwords
                else ""
            )
            yield make_finding(
                "BASE-SEED-ON-START",
                tag=Tag.INFERRED,
                locations=[Location(entry.rel, number)],
                severity="critical" if with_passwords else "high",
                snippet=snippet(text, number),
                refs=("BASE-LITERAL-PASSWORD-HASH",) if with_passwords else (),
                start=entry.rel,
                extra=detail,
            )


def _py_short_minimums(tree: ast.Module) -> Iterator[tuple[int, int]]:
    for fn in pyast.functions(tree):
        decorators = " ".join(ast.unparse(d) for d in fn.decorator_list)
        if "password" not in (fn.name + decorators).lower():
            continue
        for node in ast.walk(fn):
            if not (isinstance(node, ast.Compare) and len(node.ops) == 1):
                continue
            left, right = node.left, node.comparators[0]
            if not (isinstance(left, ast.Call) and pyast.dotted(left.func) == "len"):
                continue
            limit = pyast.constant(right, None)
            if not isinstance(limit, int):
                continue
            minimum = limit if isinstance(node.ops[0], ast.Lt) else limit + 1
            if isinstance(node.ops[0], ast.Lt | ast.LtE) and 2 <= minimum < 8:
                yield node.lineno, minimum
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if "password" in node.target.id.lower():
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Call):
                        value = pyast.constant(pyast.kwarg(sub, "min_length"), None)
                        if isinstance(value, int) and 2 <= value < 8:
                            yield node.lineno, value
        if isinstance(node, ast.Dict):
            text = ast.unparse(node)
            match = re.search(r"MinimumLengthValidator.*'min_length':\s*(\d+)", text)
            if match and 2 <= int(match.group(1)) < 8:
                yield node.lineno, int(match.group(1))


@rule(
    "BASE-SHORT-PASSWORD-MIN", review="baseline", severity="low", exploitability="low", owasp="A07"
)
def short_password_minimum(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel) or "password" not in text.lower():
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for line, minimum in sorted(set(_py_short_minimums(tree))) if tree else []:
            yield make_finding(
                "BASE-SHORT-PASSWORD-MIN",
                tag=Tag.CONFIRMED,
                locations=[Location(entry.rel, line)],
                snippet=snippet(text, line),
                minimum=minimum,
            )
    for entry in ctx.index.js_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel):
            continue
        for match in re.finditer(r"(?i)password\w*['\"]?\s*:\s*[\w.()]*?\.min\(\s*(\d+)", text):
            if 2 <= int(match.group(1)) < 8:
                line = line_of(text, match.start())
                yield make_finding(
                    "BASE-SHORT-PASSWORD-MIN",
                    tag=Tag.CONFIRMED,
                    locations=[Location(entry.rel, line)],
                    snippet=snippet(text, line),
                    minimum=int(match.group(1)),
                )


def _has_csrf_defence(ctx: Context) -> bool:
    if CSRF_PACKAGES & ctx.detection.packages or "django" in ctx.detection.frameworks:
        return True
    return any(
        "csrf" in ctx.index.text(f.rel).lower()
        for f in [*ctx.index.js_files, *ctx.index.py_files]
        if not is_test(f.rel)
    )


@rule(
    "BASE-SAMESITE-NONE-NO-CSRF",
    review="baseline",
    severity="low",
    exploitability="medium",
    owasp="A01",
)
def samesite_none_without_csrf(ctx: Context) -> Iterator[Finding]:
    found = []
    for entry in ctx.index.files:
        if not entry.rel.endswith(CONFIG_SUFFIXES) or is_test(entry.rel):
            continue
        text = ctx.index.text(entry.rel)
        found += [
            Location(entry.rel, line_of(text, m.start())) for m in SAMESITE_NONE.finditer(text)
        ]
    if found and not _has_csrf_defence(ctx):
        yield make_finding(
            "BASE-SAMESITE-NONE-NO-CSRF",
            tag=Tag.INFERRED,
            locations=found[:5],
            snippet=snippet(ctx.index.text(found[0].file), found[0].line),
        )
```

`src/dpr/data/rule_text/baseline_accounts.yaml`:

```yaml
BASE-LITERAL-PASSWORD-HASH:
  title: Account passwords are written in ${file}
  effort_minutes: 10
  detail: ${count} password hashing call(s) in ${file} hash text that is written in the repository, so every account created this way has a password anyone with repository access can read.${extra} The password itself is not printed here.
  proof_needed: Check whether the environment variable is set in every deployed environment.
  attack: Read the password from the repository or any clone, then sign in to each account the script created, one attempt per account so lockouts never trigger.
  blast: Every account whose password was never changed after it was created, including admin accounts.
  fix: |-
    Treat the password as burned. Replace every stored hash that still matches it with an unusable value (for example a hash of a random value), invalidate existing sessions, and have owners set a password through reset.
    Change the code to generate a random per-account password or create accounts in a pending state that requires a reset link. Remove the password from every file where it also appears.
  verify: Sign in with the committed password against a copy of production data and confirm it is rejected for every account.
BASE-SEED-ON-START:
  title: Start command runs a seed script
  effort_minutes: 10
  detail: ${start} runs a seed step every time the app starts, so whatever the seed creates exists in every environment that uses this command, including production.${extra}
  proof_needed: Check whether this start command is the one production uses, and what the seed creates when the data is missing.
  attack: Use the demo or default accounts the seed creates, with the credentials written in the seed file or the README.
  blast: Every account and record the seed creates, in every environment that runs this start command.
  fix: Seed only reference data at start, or guard the seed so it refuses to create users outside local development. In production, change or disable any account the seed already created.
  verify: Start the app with the production environment setting and confirm no user rows are created.
BASE-SHORT-PASSWORD-MIN:
  title: Passwords can be as short as ${minimum} characters
  effort_minutes: 10
  detail: A password check here accepts ${minimum} characters. Short passwords fall to guessing and credential stuffing.
  attack: Try common short passwords against accounts created through this path.
  blast: Accounts that chose a password at the minimum length.
  fix: Require at least 12 characters (8 as an absolute floor), drop composition rules, and check new passwords against a breached-password list.
  verify: Try to set a 7-character password through this path and confirm it is rejected.
BASE-SAMESITE-NONE-NO-CSRF:
  title: Cookies are sent cross-site with no CSRF defence found
  effort_minutes: 30
  detail: SameSite is set to None, so browsers attach the auth cookie to requests started by other sites, and no CSRF token, CSRF library or csrf check was found anywhere in the code.
  proof_needed: Check whether state-changing routes accept cookie authentication without a custom header, token or Origin check.
  attack: Host a page that submits a form or fetch to a state-changing route; a signed-in visitor's browser sends the cookie and the action runs as them.
  blast: Every state-changing action reachable with cookie authentication.
  fix: Use SameSite=Lax where the frontend and API share a site. If None is required, reject state-changing requests authenticated by cookie unless the Origin header is in the allowlist, or require a CSRF token or the Authorization header for them.
  verify: From another origin, submit a form POST to a state-changing route with a valid session cookie and confirm a 403.
```

Modify `src/dpr/reviews/baseline.py`, replace:

```python
import dpr.reviews.baseline_config  # noqa: F401  (registers rules)
```

with:

```python
import dpr.reviews.baseline_accounts  # noqa: F401  (registers rules)
import dpr.reviews.baseline_config  # noqa: F401  (registers rules)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest -q`
Expected: PASS (all tests, including 7 new ones)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/reviews/paths.py src/dpr/parsing/pyvalues.py src/dpr/reviews/baseline_accounts.py src/dpr/reviews/baseline.py src/dpr/data/rule_text/baseline_accounts.yaml tests/reviews/test_baseline_accounts.py tests/parsing/test_pyvalues.py
git commit -m "Report committed account passwords, seeding on start, short password minimums and SameSite None without CSRF"
```

---
### Task 38: Terraform database exposure, admin connection strings and HTTPS enforcement

**Files:**
- Create: `src/dpr/parsing/hcl.py`, `src/dpr/reviews/baseline_infra.py`, `src/dpr/data/rule_text/baseline_infra.yaml`
- Modify: `src/dpr/reviews/baseline.py` (import the rule module)
- Test: `tests/parsing/test_hcl.py`, `tests/reviews/test_baseline_infra.py`

**Interfaces:**
- Consumes: `Location`, `Tag` (Task 2); `rule`, `make_finding`, `Context` (Task 4); `RepoIndex.with_suffix`, `line_of` (Task 5); `snippet` (Task 6)
- Produces:
  - `dpr.parsing.hcl`: `Block(kind: str, labels: tuple[str, ...], line: int, body: str, body_line: int)`; `blocks(text) -> list[Block]` (top-level blocks, braces inside strings, `${...}` interpolation and comments ignored); `attributes(block) -> dict[str, tuple[str, int]]` (top-level `name = value` pairs with their line); `unquote(value) -> str`
  - Registered rules (review `baseline`):
    - `BASE-DB-NETWORK-OPEN` (A05, CONFIRMED): Azure database firewall rule `0.0.0.0` to `0.0.0.0` (medium, any Azure tenant) or to `255.255.255.255` (high); AWS security group allowing `0.0.0.0/0` to a database port (high); `aws_db_instance` with `publicly_accessible = true` (medium); Cloud SQL authorized network `0.0.0.0/0` (high)
    - `BASE-DB-ADMIN-LOGIN` (A05, INFERRED medium): a connection string in Terraform built as `://${<expression with admin, master, root, superuser or administrator_login>}:`
    - `BASE-HTTPS-NOT-ENFORCED` (A02, CONFIRMED low): Azure web and function apps without `https_only = true`, CloudFront `viewer_protocol_policy = "allow-all"`, an HTTP load balancer listener without a redirect

- [ ] **Step 1: Write the failing tests**

`tests/parsing/test_hcl.py`:

```python
from dpr.parsing.hcl import attributes, blocks, unquote

TF = """
terraform {
  required_version = ">= 1.5"
}

resource "azurerm_linux_web_app" "api" {
  name = "${var.project}-api-${var.env == "prod" ? "p" : "d"}"
  site_config {
    https_only = false
  }
  app_settings = {
    URL = "https://${azurerm_static_web_app.web.default_host_name}"
  }
  https_only = true # comment with a } brace
}

# resource "commented" "out" {
resource "azurerm_postgresql_flexible_server_firewall_rule" "azure" {
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}
"""


def test_blocks_labels_and_lines():
    found = blocks(TF)
    assert [(b.kind, b.labels, b.line) for b in found] == [
        ("terraform", (), 2),
        ("resource", ("azurerm_linux_web_app", "api"), 6),
        ("resource", ("azurerm_postgresql_flexible_server_firewall_rule", "azure"), 18),
    ]


def test_top_level_attributes_only():
    web = blocks(TF)[1]
    attrs = attributes(web)
    assert attrs["https_only"] == ("true", 14)
    assert "URL" not in attrs
    assert unquote(attrs["name"][0]).startswith("${var.project}")
    rule = attributes(blocks(TF)[2])
    assert (unquote(rule["start_ip_address"][0]), rule["end_ip_address"][1]) == ("0.0.0.0", 20)
```

`tests/reviews/test_baseline_infra.py`:

```python
from tests.reviews.helpers import findings_for, write

AZURE = """
resource "azurerm_postgresql_flexible_server_firewall_rule" "allow_azure" {
  name             = "AllowAzureServices"
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}
resource "azurerm_postgresql_flexible_server_firewall_rule" "office" {
  start_ip_address = "203.0.113.10"
  end_ip_address   = "203.0.113.10"
}
resource "azurerm_mysql_flexible_server_firewall_rule" "everyone" {
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"
}
resource "azurerm_key_vault_secret" "database_url" {
  value = "postgresql://${var.db_admin_username}:${var.db_admin_password}@${azurerm_postgresql_flexible_server.main.fqdn}/app"
}
resource "azurerm_key_vault_secret" "app_url" {
  value = "postgresql://${var.app_db_user}:${var.app_db_password}@db/app"
}
resource "azurerm_linux_web_app" "api" {
  name = "api"
  site_config {
    always_on = true
  }
}
resource "azurerm_linux_web_app" "safe" {
  https_only = true
}
"""

AWS = """
resource "aws_security_group" "db" {
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_security_group" "web" {
  ingress {
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_db_instance" "main" {
  engine              = "postgres"
  publicly_accessible = true
}
resource "aws_cloudfront_distribution" "cdn" {
  default_cache_behavior {
    viewer_protocol_policy = "allow-all"
  }
}
resource "aws_lb_listener" "http" {
  protocol = "HTTP"
  default_action {
    type = "redirect"
  }
}
"""


def test_database_network_rules(tmp_path):
    write(tmp_path, "infra/azure.tf", AZURE)
    write(tmp_path, "infra/aws.tf", AWS)
    found = findings_for(tmp_path, "baseline", "BASE-DB-NETWORK-OPEN")
    assert sorted((str(f.locations[0]), f.severity.value) for f in found) == [
        ("infra/aws.tf:19", "medium"),
        ("infra/aws.tf:2", "high"),
        ("infra/azure.tf:11", "high"),
        ("infra/azure.tf:2", "medium"),
    ]
    assert all(f.tag.value == "CONFIRMED" for f in found)


def test_admin_login_connection_string(tmp_path):
    write(tmp_path, "infra/azure.tf", AZURE)
    [f] = findings_for(tmp_path, "baseline", "BASE-DB-ADMIN-LOGIN")
    assert str(f.locations[0]) == "infra/azure.tf:16"
    assert "var.db_admin_username" in f.detail and f.proof_needed


def test_https_not_enforced(tmp_path):
    write(tmp_path, "infra/azure.tf", AZURE)
    write(tmp_path, "infra/aws.tf", AWS)
    found = findings_for(tmp_path, "baseline", "BASE-HTTPS-NOT-ENFORCED")
    assert sorted(str(f.locations[0]) for f in found) == ["infra/aws.tf:21", "infra/azure.tf:21"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/parsing/test_hcl.py tests/reviews/test_baseline_infra.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'dpr.parsing.hcl'` during collection

- [ ] **Step 3: Write the parser, the rules and the rule text**

`src/dpr/parsing/hcl.py`:

```python
"""Just enough HCL for Terraform checks: top-level blocks and their top-level attributes."""

from __future__ import annotations

import re
from dataclasses import dataclass

HEAD = re.compile(r'^([A-Za-z_][\w-]*)((?:\s+"[^"]*")*)\s*\{', re.MULTILINE)
ATTRIBUTE = re.compile(r"^\s*([A-Za-z_][\w-]*)\s*=\s*(.*?)\s*$")


@dataclass(frozen=True)
class Block:
    kind: str
    labels: tuple[str, ...]
    line: int
    body: str
    body_line: int


def _block_end(text: str, start: int) -> int:
    """Index just past the brace that closes the block opened at text[start - 1]."""
    depth, i, stack = 1, start, []
    while i < len(text):
        ch = text[i]
        mode = stack[-1] if stack else "code"
        if mode == "string":
            if ch == "\\":
                i += 2
                continue
            if text.startswith("${", i):
                stack.append("interp")
                i += 2
                continue
            if ch == '"':
                stack.pop()
        elif text.startswith("#", i) or text.startswith("//", i):
            end = text.find("\n", i)
            i = len(text) if end == -1 else end
            continue
        elif ch == '"':
            stack.append("string")
        elif ch == "{":
            if mode == "interp":
                stack.append("interp")
            else:
                depth += 1
        elif ch == "}":
            if mode == "interp":
                stack.pop()
            else:
                depth -= 1
                if depth == 0:
                    return i + 1
        i += 1
    return len(text)


def blocks(text: str) -> list[Block]:
    found = []
    position = 0
    while True:
        match = HEAD.search(text, position)
        if match is None:
            return found
        end = _block_end(text, match.end())
        labels = tuple(re.findall(r'"([^"]*)"', match.group(2)))
        line = text.count("\n", 0, match.start()) + 1
        body = text[match.end() : end - 1]
        body_line = text.count("\n", 0, match.end()) + 1
        found.append(Block(match.group(1), labels, line, body, body_line))
        position = end


def attributes(block: Block) -> dict[str, tuple[str, int]]:
    """Top-level `name = value` pairs of a block, with the line of each."""
    found: dict[str, tuple[str, int]] = {}
    depth = 0
    for offset, raw in enumerate(block.body.split("\n")):
        line = raw.split("#", 1)[0]
        if depth == 0:
            match = ATTRIBUTE.match(line)
            if match:
                found[match.group(1)] = (match.group(2), block.body_line + offset)
        depth += line.count("{") - line.count("}")
        depth = max(depth, 0)
    return found


def unquote(value: str) -> str:
    value = value.strip()
    return value[1:-1] if len(value) >= 2 and value[0] == value[-1] == '"' else value
```

`src/dpr/reviews/baseline_infra.py`:

```python
"""Review 4, baseline: infrastructure as code, database network exposure and HTTPS enforcement."""

from __future__ import annotations

import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Tag
from dpr.parsing import hcl
from dpr.redact import snippet
from dpr.rules import Context, make_finding, rule
from dpr.walk import line_of

AZURE_DB_FIREWALL = re.compile(
    r"azurerm_(?:postgresql|mysql|mariadb|mssql|sql|cosmosdb)\w*firewall_rule"
)
AWS_INGRESS = (
    "aws_security_group",
    "aws_security_group_rule",
    "aws_vpc_security_group_ingress_rule",
)
DB_PORTS = {5432, 3306, 1433, 27017, 6379, 9200, 5984, 26257}
OPEN_CIDR = re.compile(r'"0\.0\.0\.0/0"')
AZURE_WEB_APPS = re.compile(
    r"azurerm_(?:linux_web_app|windows_web_app|app_service|linux_function_app"
    r"|windows_function_app|function_app)"
)
ADMIN_URL = re.compile(
    r"://\$\{([^}]*(?:admin|master|root|superuser|administrator_login)[^}]*)\}:", re.IGNORECASE
)


def _terraform(ctx: Context) -> Iterator[tuple[str, str, hcl.Block]]:
    for entry in ctx.index.with_suffix(".tf"):
        text = ctx.index.text(entry.rel)
        for block in hcl.blocks(text):
            if block.kind == "resource" and len(block.labels) == 2:
                yield entry.rel, text, block


def _ports(block: hcl.Block) -> set[int]:
    numbers = set()
    for match in re.finditer(r"\b(from_port|to_port)\s*=\s*(\d+)", block.body):
        numbers.add(int(match.group(2)))
    if len(numbers) == 2:
        low, high = sorted(numbers)
        return {p for p in DB_PORTS if low <= p <= high}
    return numbers & DB_PORTS


def _open(rel: str, text: str, line: int, severity: str, what: str) -> Finding:
    return make_finding(
        "BASE-DB-NETWORK-OPEN",
        tag=Tag.CONFIRMED,
        locations=[Location(rel, line)],
        severity=severity,
        snippet=snippet(text, line),
        what=what,
    )


@rule(
    "BASE-DB-NETWORK-OPEN",
    review="baseline",
    severity="medium",
    exploitability="medium",
    owasp="A05",
)
def db_network_open(ctx: Context) -> Iterator[Finding]:
    for rel, text, block in _terraform(ctx):
        kind, name = block.labels
        attrs = hcl.attributes(block)
        if AZURE_DB_FIREWALL.fullmatch(kind):
            start = hcl.unquote(attrs.get("start_ip_address", ("", 0))[0])
            end = hcl.unquote(attrs.get("end_ip_address", ("", 0))[0])
            if start == "0.0.0.0" and end == "0.0.0.0":
                what = (
                    f"Firewall rule {name} opens 0.0.0.0 to 0.0.0.0, which admits connections "
                    "from any Azure-hosted service, including other customers' tenants."
                )
                yield _open(rel, text, block.line, "medium", what)
            elif start == "0.0.0.0" and end == "255.255.255.255":
                what = f"Firewall rule {name} admits every IPv4 address on the internet."
                yield _open(rel, text, block.line, "high", what)
        elif kind in AWS_INGRESS and OPEN_CIDR.search(block.body) and _ports(block):
            ports = ", ".join(str(p) for p in sorted(_ports(block)))
            what = f"Security group {name} allows 0.0.0.0/0 to database port(s) {ports}."
            yield _open(rel, text, block.line, "high", what)
        elif kind in ("aws_db_instance", "aws_rds_cluster_instance"):
            value, line = attrs.get("publicly_accessible", ("", 0))
            if value.strip() == "true":
                what = f"Database instance {name} is publicly accessible."
                yield _open(rel, text, line, "medium", what)
        elif kind == "google_sql_database_instance" and OPEN_CIDR.search(block.body):
            line = block.body_line + block.body[: OPEN_CIDR.search(block.body).start()].count("\n")
            what = f"Cloud SQL instance {name} has 0.0.0.0/0 as an authorized network."
            yield _open(rel, text, line, "high", what)


@rule(
    "BASE-DB-ADMIN-LOGIN",
    review="baseline",
    severity="medium",
    exploitability="medium",
    owasp="A05",
)
def db_admin_login(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.with_suffix(".tf"):
        text = ctx.index.text(entry.rel)
        for match in ADMIN_URL.finditer(text):
            line = line_of(text, match.start())
            yield make_finding(
                "BASE-DB-ADMIN-LOGIN",
                tag=Tag.INFERRED,
                locations=[Location(entry.rel, line)],
                snippet=snippet(text, line),
                login=match.group(1),
            )


@rule(
    "BASE-HTTPS-NOT-ENFORCED",
    review="baseline",
    severity="low",
    exploitability="low",
    owasp="A02",
)
def https_not_enforced(ctx: Context) -> Iterator[Finding]:
    for rel, text, block in _terraform(ctx):
        kind, name = block.labels
        attrs = hcl.attributes(block)
        what = None
        line = block.line
        if AZURE_WEB_APPS.fullmatch(kind) and attrs.get("https_only", ("",))[0] != "true":
            what = f"{kind} {name} does not set https_only = true, so plain HTTP is served."
        elif kind == "aws_cloudfront_distribution" and re.search(
            r'viewer_protocol_policy\s*=\s*"allow-all"', block.body
        ):
            what = f"CloudFront distribution {name} allows plain HTTP viewers (allow-all)."
        elif kind == "aws_lb_listener" and re.search(r'protocol\s*=\s*"HTTP"', block.body):
            if "redirect" not in block.body:
                what = f"Load balancer listener {name} serves HTTP without a redirect to HTTPS."
        if what:
            yield make_finding(
                "BASE-HTTPS-NOT-ENFORCED",
                tag=Tag.CONFIRMED,
                locations=[Location(rel, line)],
                snippet=snippet(text, line),
                what=what,
            )
```

`src/dpr/data/rule_text/baseline_infra.yaml`:

```yaml
BASE-DB-NETWORK-OPEN:
  title: Database network access is open wider than the app needs
  effort_minutes: 30
  detail: ${what} The database password is then the only barrier.
  attack: Reach the database port from the admitted network and try the credentials, or use any leaked or default database password directly.
  blast: Every table in the database, with the rights of whichever login is used.
  fix: Remove the rule. Use private networking (VNet integration or private endpoints, a private subnet, private IP) for the app, or allow only the app's outbound addresses.
  verify: List the firewall or security group rules for the server and confirm no 0.0.0.0 rule remains.
BASE-DB-ADMIN-LOGIN:
  title: App connection string uses the database admin login
  effort_minutes: 45
  detail: A connection string is built from ${login}, which looks like the server administrator login. An injection bug or a leaked app setting then gives owner rights over every table, including DDL.
  proof_needed: Run select current_user through the deployed app's connection string and compare it with the administrator login.
  blast: Every table, schema change and role in the database.
  fix: Create a least-privilege role for the app with only select, insert, update and delete on its tables, point the app's connection string at it, and keep the admin login for migrations in the deploy pipeline.
  verify: Through the app's connection string, run select current_user and confirm it is not the administrator login.
BASE-HTTPS-NOT-ENFORCED:
  title: HTTPS is not enforced by the infrastructure
  effort_minutes: 5
  detail: ${what}
  attack: Send a victim a plain http:// link to the host and read or change the unencrypted traffic on a hostile network.
  blast: Requests and responses on the plain HTTP path, including cookies without the Secure flag.
  fix: Set https_only = true on Azure App Service and Function Apps, viewer_protocol_policy = "redirect-to-https" on CloudFront, or a redirect action on HTTP load balancer listeners.
  verify: curl -sSI http://your-host/ and confirm a 301 to https://.
```

Modify `src/dpr/reviews/baseline.py`, replace:

```python
import dpr.reviews.baseline_config  # noqa: F401  (registers rules)
```

with:

```python
import dpr.reviews.baseline_config  # noqa: F401  (registers rules)
import dpr.reviews.baseline_infra  # noqa: F401  (registers rules)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest -q`
Expected: PASS (all tests, including 5 new ones)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/parsing/hcl.py src/dpr/reviews/baseline_infra.py src/dpr/reviews/baseline.py src/dpr/data/rule_text/baseline_infra.yaml tests/parsing/test_hcl.py tests/reviews/test_baseline_infra.py
git commit -m "Report open database networks, admin connection strings and unenforced HTTPS in Terraform"
```

---
### Task 39: OWASP A01 record lookups, guessable IDs, unguarded methods and email ownership

The A01 signature is a route that checks who you are but never checks whether the record belongs to you. A lookup is any ORM call in a route handler whose arguments use a request identifier: a path parameter, or a query parameter named `id` or `*_id` (form and body fields are not identifiers). Python lookups are `select(...).where/filter/filter_by`, `.objects.*`, `get_object_or_404`, `session.get` and `Model.query.get`; JS lookups are Prisma `findUnique/findFirst/update/delete/upsert` and Mongoose `findById/findOne`.

A lookup is scoped when the lookup expression itself names the caller (the access subjects from Task 33, plus local names assigned from them). An unscoped lookup is cleared when a later comparison, or a later non-logging call, uses both the caller and the loaded record (following the record through reassignment such as `client = result.scalar_one_or_none()`). A later call that receives only the caller makes the finding INFERRED. Once one lookup keyed by an identifier is ownership-checked, later lookups keyed by the same identifier count as checked too.

When the handler passes the identifier (and not the caller) to a helper, the helper is resolved by name, up to two levels deep: a method call resolves to methods, a plain call to functions, the handler itself is excluded, and when a name repeats the definition in the file sharing the longest path prefix wins (a tie means unresolved, and nothing is reported). A helper that takes a user, owner or tenant parameter counts as scoped. The finding then points at the handler line and at the helper's query.

Only records that belong to someone are reported. A model counts as owned when it is user-like (`user`, `profile`, `account`, `customer`, `member`), has an owner or tenant column (`user_id`, `owner_id`, `created_by`, `author_id`, `profile_id`, `uploaded_by(_id)`, `manager_id`, `account_id`, `customer_id`, `client_id`, `member_id`, `org_id`, `organization_id`, `tenant_id`, `workspace_id`, `team_id`, `company_id`), or has a `<parent>_id` column pointing at an owned model. A model that is found but owns nothing (reference data) is skipped. An unknown model gives an INFERRED finding. Admin routes and test files are skipped.

**Files:**
- Create: `src/dpr/reviews/lookups.py`, `src/dpr/reviews/owasp_a01.py`, `src/dpr/data/rule_text/owasp_a01.yaml`
- Modify: `src/dpr/reviews/owasp.py` (import the rule module)
- Test: `tests/reviews/test_owasp_a01.py`

**Interfaces:**
- Consumes: `Location`, `Route`, `DataModel`, `Tag` (Task 2); `rule`, `make_finding`, `Context` (Task 4); `snippet` (Task 6); `jsts`, `pyast` (Tasks 7, 8); `find_model` (Task 12); `access`, `path_params`, `Access`, `ADMIN`, `PUBLIC` (Task 33); `is_test` (Task 37)
- Produces:
  - `dpr.reviews.lookups`: `Lookup(location, keys, model, by_primary_key, target, via=None)`; `snake(name)`; `model_for(ctx, name) -> DataModel | None`; `owned(ctx, name) -> bool | None`; `request_keys(route) -> set[str]`; `helper_index(ctx)`; `py_lookups(ctx, rel, fn, keys, subjects, depth=0) -> list[Lookup]`; `py_checked_after(fn, lookup, subjects) -> str`; `js_keys(handler) -> set[str]`; `js_lookups(route, subjects) -> list[Lookup]`; `js_checked_after(route, lookup, subjects) -> str`; `route_lookups(ctx, route, access) -> list[tuple[Lookup, str]]` (check is `"owner"`, `"helper"` or `""`); `OWNER_COLUMNS`, `USER_MODELS`
  - `dpr.reviews.owasp_a01.unscoped(ctx) -> list[tuple[Route, list[Lookup], str]]`, cached in `ctx.facts["unscoped_lookups"]` (Task 43's route table reads it)
  - Registered rules (review `owasp`, owasp A01): `OWASP-A01-UNSCOPED-QUERY` (high; CONFIRMED with a visible filter, a known model and no later check, else INFERRED; one finding per route listing every unscoped lookup), `OWASP-A01-GUESSABLE-ID` (medium, CONFIRMED; a primary key lookup on an owned model whose `id` is auto-increment, with the model field as the second location), `OWASP-A01-UNGUARDED-METHOD` (high, CONFIRMED; a public write method on a file and path where another method requires a caller), `OWASP-A01-EMAIL-OWNERSHIP` (high, INFERRED; a non-user model matched by `Model.email == user.email` in Python or `where: { email: session.user.email }` in Prisma)

- [ ] **Step 1: Write the failing tests**

`tests/reviews/test_owasp_a01.py`:

```python
from tests.reviews.helpers import findings_for, write

MODELS = (
    "from sqlalchemy import Column, ForeignKey, Integer, String\n"
    "class Attachment(Base):\n    __tablename__ = 'attachments'\n"
    "    id = Column(String, primary_key=True)\n    uploaded_by_id = Column(String)\n"
    "class Note(Base):\n    __tablename__ = 'notes'\n"
    "    id = Column(String, primary_key=True)\n    attachment_id = Column(String, ForeignKey('attachments.id'))\n"
    "class Country(Base):\n    __tablename__ = 'countries'\n    id = Column(Integer, primary_key=True)\n"
)
DEPS = (
    "from typing import Annotated\nfrom fastapi import Depends\n"
    "CurrentUser = Annotated[dict, Depends(get_current_user)]\n"
    "AdminUser = Annotated[dict, Depends(get_admin_user)]\n"
)


def fastapi_app(root):
    write(root, "api/app/models.py", MODELS)
    write(root, "api/app/deps.py", DEPS)
    write(
        root,
        "api/app/service.py",
        "class AttachmentService:\n    def __init__(self, db):\n        self.db = db\n"
        "    async def get_attachment(self, attachment_id):\n"
        "        return await self.db.execute(select(Attachment).where(Attachment.id == attachment_id))\n"
        "    async def get_for_user(self, attachment_id, user):\n"
        "        return await self.db.execute(select(Attachment).where(Attachment.id == attachment_id))\n",
    )
    write(
        root,
        "api/app/routes.py",
        "from fastapi import APIRouter, Form, Query\nfrom app.deps import AdminUser, CurrentUser\n"
        "router = APIRouter(prefix='/files')\n"
        "@router.get('/{attachment_id}')\n"
        "async def direct(attachment_id: str, current_user: CurrentUser, db=Depends(get_db)):\n"
        "    result = await db.execute(select(Attachment).where(Attachment.id == attachment_id))\n"
        "    return result.scalar_one_or_none()\n"
        "@router.get('/{attachment_id}/mine')\n"
        "async def scoped(attachment_id: str, current_user: CurrentUser, db=Depends(get_db)):\n"
        "    return await db.execute(select(Attachment).where(\n"
        "        Attachment.id == attachment_id, Attachment.uploaded_by_id == current_user.id))\n"
        "@router.get('/{attachment_id}/checked')\n"
        "async def checked(attachment_id: str, current_user: CurrentUser, db=Depends(get_db)):\n"
        "    result = await db.execute(select(Attachment).where(Attachment.id == attachment_id))\n"
        "    item = result.scalar_one_or_none()\n"
        "    if item.uploaded_by_id != current_user.id:\n        raise HTTPException(404)\n"
        "@router.get('/{attachment_id}/helper')\n"
        "async def helper(attachment_id: str, current_user: CurrentUser, db=Depends(get_db)):\n"
        "    result = await db.execute(select(Attachment).where(Attachment.id == attachment_id))\n"
        "    audit(current_user)\n"
        "@router.delete('/{attachment_id}')\n"
        "async def via_service(attachment_id: str, current_user: CurrentUser, db=Depends(get_db)):\n"
        "    service = AttachmentService(db)\n"
        "    item = await service.get_attachment(attachment_id)\n"
        "    logger.info('deleted %s by %s', attachment_id, current_user.id)\n"
        "@router.put('/{attachment_id}')\n"
        "async def via_scoped_service(attachment_id: str, current_user: CurrentUser, db=Depends(get_db)):\n"
        "    return await AttachmentService(db).get_for_user(attachment_id, current_user)\n"
        "@router.get('/notes/{note_id}')\n"
        "async def note(note_id: str, current_user: CurrentUser, db=Depends(get_db)):\n"
        "    return await db.get(Note, note_id)\n"
        "@router.get('/countries/{country_id}')\n"
        "async def country(country_id: int, current_user: CurrentUser, db=Depends(get_db)):\n"
        "    return await db.get(Country, country_id)\n"
        "@router.get('/admin/{attachment_id}')\n"
        "async def admin(attachment_id: str, boss: AdminUser, db=Depends(get_db)):\n"
        "    return await db.get(Attachment, attachment_id)\n"
        "@router.get('')\n"
        "async def listing(current_user: CurrentUser, attachment_id: str = Query(...), db=Depends(get_db)):\n"
        "    return await db.execute(select(Attachment).where(Attachment.id == attachment_id))\n"
        "@router.post('')\n"
        "async def create(current_user: CurrentUser, attachment_id: str = Form(...), db=Depends(get_db)):\n"
        "    return await db.get(Attachment, attachment_id)\n",
    )
    return root


def summary(found):
    return sorted((str(f.locations[0]), f.tag.value) for f in found)


def test_fastapi_unscoped_queries(tmp_path):
    root = fastapi_app(tmp_path)
    found = findings_for(root, "owasp", "OWASP-A01-UNSCOPED-QUERY")
    by_line = {f.locations[0].line: f for f in found}
    assert sorted(by_line) == [6, 20, 25, 32, 41]
    assert {line: f.tag.value for line, f in by_line.items()} == {
        6: "CONFIRMED",
        20: "INFERRED",
        25: "CONFIRMED",
        32: "CONFIRMED",
        41: "CONFIRMED",
    }
    assert by_line[20].proof_needed
    assert [str(loc) for loc in by_line[25].locations] == [
        "api/app/routes.py:25",
        "api/app/service.py:5",
    ]
    assert (
        by_line[6].title
        == "GET /files/{attachment_id} loads Attachment by attachment_id with no owner check"
    )
    assert by_line[32].title.startswith("GET /files/notes/{note_id} loads Note")


def test_django_views_and_guessable_ids(tmp_path):
    write(
        tmp_path,
        "shop/models.py",
        "from django.db import models\n"
        "class Invoice(models.Model):\n    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)\n"
        "    user_id = models.IntegerField()\n    total = models.IntegerField()\n",
    )
    write(
        tmp_path,
        "shop/urls.py",
        "from django.urls import path\nfrom . import views\nurlpatterns = [\n"
        "    path('invoices/<int:pk>/', views.invoice),\n    path('mine/<int:pk>/', views.mine),\n]\n",
    )
    write(
        tmp_path,
        "shop/views.py",
        "from django.contrib.auth.decorators import login_required\n"
        "@login_required\ndef invoice(request, pk):\n    return get_object_or_404(Invoice, pk=pk)\n"
        "@login_required\ndef mine(request, pk):\n    return get_object_or_404(Invoice, pk=pk, user=request.user)\n",
    )
    [unscoped] = findings_for(tmp_path, "owasp", "OWASP-A01-UNSCOPED-QUERY")
    assert (str(unscoped.locations[0]), unscoped.tag.value) == ("shop/views.py:4", "CONFIRMED")
    guessable = findings_for(tmp_path, "owasp", "OWASP-A01-GUESSABLE-ID")
    assert [str(f.locations[0]) for f in guessable] == ["shop/views.py:4"]
    assert guessable[0].severity.value == "medium"


def test_next_and_express_lookups(tmp_path):
    write(
        tmp_path,
        "prisma/schema.prisma",
        "model Invoice {\n  id Int @id @default(autoincrement())\n  userId Int\n}\n",
    )
    write(
        tmp_path,
        "app/api/invoices/[id]/route.ts",
        "export async function GET(req: Request, { params }: { params: { id: string } }) {\n"
        "  const session = await auth()\n"
        "  const invoice = await prisma.invoice.findUnique({ where: { id: Number(params.id) } })\n"
        "  return Response.json(invoice)\n}\n"
        "export async function PUT(req: Request, { params }: { params: { id: string } }) {\n"
        "  const session = await auth()\n"
        "  return prisma.invoice.findFirst({ where: { id: Number(params.id), userId: session.user.id } })\n}\n"
        "export async function DELETE(req: Request, { params }: { params: { id: string } }) {\n"
        "  const session = await auth()\n"
        "  const invoice = await prisma.invoice.findUnique({ where: { id: Number(params.id) } })\n"
        "  if (invoice.userId !== session.user.id) return new Response(null, { status: 404 })\n}\n",
    )
    write(
        tmp_path,
        "server/orders.js",
        "router.get('/orders/:id', requireAuth, async (req, res) => {\n"
        "  const order = await Order.findById(req.params.id)\n  res.json(order)\n})\n",
    )
    found = findings_for(tmp_path, "owasp", "OWASP-A01-UNSCOPED-QUERY")
    assert summary(found) == [
        ("app/api/invoices/[id]/route.ts:3", "CONFIRMED"),
        ("server/orders.js:2", "INFERRED"),
    ]
    guessable = findings_for(tmp_path, "owasp", "OWASP-A01-GUESSABLE-ID")
    assert sorted(str(f.locations[0]) for f in guessable) == [
        "app/api/invoices/[id]/route.ts:12",
        "app/api/invoices/[id]/route.ts:3",
    ]
    assert str(guessable[0].locations[1]) == "prisma/schema.prisma:2"


def test_unguarded_method(tmp_path):
    write(
        tmp_path,
        "app/api/posts/[id]/route.ts",
        "export async function GET() {\n  const session = await auth()\n}\n"
        "export async function DELETE() {\n  return new Response(null)\n}\n",
    )
    write(
        tmp_path,
        "app/api/open/route.ts",
        "export async function GET() {}\nexport async function POST() {}\n",
    )
    [f] = findings_for(tmp_path, "owasp", "OWASP-A01-UNGUARDED-METHOD")
    assert str(f.locations[0]) == "app/api/posts/[id]/route.ts:4"
    assert f.title == "DELETE /api/posts/:id has no auth check while GET on the same route does"


def test_email_ownership(tmp_path):
    write(
        tmp_path,
        "app/portal.py",
        "async def resolve(db, user):\n"
        "    return await db.execute(select(Client).where(func.lower(Client.email) == user.email.lower()))\n"
        "async def me(db, current_user):\n"
        "    return await db.execute(select(User).where(User.email == current_user.email))\n",
    )
    write(
        tmp_path,
        "lib/portal.ts",
        "export const load = (session) => prisma.customerRecord.findFirst({ where: { email: session.user.email } })\n",
    )
    found = findings_for(tmp_path, "owasp", "OWASP-A01-EMAIL-OWNERSHIP")
    assert sorted((str(f.locations[0]), f.tag.value) for f in found) == [
        ("app/portal.py:2", "INFERRED"),
        ("lib/portal.ts:1", "INFERRED"),
    ]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/reviews/test_owasp_a01.py -q`
Expected: FAIL in all 5 tests (no OWASP rules are registered yet, so each comparison or unpacking meets an empty result)

- [ ] **Step 3: Write the lookup analysis, the rules and the rule text**

`src/dpr/reviews/lookups.py`:

```python
"""Record lookups keyed by a request identifier, and whether the caller scopes them."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from dpr.model import DataModel, Location, Route
from dpr.parsing import jsts, pyast
from dpr.parsing.schemas import find_model
from dpr.reviews.access import Access, path_params
from dpr.rules import Context

PY_ORM = re.compile(
    r"\bselect\(|\.where\(|\.filter(?:_by)?\(|\.objects\.|get_object_or_404\(|get_list_or_404\("
    r"|\.get_or_404\(|\.query\.get\(|\b(?:session|db|self\.db|self\.session)\.get\("
)
PY_MODEL = re.compile(
    r"\bselect\(\s*(\w+)|(\w+)\.objects\.|get_(?:object|list)_or_404\(\s*(\w+)"
    r"|(?:session|db)\.get\(\s*(\w+)|(\w+)\.query\b"
)
PY_PK = re.compile(r"\.id\s*==|\bpk\s*=|\bid\s*=|\.get\(\s*\w+\s*,|get_or_404\(|query\.get\(")
LOG_CALLS = re.compile(r"(?:logger|logging|log|print|warnings)\b")
SKIP_CALLS = re.compile(
    r"HTTPException|Response|JSONResponse|str|int|len|dict|list|getattr|isinstance"
)
JS_ORM = re.compile(
    r"(?:\w+)\.(\w+)\.(findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow|update|delete"
    r"|upsert)$|^(\w+)\.(findById|findByIdAndUpdate|findByIdAndDelete|findOne)$"
)
JS_KEY = re.compile(
    r"\b(?:params|req\.params|req\.query|request\.params|context\.params)\.(\w+)"
    r"|searchParams\.get\(\s*['\"](\w+)['\"]"
)
OWNER_COLUMNS = {
    "user_id", "owner_id", "created_by", "author_id", "profile_id", "uploaded_by",
    "uploaded_by_id", "manager_id", "account_id", "customer_id", "client_id", "member_id",
    "org_id", "organization_id", "tenant_id", "workspace_id", "team_id", "company_id",
}  # fmt: skip
USER_MODELS = {"user", "users", "profile", "profiles", "account", "accounts", "customer", "member"}


@dataclass(frozen=True)
class Lookup:
    location: Location
    keys: tuple[str, ...]
    model: str | None
    by_primary_key: bool
    target: str | None
    via: Location | None = None


def snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def model_for(ctx: Context, name: str | None) -> DataModel | None:
    return find_model(ctx.detection.models, name) if name else None


def owned(ctx: Context, name: str | None) -> bool | None:
    """True when the model has an owner or tenant column, None when the model is unknown."""
    if name and name.lower().rstrip("s") in {m.rstrip("s") for m in USER_MODELS}:
        return True
    model = model_for(ctx, name)
    if model is None:
        return None
    columns = {snake(f.name) for f in model.fields}
    if columns & OWNER_COLUMNS:
        return True
    stems = {c[: -len("_id")] for c in columns if c.endswith("_id")}
    for parent in ctx.detection.models:
        names = (snake(parent.name), parent.table.split(".")[-1].rstrip("s"))
        if parent is not model and any(n.endswith(stem) for n in names for stem in stems):
            if {snake(f.name) for f in parent.fields} & OWNER_COLUMNS:
                return True
    return False


def request_keys(route: Route) -> set[str]:
    keys = set(path_params(route))
    fn = route.handler
    if isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
        params = [*fn.args.args, *fn.args.kwonlyargs]
        defaults = [None] * (len(fn.args.args) - len(fn.args.defaults))
        defaults += [*fn.args.defaults, *fn.args.kw_defaults]
        for arg, default in zip(params, defaults, strict=True):
            source = pyast.dotted(default.func) if isinstance(default, ast.Call) else None
            if source in ("Form", "Body", "File"):
                continue
            if arg.arg == "id" or arg.arg.endswith("_id"):
                keys.add(arg.arg)
    return keys


def _subject_text(text: str, subjects: tuple[str, ...]) -> bool:
    return any(re.search(rf"(?<![\w.]){re.escape(s)}\b", text) for s in subjects)


def _statements(fn: ast.AST) -> list[ast.stmt]:
    found = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign | ast.AnnAssign | ast.Expr | ast.Return | ast.AugAssign):
            found.append(node)
    return sorted(found, key=lambda n: n.lineno)


def _target(stmt: ast.stmt) -> str | None:
    if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name):
        return stmt.targets[0].id
    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
        return stmt.target.id
    return None


def _model_name(text: str, fn: ast.AST) -> str | None:
    match = PY_MODEL.search(text)
    name = next(g for g in match.groups() if g) if match else None
    if name and name[0].isupper():
        return name
    compared = re.search(r"\b([A-Z]\w*)\.\w+\s*==", text)
    if compared:
        return compared.group(1)
    root = re.match(r"(\w+)\.(?:where|filter)", text)
    if root:
        for stmt in _statements(fn):
            if _target(stmt) == root.group(1):
                found = PY_MODEL.search(ast.unparse(stmt.value))
                if found:
                    return next(g for g in found.groups() if g)
    return None


def helper_index(ctx: Context) -> dict[str, list[tuple[str, ast.AST]]]:
    key = ("helper-index", "")
    if key not in ctx.index.cache:
        found: dict[str, list[tuple[str, ast.AST]]] = {}
        for entry in ctx.index.py_files:
            tree = pyast.parse_file(ctx.index, entry.rel)
            for fn in pyast.functions(tree) if tree else []:
                found.setdefault(fn.name, []).append((entry.rel, fn))
        ctx.index.cache[key] = found
    return ctx.index.cache[key]


def _shared_prefix(a: str, b: str) -> int:
    count = 0
    for left, right in zip(a.split("/"), b.split("/"), strict=False):
        if left != right:
            break
        count += 1
    return count


def _is_method(fn: ast.AST) -> bool:
    args = [*fn.args.posonlyargs, *fn.args.args]
    return bool(args) and args[0].arg in ("self", "cls")


def _helper(ctx: Context, rel: str, call: ast.Call, caller: ast.AST) -> tuple[str, ast.AST] | None:
    """The one definition of the called name, preferring the closest file when names repeat."""
    name = (pyast.dotted(call.func) or "").split(".")[-1]
    method = isinstance(call.func, ast.Attribute)
    defs = [
        d
        for d in helper_index(ctx).get(name, [])
        if d[1] is not caller and _is_method(d[1]) == method
    ]
    if len(defs) <= 1:
        return defs[0] if defs else None
    ranked = sorted(defs, key=lambda d: -_shared_prefix(rel, d[0]))
    if _shared_prefix(rel, ranked[0][0]) > _shared_prefix(rel, ranked[1][0]):
        return ranked[0]
    return None


def _param_names(fn: ast.AST, call: ast.Call, keys: set[str]) -> set[str]:
    params = [a.arg for a in [*fn.args.posonlyargs, *fn.args.args] if a.arg not in ("self", "cls")]
    mapped = set()
    for position, arg in enumerate(call.args):
        if isinstance(arg, ast.Name) and arg.id in keys and position < len(params):
            mapped.add(params[position])
    for keyword in call.keywords:
        if isinstance(keyword.value, ast.Name) and keyword.value.id in keys and keyword.arg:
            mapped.add(keyword.arg)
    return mapped


SUBJECT_PARAMS = re.compile(r"(?i)user|owner|actor|caller|principal|account|member|tenant|org")


def py_lookups(
    ctx: Context, rel: str, fn: ast.AST, keys: set[str], subjects: tuple[str, ...], depth: int = 0
) -> list[Lookup]:
    found = []
    for stmt in _statements(fn):
        value = stmt if isinstance(stmt, ast.Expr) else getattr(stmt, "value", None)
        if value is None:
            continue
        text = ast.unparse(value)
        names = pyast.names_in(value)
        used = names & keys
        if not used or _subject_text(text, subjects):
            continue
        if PY_ORM.search(text):
            found.append(
                Lookup(
                    Location(rel, stmt.lineno),
                    tuple(sorted(used)),
                    _model_name(text, fn),
                    bool(PY_PK.search(text)),
                    _target(stmt),
                )
            )
            continue
        if depth >= 2:
            continue
        for call in [n for n in ast.walk(value) if isinstance(n, ast.Call)]:
            name = pyast.dotted(call.func) or ""
            if LOG_CALLS.match(name) or SKIP_CALLS.fullmatch(name.split(".")[-1]):
                continue
            if not pyast.names_in(call) & keys:
                continue
            helper = _helper(ctx, rel, call, fn)
            if helper is None:
                continue
            helper_rel, helper_fn = helper
            params = {a.arg for a in [*helper_fn.args.args, *helper_fn.args.kwonlyargs]}
            if any(SUBJECT_PARAMS.search(p) for p in params):
                continue
            mapped = _param_names(helper_fn, call, keys)
            inner = py_lookups(ctx, helper_rel, helper_fn, mapped, (), depth + 1)
            for item in inner:
                via = item.via or item.location
                found.append(
                    Lookup(
                        Location(rel, stmt.lineno),
                        tuple(sorted(used)),
                        item.model,
                        item.by_primary_key,
                        _target(stmt),
                        via,
                    )
                )
            if inner:
                break
    return found


def py_checked_after(fn: ast.AST, lookup: Lookup, subjects: tuple[str, ...]) -> str:
    """'owner' when a later comparison or call uses both the subject and the record, 'helper'
    when a later call receives only the subject, else ''."""
    targets = {lookup.target} if lookup.target else set()
    for stmt in _statements(fn):
        if stmt.lineno > lookup.location.line and _target(stmt):
            if pyast.names_in(stmt.value) & targets:
                targets.add(_target(stmt))
    pattern = (
        re.compile(r"\b(?:" + "|".join(re.escape(t) for t in targets) + r")\b") if targets else None
    )
    result = ""
    for node in ast.walk(fn):
        if getattr(node, "lineno", 0) <= lookup.location.line:
            continue
        if isinstance(node, ast.Compare):
            text = ast.unparse(node)
        elif isinstance(node, ast.Call) and not LOG_CALLS.match(pyast.dotted(node.func) or ""):
            text = " ".join(ast.unparse(a) for a in [*node.args, *node.keywords])
        else:
            continue
        if not _subject_text(text, subjects):
            continue
        if pattern is None or pattern.search(text):
            return "owner"
        if isinstance(node, ast.Call):
            result = "helper"
    return result


def js_keys(handler) -> set[str]:
    text = jsts.node_text(handler)
    keys = {next(g for g in m.groups() if g) for m in JS_KEY.finditer(text)}
    for match in re.finditer(r"\{\s*([\w\s,:]+)\}\s*=\s*(?:await\s+)?(?:\w+\.)?params\b", text):
        keys.update(n.strip().split(":")[-1].strip() for n in match.group(1).split(","))
    return {k for k in keys if k}


def js_lookups(route: Route, subjects: tuple[str, ...]) -> list[Lookup]:
    tree, handler = route.tree, route.handler
    keys = js_keys(handler)
    found = []
    for call in jsts.calls(tree, re.compile(r".*"), handler):
        match = JS_ORM.search(jsts.callee(call))
        if not match:
            continue
        text = jsts.node_text(call)
        used = {k for k in keys if re.search(rf"\b{re.escape(k)}\b", text)}
        if not used or _subject_text(text, subjects):
            continue
        model = match.group(1) or match.group(3)
        target = None
        parent = call.parent
        while parent is not None and parent.type in (
            "await_expression",
            "parenthesized_expression",
        ):
            parent = parent.parent
        if parent is not None and parent.type == "variable_declarator":
            target = jsts.node_text(parent.child_by_field_name("name"))
        pk = bool(re.search(r"\bid\s*:|findById", text))
        found.append(
            Lookup(
                Location(route.file, jsts.line(tree, call)), tuple(sorted(used)), model, pk, target
            )
        )
    return found


def js_checked_after(route: Route, lookup: Lookup, subjects: tuple[str, ...]) -> str:
    for node in jsts.walk(route.handler, {"binary_expression"}):
        if jsts.line(route.tree, node) <= lookup.location.line:
            continue
        text = jsts.node_text(node)
        if _subject_text(text, subjects) and (
            lookup.target is None or re.search(rf"\b{re.escape(lookup.target)}\b", text)
        ):
            return "owner"
    return ""


def route_lookups(ctx: Context, route: Route, access: Access) -> list[tuple[Lookup, str]]:
    """Unscoped lookups of a route with the later check kind: 'owner', 'helper' or ''."""
    subjects = access.subjects
    if isinstance(route.handler, ast.AST) and route.framework in ("fastapi", "flask", "django"):
        fn = route.handler
        if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
            return []
        derived = tuple(
            _target(s)
            for s in _statements(fn)
            if _target(s) and _subject_text(ast.unparse(s.value), subjects)
        )
        subjects = (*subjects, *derived)
        keys = request_keys(route)
        checked = [
            (item, py_checked_after(fn, item, subjects))
            for item in py_lookups(ctx, route.file, fn, keys, subjects)
        ]
        verified = {k for item, check in checked if check == "owner" for k in item.keys}
        return [(item, check) for item, check in checked if not set(item.keys) <= verified]
    if route.tree is not None and route.handler is not None and hasattr(route.handler, "type"):
        if route.handler.type in jsts.FUNCTION_TYPES:
            subjects = (*subjects, *(("req.user",) if route.framework == "express" else ()))
            return [
                (item, js_checked_after(route, item, subjects))
                for item in js_lookups(route, subjects)
            ]
    return []
```

`src/dpr/reviews/owasp_a01.py`:

```python
"""Review 5, OWASP A01: unscoped lookups, guessable IDs, unguarded methods, email ownership."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Route, Tag
from dpr.parsing import jsts, pyast
from dpr.redact import snippet
from dpr.reviews.access import ADMIN, PUBLIC, access
from dpr.reviews.lookups import USER_MODELS, model_for, owned, route_lookups
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule

WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
EMAIL_SUBJECT = re.compile(
    r"\b(?:current_user|user|me|caller|request\.user|session\.user)\.email\b"
)
MODEL_EMAIL = re.compile(r"\b([A-Z]\w*)\.email\b")


def unscoped(ctx: Context) -> list[tuple[Route, list, str]]:
    """Unscoped lookups on owned or unknown models, grouped per route, first lookup first."""
    if "unscoped_lookups" not in ctx.facts:
        found = []
        for route in ctx.detection.routes:
            level = access(ctx, route)
            if level.level == ADMIN or is_test(route.file):
                continue
            items = [
                (lookup, check)
                for lookup, check in route_lookups(ctx, route, level)
                if check != "owner" and owned(ctx, lookup.model) is not False
            ]
            if items:
                checks = {check for _, check in items}
                found.append(
                    (route, [lookup for lookup, _ in items], "helper" if "helper" in checks else "")
                )
        ctx.facts["unscoped_lookups"] = found
    return ctx.facts["unscoped_lookups"]


@rule(
    "OWASP-A01-UNSCOPED-QUERY", review="owasp", severity="high", exploitability="high", owasp="A01"
)
def unscoped_query(ctx: Context) -> Iterator[Finding]:
    for route, items, check in unscoped(ctx):
        lookup = items[0]
        known = owned(ctx, lookup.model) is not None
        confirmed = check == "" and known
        proof = None
        if check == "helper":
            proof = "A later call receives the caller; confirm it rejects other owners' records."
        elif not known:
            proof = "The model was not found; confirm the record belongs to a user or tenant."
        locations = [lookup.location, *([lookup.via] if lookup.via else [])]
        locations += [item.location for item in items[1:]]
        level = access(ctx, route).level
        yield make_finding(
            "OWASP-A01-UNSCOPED-QUERY",
            tag=Tag.CONFIRMED if confirmed else Tag.INFERRED,
            locations=locations,
            snippet=snippet(ctx.index.text(route.file), lookup.location.line),
            proof_needed=proof,
            method=route.method,
            path=route.path,
            key=", ".join(lookup.keys),
            model=lookup.model or "record",
            level=level,
        )


@rule(
    "OWASP-A01-GUESSABLE-ID",
    review="owasp",
    severity="medium",
    exploitability="medium",
    owasp="A01",
)
def guessable_id(ctx: Context) -> Iterator[Finding]:
    seen = set()
    for route in ctx.detection.routes:
        level = access(ctx, route)
        if level.level == ADMIN or is_test(route.file):
            continue
        for lookup, _check in route_lookups(ctx, route, level):
            model = model_for(ctx, lookup.model)
            if not lookup.by_primary_key or model is None or not owned(ctx, lookup.model):
                continue
            id_field = next((f for f in model.fields if f.name in ("id", "pk")), None)
            key = (route.file, lookup.location.line)
            if id_field is not None and id_field.autoincrement and key not in seen:
                seen.add(key)
                yield make_finding(
                    "OWASP-A01-GUESSABLE-ID",
                    tag=Tag.CONFIRMED,
                    locations=[lookup.location, id_field.location],
                    model=model.name,
                    path=route.path,
                )


@rule(
    "OWASP-A01-UNGUARDED-METHOD",
    review="owasp",
    severity="high",
    exploitability="high",
    owasp="A01",
)
def unguarded_method(ctx: Context) -> Iterator[Finding]:
    groups: dict[tuple[str, str], list[Route]] = {}
    for route in ctx.detection.routes:
        groups.setdefault((route.file, route.path), []).append(route)
    for (_file, path), routes in sorted(groups.items()):
        guarded = [r for r in routes if access(ctx, r).level != PUBLIC]
        if not guarded:
            continue
        for route in routes:
            if route.method in WRITE_METHODS and access(ctx, route).level == PUBLIC:
                yield make_finding(
                    "OWASP-A01-UNGUARDED-METHOD",
                    tag=Tag.CONFIRMED,
                    locations=[Location(route.file, route.line)],
                    snippet=snippet(ctx.index.text(route.file), route.line),
                    method=route.method,
                    path=path,
                    guarded=", ".join(sorted({r.method for r in guarded})),
                )


def _py_email_matches(tree: ast.Module) -> Iterator[tuple[int, str]]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            text = ast.unparse(node)
            model = MODEL_EMAIL.search(text)
            if model and EMAIL_SUBJECT.search(text):
                yield node.lineno, model.group(1)
        if isinstance(node, ast.keyword) and node.arg == "email":
            call_text = ast.unparse(node.value)
            if EMAIL_SUBJECT.search(call_text):
                yield node.value.lineno, ""


@rule(
    "OWASP-A01-EMAIL-OWNERSHIP",
    review="owasp",
    severity="high",
    exploitability="medium",
    owasp="A01",
)
def email_ownership(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel) or ".email" not in text:
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for line, model in sorted(set(_py_email_matches(tree))) if tree else []:
            if not model or model.lower().rstrip("s") in {m.rstrip("s") for m in USER_MODELS}:
                continue
            yield make_finding(
                "OWASP-A01-EMAIL-OWNERSHIP",
                tag=Tag.INFERRED,
                locations=[Location(entry.rel, line)],
                snippet=snippet(text, line),
                model=model,
            )
    for entry in ctx.index.js_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel) or "email" not in text:
            continue
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for call in jsts.calls(tree, r"\w+\.(\w+)\.(?:findFirst|findUnique|findMany)"):
                model = jsts.callee(call).split(".")[-2]
                body = jsts.node_text(call)
                if model.lower().rstrip("s") in {m.rstrip("s") for m in USER_MODELS}:
                    continue
                if re.search(
                    r"email\s*:\s*(?:session|user|currentUser)\??\.(?:user\??\.)?email", body
                ):
                    line = jsts.line(tree, call)
                    yield make_finding(
                        "OWASP-A01-EMAIL-OWNERSHIP",
                        tag=Tag.INFERRED,
                        locations=[Location(entry.rel, line)],
                        snippet=snippet(text, line),
                        model=model,
                    )
```

`src/dpr/data/rule_text/owasp_a01.yaml`:

```yaml
OWASP-A01-UNSCOPED-QUERY:
  title: ${method} ${path} loads ${model} by ${key} with no owner check
  effort_minutes: 15
  detail: The ${level} route ${method} ${path} looks up a ${model} using ${key} from the request, and neither the query nor a later check ties the record to the caller.
  proof_needed: Confirm the record belongs to a user or tenant and that nothing outside this code path checks ownership.
  attack: 1. Sign in as any user. 2. Note the identifier of one of your own records. 3. Request the same route with another identifier. 4. Read or change a record that belongs to someone else.
  blast: Every ${model} record reachable through ${method} ${path}.
  fix: Put the caller into the query itself, for example where(Model.id == key, Model.owner_id == current_user.id) or findFirst({ where { id, userId session.user.id } }), and return 404 when nothing matches.
  verify: As user A, request a record that belongs to user B through ${method} ${path} and expect 404.
OWASP-A01-GUESSABLE-ID:
  title: ${model} uses sequential IDs in ${path}
  effort_minutes: 60
  detail: ${model} has an auto-increment integer primary key and ${path} takes it from the URL, so one working ID reveals all the others.
  attack: Take your own record ID and count down or up to walk the whole table through ${path}.
  blast: Every ${model} row, as soon as any lookup on it is missing an ownership check.
  fix: Keep ownership checks as the real control, and expose a random identifier (UUID or a public slug) in URLs instead of the integer primary key.
  verify: Confirm the URL identifier is a UUID or slug and that neighbouring integers return 404.
OWASP-A01-UNGUARDED-METHOD:
  title: ${method} ${path} has no auth check while ${guarded} on the same route does
  effort_minutes: 10
  detail: In the same file, ${path} checks the caller for ${guarded} but not for ${method}.
  attack: Send ${method} to ${path} without signing in.
  blast: Whatever ${method} ${path} writes or deletes, for every record it accepts.
  fix: Apply the same authentication (and ownership) check to ${method} as to the other methods, ideally through one shared guard for the route.
  verify: Send ${method} to ${path} without a session and expect 401.
OWASP-A01-EMAIL-OWNERSHIP:
  title: ${model} records are matched to the caller by email
  effort_minutes: 30
  detail: The code finds the caller's ${model} by comparing its email with the signed-in user's email. Ownership is then only as strong as control over that email field.
  proof_needed: Check whether users can sign up or change their own email without verifying it; if they can, anyone can claim a record by setting its email.
  attack: 1. Sign up or change your account email to the email stored on someone else's record. 2. Open the page that resolves records by email. 3. Read that record.
  blast: Every ${model} whose email is not already held by another account.
  fix: Link the record to the account with an explicit foreign key (for example ${model}.user_id) set by staff or by a verified invite, and filter on that key.
  verify: Change a test account's email to another record's email and confirm that record is not returned.
```

Modify `src/dpr/reviews/owasp.py`, replace:

```python
from dpr.model import Part, ReviewSection
```

with:

```python
import dpr.reviews.owasp_a01  # noqa: F401  (registers rules)
from dpr.model import Part, ReviewSection
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest -q`
Expected: PASS (all tests, including 5 new ones)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/reviews/lookups.py src/dpr/reviews/owasp_a01.py src/dpr/reviews/owasp.py src/dpr/data/rule_text/owasp_a01.yaml tests/reviews/test_owasp_a01.py
git commit -m "Add OWASP A01 checks for unscoped lookups, guessable IDs, unguarded methods and email ownership"
```

---
### Task 40: Path traversal in file writes, mass assignment and client-only admin guards

Path traversal is found with a small taint pass over Python functions. The request values of a route are seeded: every FastAPI parameter that is not a dependency, `Request`, session or response object (so `UploadFile`, `Form`, `Query` and path parameters), path parameters for other frameworks, and `request.files/form/args/data/json/FILES/POST/GET`. Taint follows assignments, `with ... as`, f-strings, joins and method calls in source order. It is cleared by `secure_filename`, `basename`, UUID or token generators, `.name`/`.stem`/`.suffix`, and by an allowlist exit (`if value not in ALLOWED: raise`). A function that checks `is_relative_to(...)` or `resolve()...startswith(...)` is treated as guarded. Sinks are `open` and `aiofiles.open` in a write mode, `Path.write_bytes/write_text/open("w")`, `FileStorage.save(path)`, and `os.rename/os.replace/shutil.move/shutil.copy` targets. Calls are followed into helpers up to three levels. When the helper name repeats, the closest file is used and the finding is INFERRED. JavaScript handlers are checked in the handler only, for `fs` write calls whose path uses `req.body/query/params/file`, `originalname`, `formData.get` or `file.name` without `path.basename`.

**Files:**
- Create: `src/dpr/reviews/owasp_paths.py`, `src/dpr/reviews/owasp_assign.py`, `src/dpr/data/rule_text/owasp_files.yaml`
- Modify: `src/dpr/reviews/owasp.py` (import the rule modules)
- Test: `tests/reviews/test_owasp_paths.py`, `tests/reviews/test_owasp_assign.py`

**Interfaces:**
- Consumes: Task 39 (`helper_index`, `model_for`, `snake`), Task 33 (`access`, `fastapi_aliases`, `path_params`, `ADMIN`), Task 37 (`is_test`), plus the Milestone 1 helpers used by every rule module
- Produces:
  - `dpr.reviews.owasp_paths`: `Reach(sink: Location, via_helper: bool, unique: bool)`; `reaches(ctx, rel, fn, seeds: dict[str, set[str]], depth=0) -> dict[str, Reach]`; `request_params(ctx, route) -> dict[str, set[str]]` (the seeded request values of a Python route, reused by the SSRF rule in Task 41)
  - Registered rules (review `owasp`, A01): `OWASP-A01-PATH-TRAVERSAL` (high; one finding per route naming every request value that reaches a write, located at the handler and at each sink), `OWASP-A01-MASS-ASSIGNMENT` (high; a raw request body passed to a Prisma, Mongoose or Sequelize write or `Object.assign`, to `Model(**body)` or `**body` in any call, or looped into `setattr`; CONFIRMED when the model has a sensitive column such as `role`, `is_admin`, `org_id`, `plan`, `user_id`, else INFERRED; pydantic `model_dump()` and `dict()` are allowlists and are not reported), `OWASP-A01-CLIENT-ONLY-GUARD` (medium, INFERRED; a UI file checks `isAdmin` or an admin role while a route under `/admin` is not admin-level)

- [ ] **Step 1: Write the failing tests**

`tests/reviews/test_owasp_paths.py`:

```python
from tests.reviews.helpers import findings_for, write

DEPS = "from typing import Annotated\nfrom fastapi import Depends\nCurrentUser = Annotated[dict, Depends(get_current_user)]\n"


def test_fastapi_upload_writes(tmp_path):
    write(tmp_path, "api/app/deps.py", DEPS)
    write(
        tmp_path,
        "api/app/storage.py",
        "from pathlib import Path\n"
        "class Storage:\n"
        "    def save(self, upload, folder):\n"
        "        name = f'{uuid4().hex}_{upload.filename}'\n"
        "        return self._write(f'{folder}/{name}', b'')\n"
        "    def _write(self, blob_path, content):\n"
        "        dest = Path('data/uploads') / blob_path\n"
        "        dest.write_bytes(content)\n"
        "    def safe(self, upload):\n"
        "        dest = Path('data') / Path(upload.filename).name\n"
        "        dest.write_bytes(b'')\n",
    )
    write(
        tmp_path,
        "api/app/routes.py",
        "from fastapi import APIRouter, File, Form, UploadFile\nfrom app.deps import CurrentUser\n"
        "router = APIRouter()\n"
        "@router.post('/docs')\n"
        "async def upload(current_user: CurrentUser, file: UploadFile = File(...)):\n"
        "    target = settings.upload_path / file.filename\n"
        "    target.write_bytes(await file.read())\n"
        "@router.post('/attachments')\n"
        "async def attach(current_user: CurrentUser, file: UploadFile = File(...), entity_id: str = Form(...),\n"
        "                 kind: str = Form(...)):\n"
        "    if kind not in KINDS:\n        raise HTTPException(400)\n"
        "    return Storage().save(file, f'{kind}/{entity_id}')\n"
        "@router.post('/safe')\n"
        "async def safe(current_user: CurrentUser, file: UploadFile = File(...)):\n"
        "    Storage().safe(file)\n"
        "    name = secure_filename(file.filename)\n"
        "    with open(f'data/{name}', 'wb') as out:\n        out.write(b'')\n"
        "@router.post('/checked')\n"
        "async def checked(current_user: CurrentUser, file: UploadFile = File(...)):\n"
        "    dest = (root / file.filename).resolve()\n"
        "    if not dest.is_relative_to(root):\n        raise ValueError()\n"
        "    dest.write_bytes(b'')\n"
        "@router.get('/cache')\n"
        "async def cache(current_user: CurrentUser):\n"
        "    with open(CACHE_FILE, 'w') as out:\n        out.write('x')\n",
    )
    found = findings_for(tmp_path, "owasp", "OWASP-A01-PATH-TRAVERSAL")
    assert sorted((f.title, [str(loc) for loc in f.locations], f.tag.value) for f in found) == [
        (
            "POST /attachments writes a file to a path built from the request values entity_id and file",
            ["api/app/routes.py:9", "api/app/storage.py:8"],
            "CONFIRMED",
        ),
        (
            "POST /docs writes a file to a path built from the request value file",
            ["api/app/routes.py:5", "api/app/routes.py:7"],
            "CONFIRMED",
        ),
    ]


def test_flask_and_express_writes(tmp_path):
    write(
        tmp_path,
        "web/app.py",
        "from flask import Flask, request\napp = Flask(__name__)\n"
        "@app.route('/upload', methods=['POST'])\ndef upload():\n"
        "    f = request.files['doc']\n    f.save('uploads/' + f.filename)\n"
        "@app.route('/avatar', methods=['POST'])\ndef avatar():\n"
        "    f = request.files['doc']\n    f.save(os.path.join('uploads', secure_filename(f.filename)))\n",
    )
    write(
        tmp_path,
        "server/files.js",
        "router.post('/files', requireAuth, async (req, res) => {\n"
        "  const target = path.join(UPLOADS, req.body.name)\n"
        "  await fs.promises.writeFile(target, req.body.content)\n"
        "  fs.writeFileSync(path.join(UPLOADS, path.basename(req.body.name)), '')\n"
        "})\n",
    )
    found = findings_for(tmp_path, "owasp", "OWASP-A01-PATH-TRAVERSAL")
    assert sorted(str(f.locations[-1]) for f in found) == ["server/files.js:3", "web/app.py:6"]
```

`tests/reviews/test_owasp_assign.py`:

```python
from tests.reviews.helpers import findings_for, write


def test_mass_assignment_js(tmp_path):
    write(
        tmp_path,
        "prisma/schema.prisma",
        "model User {\n  id Int @id\n  email String\n  role String\n}\nmodel Note {\n  id Int @id\n  body String\n}\n",
    )
    write(
        tmp_path,
        "app/api/users/route.ts",
        "export async function POST(req: Request) {\n"
        "  const body = await req.json()\n"
        "  await prisma.user.create({ data: body })\n"
        "  await prisma.note.create({ data: { ...body } })\n"
        "  await prisma.note.create({ data: { body: body.text } })\n"
        "}\n",
    )
    write(
        tmp_path,
        "server/notes.js",
        "router.put('/notes/:id', auth, async (req, res) => {\n"
        "  await Note.findByIdAndUpdate(req.params.id, req.body)\n"
        "  await Note.findByIdAndUpdate(req.params.id, { text: req.body.text })\n"
        "})\n",
    )
    found = findings_for(tmp_path, "owasp", "OWASP-A01-MASS-ASSIGNMENT")
    assert sorted((str(f.locations[0]), f.tag.value) for f in found) == [
        ("app/api/users/route.ts:3", "CONFIRMED"),
        ("app/api/users/route.ts:4", "INFERRED"),
        ("server/notes.js:2", "INFERRED"),
    ]
    confirmed = next(f for f in found if f.tag.value == "CONFIRMED")
    assert "role" in confirmed.detail


def test_mass_assignment_python(tmp_path):
    write(
        tmp_path,
        "api/app.py",
        "from fastapi import FastAPI, Request\napp = FastAPI()\n"
        "@app.post('/items')\nasync def create(request: Request):\n"
        "    payload = await request.json()\n    return Item(**payload)\n"
        "@app.put('/items/{item_id}')\nasync def update(item_id: str, data: ItemUpdate):\n"
        "    item = Item(**data.model_dump())\n"
        "    for key, value in data.model_dump(exclude_unset=True).items():\n        setattr(item, key, value)\n",
    )
    write(
        tmp_path,
        "shop/urls.py",
        "from django.urls import path\nfrom . import views\nurlpatterns = [path('orders/', views.order)]\n",
    )
    write(
        tmp_path,
        "shop/views.py",
        "def order(request):\n    data = request.POST.dict()\n"
        "    for key, value in data.items():\n        setattr(order, key, value)\n",
    )
    found = findings_for(tmp_path, "owasp", "OWASP-A01-MASS-ASSIGNMENT")
    assert sorted(str(f.locations[0]) for f in found) == ["api/app.py:6", "shop/views.py:3"]


def test_client_only_guard(tmp_path):
    write(
        tmp_path,
        "src/Nav.tsx",
        "export const Nav = ({ user }) => user.role === 'admin' ? <Admin /> : null\n",
    )
    write(
        tmp_path,
        "app/api/admin/users/route.ts",
        "export async function GET() {\n  const session = await auth()\n}\n",
    )
    write(
        tmp_path,
        "app/api/admin/stats/route.ts",
        "export async function GET() {\n  const session = await auth()\n  if (session.user.role !== 'admin') return null\n}\n",
    )
    [f] = findings_for(tmp_path, "owasp", "OWASP-A01-CLIENT-ONLY-GUARD")
    assert [str(loc) for loc in f.locations] == ["app/api/admin/users/route.ts:1", "src/Nav.tsx:1"]
    (tmp_path / "src/Nav.tsx").write_text("export const Nav = () => null\n")
    assert findings_for(tmp_path, "owasp", "OWASP-A01-CLIENT-ONLY-GUARD") == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/reviews/test_owasp_paths.py tests/reviews/test_owasp_assign.py -q`
Expected: FAIL (the rules are not registered, so every assertion compares an empty result with the expected findings)

- [ ] **Step 3: Write the rules and the rule text**

`src/dpr/reviews/owasp_paths.py`:

```python
"""Review 5, OWASP A01: request values that reach a file write path (path traversal)."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from dataclasses import dataclass

from dpr.model import Finding, Location, Route, Tag
from dpr.parsing import jsts, pyast
from dpr.redact import snippet
from dpr.reviews.access import fastapi_aliases, path_params
from dpr.reviews.lookups import helper_index
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule

WRITE_MODE = re.compile(r"[wax+]")
SANITIZERS = re.compile(r"(?:^|\.)(secure_filename|basename|uuid4|uuid1|token_hex|token_urlsafe)$")
SAFE_ATTRIBUTES = {"name", "stem", "suffix", "hex"}
NOT_REQUEST = re.compile(r"Depends|Security|Request|Session|BackgroundTasks|Response|WebSocket")
REQUEST_DATA = re.compile(r"^request\.(?:files|form|args|values|data|json|FILES|POST|GET)\b")
JS_WRITE = re.compile(
    r"(?:fs\.|fsp\.|promises\.|fs\.promises\.)?(writeFile|writeFileSync|createWriteStream|appendFile"
    r"|appendFileSync|rename|renameSync)"
)
JS_SOURCE = re.compile(
    r"req\.(?:body|query|params|file|files)|\.originalname|formData\.get\(|\bfile\.name\b|params\.\w+"
)


@dataclass(frozen=True)
class Reach:
    sink: Location
    via_helper: bool
    unique: bool


def _params(fn: ast.AST) -> list[str]:
    args = [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
    return [a.arg for a in args if a.arg not in ("self", "cls")]


def _taint_of(node: ast.AST | None, taint: dict[str, set[str]]) -> set[str]:
    if node is None:
        return set()
    if isinstance(node, ast.Name):
        return set(taint.get(node.id, set()))
    text = ast.unparse(node)
    if REQUEST_DATA.match(text):
        return {"request"}
    if isinstance(node, ast.Attribute):
        return set() if node.attr in SAFE_ATTRIBUTES else _taint_of(node.value, taint)
    if isinstance(node, ast.Call):
        if SANITIZERS.search(pyast.dotted(node.func) or ""):
            return set()
        found = set()
        for part in [*node.args, *(k.value for k in node.keywords)]:
            found |= _taint_of(part, taint)
        if isinstance(node.func, ast.Attribute):
            found |= _taint_of(node.func.value, taint)
        return found
    found = set()
    for child in ast.iter_child_nodes(node):
        found |= _taint_of(child, taint)
    return found


def _sink_path(call: ast.Call) -> ast.AST | None:
    name = pyast.dotted(call.func) or ""
    last = name.split(".")[-1]
    mode = pyast.constant(call.args[1], "") if len(call.args) > 1 else ""
    mode = pyast.constant(pyast.kwarg(call, "mode"), mode)
    if last == "open" and isinstance(call.func, ast.Name | ast.Attribute) and call.args:
        if name in ("open", "aiofiles.open", "io.open") and WRITE_MODE.search(str(mode)):
            return call.args[0]
    if isinstance(call.func, ast.Attribute):
        if last in ("write_bytes", "write_text"):
            return call.func.value
        if (
            last == "open"
            and call.args
            and WRITE_MODE.search(str(pyast.constant(call.args[0], "")))
        ):
            return call.func.value
        if last == "save" and len(call.args) == 1:
            return call.args[0]
    if name in ("os.rename", "os.replace", "shutil.move", "shutil.copy", "shutil.copyfile"):
        return call.args[1] if len(call.args) > 1 else None
    return None


def _guarded(fn: ast.AST) -> bool:
    text = ast.unparse(fn)
    return "is_relative_to(" in text or bool(re.search(r"resolve\(\).*startswith\(", text))


def _allowlist_exit(node: ast.If) -> bool:
    """`if name not in ALLOWED: raise` (or return) leaves `name` as one of the allowed values."""
    test = node.test
    return (
        isinstance(test, ast.Compare)
        and isinstance(test.left, ast.Name)
        and len(test.ops) == 1
        and isinstance(test.ops[0], ast.NotIn)
        and any(isinstance(stmt, ast.Raise | ast.Return) for stmt in node.body)
    )


def reaches(
    ctx: Context, rel: str, fn: ast.AST, seeds: dict[str, set[str]], depth: int = 0
) -> dict[str, Reach]:
    """Seed names (usually parameters) that reach a file write path, with the sink location."""
    if _guarded(fn):
        return {}
    taint = {name: set(sources) for name, sources in seeds.items()}
    found: dict[str, Reach] = {}
    nodes = sorted(
        (n for n in ast.walk(fn) if hasattr(n, "lineno")), key=lambda n: (n.lineno, n.col_offset)
    )
    for node in nodes:
        if isinstance(node, ast.If) and _allowlist_exit(node):
            taint[node.test.left.id] = set()
        if isinstance(node, ast.Assign | ast.AnnAssign) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    taint[target.id] = _taint_of(node.value, taint)
        if isinstance(node, ast.withitem) and isinstance(node.optional_vars, ast.Name):
            taint[node.optional_vars.id] = _taint_of(node.context_expr, taint)
        if not isinstance(node, ast.Call):
            continue
        path = _sink_path(node)
        if path is not None:
            for source in _taint_of(path, taint):
                found.setdefault(source, Reach(Location(rel, node.lineno), False, True))
            continue
        if depth >= 3:
            continue
        name = (pyast.dotted(node.func) or "").split(".")[-1]
        defs = [d for d in helper_index(ctx).get(name, []) if d[1] is not fn]
        if not defs:
            continue
        helper_rel, helper = max(defs, key=lambda d: _shared(rel, d[0]))
        params = _params(helper)
        inner_seeds = {p: {p} for p in params}
        inner = reaches(ctx, helper_rel, helper, inner_seeds, depth + 1)
        arguments = dict(zip(params, node.args, strict=False))
        arguments.update({k.arg: k.value for k in node.keywords if k.arg})
        for param, reach in inner.items():
            for source in _taint_of(arguments.get(param), taint):
                found.setdefault(source, Reach(reach.sink, True, len(defs) == 1 and reach.unique))
    return found


def _shared(a: str, b: str) -> int:
    count = 0
    for left, right in zip(a.split("/"), b.split("/"), strict=False):
        if left != right:
            break
        count += 1
    return count


def request_params(ctx: Context, route: Route) -> dict[str, set[str]]:
    fn = route.handler
    aliases = fastapi_aliases(ctx)
    seeds: dict[str, set[str]] = {"request": {"request"}} if route.framework != "fastapi" else {}
    params = [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
    defaults = [None] * (len(fn.args.posonlyargs) + len(fn.args.args) - len(fn.args.defaults))
    defaults += [*fn.args.defaults, *fn.args.kw_defaults]
    for param, default in zip(params, defaults, strict=True):
        annotation = ast.unparse(param.annotation) if param.annotation is not None else ""
        text = annotation + " " + (ast.unparse(default) if default is not None else "")
        if param.arg in ("self", "request") or NOT_REQUEST.search(text):
            continue
        if any(re.search(rf"\b{re.escape(alias)}\b", annotation) for alias in aliases):
            continue
        if route.framework == "fastapi" or param.arg in path_params(route):
            seeds[param.arg] = {param.arg}
    return seeds


def _js_findings(ctx: Context, route: Route) -> Iterator[Finding]:
    for call in jsts.calls(route.tree, JS_WRITE, route.handler):
        args = jsts.arguments(call)
        if not args:
            continue
        target = jsts.unwrap(args[0])
        text = jsts.node_text(target)
        if target is not None and target.type == "identifier":
            resolved = jsts.resolve_identifier(target)
            text = jsts.node_text(resolved) if resolved is not None else text
        if JS_SOURCE.search(text) and "basename(" not in text:
            line = jsts.line(route.tree, call)
            yield make_finding(
                "OWASP-A01-PATH-TRAVERSAL",
                tag=Tag.CONFIRMED,
                locations=[Location(route.file, line)],
                snippet=snippet(ctx.index.text(route.file), line),
                method=route.method,
                path=route.path,
                source="a request value",
            )


@rule(
    "OWASP-A01-PATH-TRAVERSAL",
    review="owasp",
    severity="high",
    exploitability="medium",
    owasp="A01",
)
def path_traversal(ctx: Context) -> Iterator[Finding]:
    for route in ctx.detection.routes:
        if is_test(route.file) or route.handler is None:
            continue
        if route.tree is not None and hasattr(route.handler, "type"):
            if route.handler.type in jsts.FUNCTION_TYPES:
                yield from _js_findings(ctx, route)
            continue
        if not isinstance(route.handler, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        found = reaches(ctx, route.file, route.handler, request_params(ctx, route))
        if not found:
            continue
        sinks = list(dict.fromkeys(reach.sink for _, reach in sorted(found.items())))
        confirmed = all(not r.via_helper or r.unique for r in found.values())
        names = sorted(found)
        source = "the request value" + ("s " if len(names) > 1 else " ") + " and ".join(names)
        yield make_finding(
            "OWASP-A01-PATH-TRAVERSAL",
            tag=Tag.CONFIRMED if confirmed else Tag.INFERRED,
            locations=[Location(route.file, route.line), *sinks],
            snippet=snippet(ctx.index.text(sinks[0].file), sinks[0].line),
            method=route.method,
            path=route.path,
            source=source,
        )
```

`src/dpr/reviews/owasp_assign.py`:

```python
"""Review 5, OWASP A01: mass assignment and admin screens guarded only in the browser."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Route, Tag
from dpr.parsing import jsts, pyast
from dpr.redact import snippet
from dpr.reviews.access import ADMIN, access
from dpr.reviews.lookups import model_for, snake
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule
from dpr.walk import line_of

SENSITIVE_FIELDS = {
    "role", "roles", "is_admin", "admin", "is_staff", "is_superuser", "org_id", "organization_id",
    "tenant_id", "plan", "permissions", "balance", "credits", "email_verified", "verified",
    "owner_id", "user_id",
}  # fmt: skip
JS_WRITE = re.compile(
    r"\w+\.(\w+)\.(create|update|upsert|createMany|updateMany)$"
    r"|^(\w+)\.(create|findByIdAndUpdate|findOneAndUpdate|updateOne|insertMany|bulkCreate)$"
    r"|^Object\.assign$"
)
JS_BODY = re.compile(r"(?:\breq|\brequest)\.(?:body\b|json\(\))(?!\s*\??\.\s*\w)|\bformData\(\)")
PY_BODY = re.compile(
    r"^(?:await )?request\.(?:json\(\)|get_json\(\)|json|data|POST|form)(?:\.dict\(\))?$"
)
UI_ADMIN = re.compile(
    r"""\bisAdmin\b|role\s*={2,3}\s*['"]admin['"]|['"]admin['"]\s*={2,3}\s*\w*\.?role"""
)
UI_SUFFIXES = (".tsx", ".jsx", ".vue", ".svelte")


def _js_body(node) -> bool:
    node = jsts.unwrap(node)
    if node is None:
        return False
    if node.type == "identifier":
        resolved = jsts.resolve_identifier(node)
        return resolved is not None and bool(JS_BODY.search(jsts.node_text(resolved)))
    if node.type == "object":
        pairs = jsts.object_pairs(node)
        if "data" in pairs:
            return _js_body(pairs["data"])
        return any(
            _js_body(child.named_children[0])
            for child in node.named_children
            if child.type == "spread_element" and child.named_children
        )
    return bool(JS_BODY.search(jsts.node_text(node)))


def _model_fields(ctx: Context, name: str | None) -> set[str]:
    model = model_for(ctx, name)
    return {snake(f.name) for f in model.fields} if model else set()


def _finding(ctx: Context, route: Route, line: int, model: str | None) -> Finding:
    sensitive = sorted(_model_fields(ctx, model) & SENSITIVE_FIELDS)
    return make_finding(
        "OWASP-A01-MASS-ASSIGNMENT",
        tag=Tag.CONFIRMED if sensitive else Tag.INFERRED,
        locations=[Location(route.file, line)],
        snippet=snippet(ctx.index.text(route.file), line),
        model=model or "record",
        fields=", ".join(sensitive) if sensitive else "any column the model has",
    )


def _js_mass(ctx: Context, route: Route) -> Iterator[Finding]:
    for call in jsts.calls(route.tree, JS_WRITE, route.handler):
        match = JS_WRITE.search(jsts.callee(call))
        args = jsts.arguments(call)
        candidates = args[-1:] if match.group(3) else args[:1]
        if jsts.callee(call) == "Object.assign":
            candidates = args[1:]
        if any(_js_body(a) for a in candidates):
            model = match.group(1) or match.group(3)
            yield _finding(ctx, route, jsts.line(route.tree, call), model)


def _py_body_names(fn: ast.AST) -> set[str]:
    names = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            if PY_BODY.match(ast.unparse(node.value)):
                names.add(node.targets[0].id)
    return names


def _py_is_body(node: ast.AST, names: set[str]) -> bool:
    return (isinstance(node, ast.Name) and node.id in names) or bool(
        PY_BODY.match(ast.unparse(node))
    )


def _py_mass(ctx: Context, route: Route) -> Iterator[Finding]:
    fn = route.handler
    names = _py_body_names(fn)
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                if keyword.arg is None and _py_is_body(keyword.value, names):
                    dotted = pyast.dotted(node.func) or ""
                    model = dotted.split(".")[0] if dotted[:1].isupper() else None
                    yield _finding(ctx, route, node.lineno, model)
        if isinstance(node, ast.For) and isinstance(node.iter, ast.Call):
            source = node.iter.func.value if isinstance(node.iter.func, ast.Attribute) else None
            body = " ".join(ast.unparse(s) for s in node.body)
            if source is not None and _py_is_body(source, names) and "setattr(" in body:
                yield _finding(ctx, route, node.lineno, None)


@rule(
    "OWASP-A01-MASS-ASSIGNMENT",
    review="owasp",
    severity="high",
    exploitability="high",
    owasp="A01",
)
def mass_assignment(ctx: Context) -> Iterator[Finding]:
    for route in ctx.detection.routes:
        if is_test(route.file) or route.handler is None:
            continue
        if isinstance(route.handler, ast.FunctionDef | ast.AsyncFunctionDef):
            yield from _py_mass(ctx, route)
        elif route.tree is not None and getattr(route.handler, "type", "") in jsts.FUNCTION_TYPES:
            yield from _js_mass(ctx, route)


@rule(
    "OWASP-A01-CLIENT-ONLY-GUARD",
    review="owasp",
    severity="medium",
    exploitability="medium",
    owasp="A01",
)
def client_only_guard(ctx: Context) -> Iterator[Finding]:
    ui = None
    for entry in ctx.index.files:
        if entry.rel.endswith(UI_SUFFIXES) and not is_test(entry.rel):
            text = ctx.index.text(entry.rel)
            match = UI_ADMIN.search(text)
            if match:
                ui = Location(entry.rel, line_of(text, match.start()))
                break
    if ui is None:
        return
    for route in ctx.detection.routes:
        if re.search(r"(?:^|/)admin(?:/|$)", route.path) and access(ctx, route).level != ADMIN:
            yield make_finding(
                "OWASP-A01-CLIENT-ONLY-GUARD",
                tag=Tag.INFERRED,
                locations=[Location(route.file, route.line), ui],
                snippet=snippet(ctx.index.text(route.file), route.line),
                method=route.method,
                path=route.path,
            )
```

`src/dpr/data/rule_text/owasp_files.yaml`:

```yaml
OWASP-A01-PATH-TRAVERSAL:
  title: ${method} ${path} writes a file to a path built from ${source}
  effort_minutes: 20
  detail: In ${method} ${path}, ${source} reaches a file write path without being reduced to a safe file name, so ../ segments or an absolute name can place the file outside the upload folder.
  proof_needed: Confirm the call reaches the helper shown and that no caller validates the value first.
  attack: Upload with a file name or identifier such as ../../app/main.py and overwrite a file the server later loads or serves.
  blast: Any file the app's process can write, which can mean code execution on the next restart.
  fix: Store uploads under a server-generated name (a UUID plus a checked extension), use only Path(name).name or secure_filename for display, validate identifiers as UUIDs, and assert the resolved path is inside the upload root before writing.
  verify: Upload a file named ../escape.txt and confirm it is rejected or stored inside the upload folder under a generated name.
OWASP-A01-MASS-ASSIGNMENT:
  title: Request body written whole into ${model}
  effort_minutes: 15
  detail: The request body is passed straight into a ${model} create or update, so the caller chooses which columns to set, including ${fields}.
  proof_needed: Check whether the model has columns a caller must not set, such as role, is_admin, org_id or plan.
  attack: Add "role":"admin" (or org_id, plan, is_staff) to the JSON body of a normal request and read the account back.
  blast: Privilege escalation or cross-tenant writes for every caller who can reach this route.
  fix: Build the data object from an explicit list of allowed fields (a schema or DTO), never from the raw body.
  verify: Send the request with an extra role or org_id field and confirm the stored record ignores it.
OWASP-A01-CLIENT-ONLY-GUARD:
  title: Admin route ${method} ${path} has no server-side role check
  effort_minutes: 15
  detail: The UI hides admin features behind an admin check, but ${method} ${path} only checks that the caller is signed in, or not even that.
  proof_needed: Check whether a middleware, layout or proxy outside this handler enforces an admin role for this path.
  attack: Sign in as a normal user and call ${method} ${path} directly; the hidden button was the only guard.
  blast: Every admin action this route performs.
  fix: Enforce the admin role in the route handler or a dependency it cannot bypass, and treat the UI check as cosmetic.
  verify: Call ${method} ${path} as a non-admin user and expect 403.
```

Modify `src/dpr/reviews/owasp.py`, replace:

```python
import dpr.reviews.owasp_a01  # noqa: F401  (registers rules)
```

with:

```python
import dpr.reviews.owasp_a01  # noqa: F401  (registers rules)
import dpr.reviews.owasp_assign  # noqa: F401  (registers rules)
import dpr.reviews.owasp_paths  # noqa: F401  (registers rules)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest -q`
Expected: PASS (all tests, including 5 new ones)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/reviews/owasp_paths.py src/dpr/reviews/owasp_assign.py src/dpr/reviews/owasp.py src/dpr/data/rule_text/owasp_files.yaml tests/reviews/test_owasp_paths.py tests/reviews/test_owasp_assign.py
git commit -m "Add OWASP A01 checks for path traversal in file writes, mass assignment and client-only admin guards"
```

---
### Task 41: OWASP injection, weak tokens, secrets in URLs, client prices and SSRF

**Files:**
- Create: `src/dpr/reviews/owasp_inject.py`, `src/dpr/reviews/owasp_misc.py`, `src/dpr/data/rule_text/owasp_inject.yaml`
- Modify: `src/dpr/reviews/owasp.py` (import the rule modules)
- Test: `tests/reviews/test_owasp_inject.py`

**Interfaces:**
- Consumes: `request_params` (Task 40), `is_test` (Task 37), plus the Milestone 1 helpers used by every rule module
- Produces:
  - `dpr.reviews.owasp_inject.REQUEST_VALUE`: pattern for request-derived values (`req.body/query/params`, `request.GET/POST/args/form/json/data/query_params/body`, `searchParams.get(`, `params.x`)
  - Registered rules (review `owasp`):
    - `OWASP-A03-RAW-SQL` (high): `$queryRawUnsafe`/`$executeRawUnsafe` with a non-literal, `.query/.execute/.raw/.unsafe` with a template or concatenated string, Python `execute/executemany/executescript/raw`, bare `text` or `sqlalchemy.text` with an f-string, `%`, `+` or `.format`. CONFIRMED when a request value appears in the enclosing function, else INFERRED. Alembic and `migrations/` folders are skipped: their formatted SQL comes from constants.
    - `OWASP-A03-XSS-SINK` (high, INFERRED): `dangerouslySetInnerHTML` with a non-literal, `v-html`, `{@html}`, `innerHTML`/`outerHTML` assigned a dynamic string, `mark_safe`/`Markup` with a non-literal
    - `OWASP-A03-COMMAND` (high, INFERRED): `exec`/`execSync`/`eval` with a dynamic argument, `new Function`, `os.system`/`os.popen`/`eval`/`exec` with a non-literal, `subprocess` with `shell=True` and a non-literal
    - `OWASP-A03-HTML-EMAIL` (low, INFERRED): in Python files whose path mentions mail, notification, SMTP or a mail provider, f-strings containing HTML tags that interpolate a value that is not escaped. Treated as safe: escaped calls and names assigned from them, constants and ALL_CAPS names, settings or config attributes, parameters and variables named like markup fragments (`content`, `body`, `html`, `rows`, `*_html`, `html_*`, `*_rows`), and loop names that take constant labels from a literal list of tuples. One finding per file.
    - `OWASP-A02-WEAK-RANDOM-TOKEN` (high, INFERRED): `Math.random()` or `random.*` assigned to a name containing token, secret, code, otp, reset, nonce, password, salt or api key
    - `OWASP-A02-SECRET-IN-URL` (medium, INFERRED): a built URL carrying `password`, `apikey`, `api_key`, `secret`, `client_secret`, `access_token` or `token` in its query string. One-time links (reset, verify, confirm, invite, magic, activate, unsubscribe) with `token=` are not reported.
    - `OWASP-A04-CLIENT-PRICE` (high, INFERRED): a payment call (Stripe, checkout, payment intent, Paddle, Lemon Squeezy) in a route whose arguments read `price`, `amount`, `total`, `unit_amount`, `discount`, `plan` or `is_paid` from the request body
    - `OWASP-A10-SSRF` (high, INFERRED): `fetch`, `axios`, `got`, `ky`, `needle`, `requests`, `httpx`, `aiohttp` or `urlopen` in a route handler with a URL from the request (for FastAPI, from a request parameter) and no allowlist name in the handler

- [ ] **Step 1: Write the failing tests**

`tests/reviews/test_owasp_inject.py`:

```python
from tests.reviews.helpers import findings_for, write


def locs(found):
    return sorted((str(f.locations[0]), f.tag.value) for f in found)


def test_raw_sql(tmp_path):
    write(
        tmp_path,
        "app/api/search/route.ts",
        "export async function GET(req: Request) {\n"
        "  const q = new URL(req.url).searchParams.get('q')\n"
        "  await prisma.$queryRawUnsafe(`select * from notes where body like '%${q}%'`)\n"
        "  await prisma.$queryRaw`select * from notes where id = ${q}`\n"
        "  await pool.query('select 1')\n"
        "}\n",
    )
    write(
        tmp_path,
        "shop/views.py",
        "def search(request):\n"
        "    term = request.GET['q']\n"
        "    cursor.execute(f\"select * from orders where name = '{term}'\")\n"
        "    cursor.execute('select * from orders where id = %s', [term])\n"
        "def report(table):\n    return db.execute(text('select * from ' + table))\n",
    )
    write(
        tmp_path,
        "shop/charts.py",
        "def label(ax, height):\n    ax.text(1, height, f'{height:.2f}')\n",
    )
    write(
        tmp_path,
        "alembic/versions/001_add.py",
        "def upgrade():\n    for name in COLUMNS:\n        op.execute(f'ALTER TABLE t ADD COLUMN {name} text')\n",
    )
    assert locs(findings_for(tmp_path, "owasp", "OWASP-A03-RAW-SQL")) == [
        ("app/api/search/route.ts:3", "CONFIRMED"),
        ("shop/views.py:3", "CONFIRMED"),
        ("shop/views.py:6", "INFERRED"),
    ]


def test_xss_sinks(tmp_path):
    write(
        tmp_path,
        "src/Bio.tsx",
        "export const Bio = ({ bio }) => (\n  <div>\n    <p dangerouslySetInnerHTML={{ __html: bio }} />\n"
        "    <p dangerouslySetInnerHTML={{ __html: '<b>static</b>' }} />\n  </div>\n)\n",
    )
    write(
        tmp_path,
        "src/Note.vue",
        '<template>\n  <div v-html="note.body"></div>\n</template>\n<script>\nexport default {}\n</script>\n',
    )
    write(
        tmp_path,
        "src/render.js",
        "el.innerHTML = `<p>${comment}</p>`\nel.innerHTML = '<p>ok</p>'\n",
    )
    write(
        tmp_path,
        "web/views.py",
        "from markupsafe import Markup\ndef show(bio):\n    return Markup(bio)\nsafe = Markup('<b>x</b>')\n",
    )
    assert [loc for loc, _ in locs(findings_for(tmp_path, "owasp", "OWASP-A03-XSS-SINK"))] == [
        "src/Bio.tsx:3",
        "src/Note.vue:2",
        "src/render.js:1",
        "web/views.py:3",
    ]


def test_command_execution(tmp_path):
    write(
        tmp_path,
        "server/convert.js",
        "const { exec } = require('child_process')\n"
        "exec(`convert ${req.body.file} out.png`)\nexec('ls -la')\nconst fn = new Function(code)\n",
    )
    write(
        tmp_path,
        "tools/run.py",
        "import os, subprocess\n"
        "subprocess.run(f'tar -xf {name}', shell=True)\n"
        "subprocess.run(['tar', '-xf', name])\n"
        "os.system('make build')\n"
        "eval(user_expression)\n",
    )
    assert [loc for loc, _ in locs(findings_for(tmp_path, "owasp", "OWASP-A03-COMMAND"))] == [
        "server/convert.js:2",
        "server/convert.js:4",
        "tools/run.py:2",
        "tools/run.py:5",
    ]


def test_html_email(tmp_path):
    write(
        tmp_path,
        "app/services/email_service.py",
        "import html\n"
        "def welcome(first_name, url):\n"
        "    body = f'<h2>Welcome, {first_name}!</h2><a href=\"{url}\">Go</a>'\n"
        "    safe = html.escape(first_name)\n"
        "    ok = f'<p>Hi {safe}</p>'\n"
        "    plain = f'Hi {first_name}'\n"
        "    also_ok = f'<p>{html.escape(url)}</p>'\n"
        "    return body, ok, plain, also_ok\n"
        "def rows(values):\n"
        "    detail = [('Name', values['name']), ('Note', values['note'])]\n"
        "    items_html = ''.join(f'<li>{label}: {html.escape(value)}</li>' for label, value in detail)\n"
        "    return f'<ul>{items_html}</ul><p>{FOOTER}</p>'\n"
        "def base(content, preview):\n"
        "    name = settings.app_name\n"
        "    return f'<html><body><h1>{name}</h1>{content}<p>{self._settings.footer}</p></body></html>'\n",
    )
    write(tmp_path, "app/services/report.py", "def page(name):\n    return f'<p>{name}</p>'\n")
    [f] = findings_for(tmp_path, "owasp", "OWASP-A03-HTML-EMAIL")
    assert [str(loc) for loc in f.locations] == ["app/services/email_service.py:3"]


def test_weak_random_and_secret_urls(tmp_path):
    write(
        tmp_path,
        "lib/tokens.ts",
        "const resetToken = Math.random().toString(36)\nconst jitter = Math.random() * 10\n"
        "const url = `${base}/api?apikey=${key}`\n"
        "const link = `${base}/reset-password?token=${token}`\n"
        "const doc = 'https://example.com/?token=abc'\n",
    )
    write(
        tmp_path,
        "app/codes.py",
        "import random\notp_code = random.randint(100000, 999999)\nshuffle = random.random()\n",
    )
    assert [
        loc for loc, _ in locs(findings_for(tmp_path, "owasp", "OWASP-A02-WEAK-RANDOM-TOKEN"))
    ] == [
        "app/codes.py:2",
        "lib/tokens.ts:1",
    ]
    assert [loc for loc, _ in locs(findings_for(tmp_path, "owasp", "OWASP-A02-SECRET-IN-URL"))] == [
        "lib/tokens.ts:3"
    ]


def test_client_price_and_ssrf(tmp_path):
    write(
        tmp_path,
        "app/api/checkout/route.ts",
        "export async function POST(req: Request) {\n  const body = await req.json()\n"
        "  await stripe.paymentIntents.create({ amount: body.amount, currency: 'usd' })\n"
        "  await stripe.paymentIntents.create({ amount: PRICES[body.productId], currency: 'usd' })\n}\n",
    )
    write(
        tmp_path,
        "app/api/preview/route.ts",
        "export async function GET(req: Request) {\n"
        "  const target = new URL(req.url).searchParams.get('url')\n  return fetch(target)\n}\n",
    )
    write(
        tmp_path,
        "api/main.py",
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "@app.get('/fetch')\nasync def fetch_url(url: str):\n    return httpx.get(url)\n"
        "@app.get('/safe')\nasync def safe(url: str):\n"
        "    if urlparse(url).hostname not in ALLOWED_HOSTS:\n        raise ValueError()\n"
        "    return httpx.get(url)\n",
    )
    [price] = findings_for(tmp_path, "owasp", "OWASP-A04-CLIENT-PRICE")
    assert str(price.locations[0]) == "app/api/checkout/route.ts:3"
    assert [loc for loc, _ in locs(findings_for(tmp_path, "owasp", "OWASP-A10-SSRF"))] == [
        "api/main.py:5",
        "app/api/preview/route.ts:3",
    ]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/reviews/test_owasp_inject.py -q`
Expected: FAIL (the rules are not registered, so every assertion compares an empty result with the expected findings)

- [ ] **Step 3: Write the rules and the rule text**

`src/dpr/reviews/owasp_inject.py`:

```python
"""Review 5, OWASP A03: raw SQL, XSS sinks, command execution and HTML built into emails."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Tag
from dpr.parsing import jsts, pyast
from dpr.redact import snippet
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule
from dpr.walk import line_of

REQUEST_VALUE = re.compile(
    r"\breq\.(?:body|query|params)|\brequest\.(?:GET|POST|args|form|json|data|query_params|body)"
    r"|searchParams\.get\(|\bparams\.\w+"
)
JS_SQL = re.compile(
    r"(?:\w+\.)?(?:\$queryRawUnsafe|\$executeRawUnsafe)|\w+\.(?:query|execute|raw|unsafe)"
)
PY_SQL = re.compile(
    r"(?:[\w.()]+\.)?(?:execute|executemany|executescript|raw)|text|(?:sqlalchemy|sa)\.text"
)
MIGRATIONS = re.compile(r"(?:^|/)(?:alembic|migrations)/")
JS_COMMAND = re.compile(r"(?:child_process\.|cp\.)?(exec|execSync)$|^eval$")
PY_COMMAND = re.compile(r"(?:os\.system|os\.popen|eval|exec)$")
PY_SUBPROCESS = re.compile(r"subprocess\.(?:run|call|check_call|check_output|Popen)$")
HTML_TAG = re.compile(r"<(?:p|div|h[1-6]|a|td|tr|table|span|strong|em|li|ul|br|body|html)\b", re.I)
MAIL_CONTEXT = re.compile(r"(?i)e?mail|notif|smtp|sendgrid|postmark|resend")
ESCAPES = re.compile(r"(?:^|\.)(?:escape|quote|bleach\.clean|clean)$")


def _dynamic_string(node) -> bool:
    node = jsts.unwrap(node)
    if node is None:
        return False
    if node.type == "template_string":
        return any(c.type == "template_substitution" for c in node.named_children)
    if node.type == "binary_expression":
        return "+" in jsts.node_text(node) and any(
            c.type in ("identifier", "member_expression", "call_expression")
            for c in node.named_children
        )
    return node.type in ("identifier", "member_expression", "call_expression")


def _py_dynamic(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
        return True
    return isinstance(node, ast.Call) and (pyast.dotted(node.func) or "").endswith(".format")


def _sql(ctx: Context, rel: str, line: int, scope_text: str, what: str) -> Finding:
    from_request = bool(REQUEST_VALUE.search(scope_text))
    return make_finding(
        "OWASP-A03-RAW-SQL",
        tag=Tag.CONFIRMED if from_request else Tag.INFERRED,
        locations=[Location(rel, line)],
        snippet=snippet(ctx.index.text(rel), line),
        what=what,
    )


@rule("OWASP-A03-RAW-SQL", review="owasp", severity="high", exploitability="high", owasp="A03")
def raw_sql(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.js_files:
        if is_test(entry.rel):
            continue
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for call in jsts.calls(tree, JS_SQL):
                args = jsts.arguments(call)
                name = jsts.callee(call)
                first = jsts.unwrap(args[0]) if args else None
                unsafe = "Unsafe" in name and first is not None and jsts.string_value(first) is None
                built = (
                    first is not None
                    and first.type in ("template_string", "binary_expression")
                    and _dynamic_string(first)
                )
                if not (unsafe or built):
                    continue
                fn = jsts.enclosing_function(call)
                scope = jsts.node_text(fn) if fn is not None else jsts.node_text(call)
                what = f"{name} receives SQL built from values at runtime."
                yield _sql(ctx, entry.rel, jsts.line(tree, call), scope, what)
    for entry in ctx.index.py_files:
        if is_test(entry.rel) or MIGRATIONS.search(entry.rel):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for call in pyast.calls(tree, PY_SQL) if tree else []:
            if not call.args or not _py_dynamic(call.args[0]):
                continue
            fn = pyast.function_at(tree, call.lineno)
            scope = ast.unparse(fn) if fn is not None else ast.unparse(call)
            name = pyast.dotted(call.func) or "execute"
            what = f"{name} receives SQL built with string formatting."
            yield _sql(ctx, entry.rel, call.lineno, scope, what)


def _xss(ctx: Context, rel: str, line: int, sink: str) -> Finding:
    return make_finding(
        "OWASP-A03-XSS-SINK",
        tag=Tag.INFERRED,
        locations=[Location(rel, line)],
        snippet=snippet(ctx.index.text(rel), line),
        sink=sink,
    )


@rule("OWASP-A03-XSS-SINK", review="owasp", severity="high", exploitability="medium", owasp="A03")
def xss_sink(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.js_files:
        if is_test(entry.rel):
            continue
        text = ctx.index.text(entry.rel)
        for match in re.finditer(
            r"dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*([^}]+)\}\}", text
        ):
            value = match.group(1).strip()
            if not re.fullmatch(r"""(['"`])[^'"`$]*\1""", value):
                yield _xss(ctx, entry.rel, line_of(text, match.start()), "dangerouslySetInnerHTML")
        for match in re.finditer(r"\bv-html\s*=|\{@html\s", text):
            yield _xss(ctx, entry.rel, line_of(text, match.start()), match.group(0).strip(" ={"))
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for node in jsts.walk(tree.root, {"assignment_expression"}):
                left = jsts.node_text(node.child_by_field_name("left"))
                right = node.child_by_field_name("right")
                if left.endswith((".innerHTML", ".outerHTML")) and _dynamic_string(right):
                    yield _xss(ctx, entry.rel, jsts.line(tree, node), "innerHTML")
    for entry in ctx.index.py_files:
        if is_test(entry.rel):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for call in pyast.calls(tree, r"(?:\w+\.)*(mark_safe|Markup)") if tree else []:
            if call.args and not isinstance(call.args[0], ast.Constant):
                yield _xss(ctx, entry.rel, call.lineno, pyast.dotted(call.func))


@rule("OWASP-A03-COMMAND", review="owasp", severity="high", exploitability="high", owasp="A03")
def command(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.js_files:
        if is_test(entry.rel):
            continue
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for call in jsts.calls(tree, JS_COMMAND):
                args = jsts.arguments(call)
                if args and _dynamic_string(args[0]):
                    line = jsts.line(tree, call)
                    yield make_finding(
                        "OWASP-A03-COMMAND",
                        tag=Tag.INFERRED,
                        locations=[Location(entry.rel, line)],
                        snippet=snippet(ctx.index.text(entry.rel), line),
                        call=jsts.callee(call),
                    )
            for node in jsts.walk(tree.root, {"new_expression"}):
                if jsts.node_text(node.child_by_field_name("constructor")) == "Function":
                    line = jsts.line(tree, node)
                    yield make_finding(
                        "OWASP-A03-COMMAND",
                        tag=Tag.INFERRED,
                        locations=[Location(entry.rel, line)],
                        snippet=snippet(ctx.index.text(entry.rel), line),
                        call="new Function",
                    )
    for entry in ctx.index.py_files:
        if is_test(entry.rel):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for call in pyast.calls(tree, r"[\w.]+") if tree else []:
            name = pyast.dotted(call.func) or ""
            if not call.args or isinstance(call.args[0], ast.Constant | ast.List):
                continue
            shell = pyast.constant(pyast.kwarg(call, "shell")) is True
            if PY_COMMAND.fullmatch(name) or (PY_SUBPROCESS.fullmatch(name) and shell):
                yield make_finding(
                    "OWASP-A03-COMMAND",
                    tag=Tag.INFERRED,
                    locations=[Location(entry.rel, call.lineno)],
                    snippet=snippet(ctx.index.text(entry.rel), call.lineno),
                    call=name,
                )


TRUSTED = re.compile(r"(?i)settings|config")
MARKUP_NAME = re.compile(r"(?i)^(?:content|body|html|template|rows|\w+_html|html_\w+|\w+_rows)$")


def _safe_value(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) or (isinstance(node, ast.Name) and node.id.isupper()):
        return True
    if isinstance(node, ast.Call) and ESCAPES.search(pyast.dotted(node.func) or ""):
        return True
    return isinstance(node, ast.Attribute) and bool(TRUSTED.search(ast.unparse(node)))


def _constant_loop_names(fn: ast.AST) -> set[str]:
    """Loop targets that take constant values from a literal list of tuples."""
    literals = {
        node.targets[0].id: node.value
        for node in ast.walk(fn)
        if isinstance(node, ast.Assign)
        and isinstance(node.targets[0], ast.Name)
        and isinstance(node.value, ast.List | ast.Tuple)
    }
    names = set()
    for node in ast.walk(fn):
        if not isinstance(node, ast.comprehension | ast.For) or not isinstance(
            node.target, ast.Tuple
        ):
            continue
        rows = literals.get(node.iter.id) if isinstance(node.iter, ast.Name) else None
        if rows is None or not all(isinstance(r, ast.Tuple) for r in rows.elts):
            continue
        for position, target in enumerate(node.target.elts):
            if isinstance(target, ast.Name) and all(
                len(r.elts) > position and isinstance(r.elts[position], ast.Constant)
                for r in rows.elts
            ):
                names.add(target.id)
    return names


def _escaped_names(fn: ast.AST) -> set[str]:
    names = {a.arg for a in fn.args.args if MARKUP_NAME.match(a.arg)} | _constant_loop_names(fn)
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            if _safe_value(node.value) or MARKUP_NAME.match(node.targets[0].id):
                names.add(node.targets[0].id)
    return names


def _unescaped(fn: ast.AST) -> list[ast.JoinedStr]:
    escaped = _escaped_names(fn)
    found = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.JoinedStr):
            continue
        literal = "".join(v.value for v in node.values if isinstance(v, ast.Constant))
        if not HTML_TAG.search(literal):
            continue
        for value in node.values:
            if not isinstance(value, ast.FormattedValue):
                continue
            expr = value.value
            if _safe_value(expr) or (isinstance(expr, ast.Name) and expr.id in escaped):
                continue
            found.append(node)
            break
    return found


@rule("OWASP-A03-HTML-EMAIL", review="owasp", severity="low", exploitability="low", owasp="A03")
def html_email(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel) or not MAIL_CONTEXT.search(entry.rel) or "<" not in text:
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        lines = (
            sorted({n.lineno for fn in pyast.functions(tree) for n in _unescaped(fn)})
            if tree
            else []
        )
        if lines:
            yield make_finding(
                "OWASP-A03-HTML-EMAIL",
                tag=Tag.INFERRED,
                locations=[Location(entry.rel, n) for n in lines[:5]],
                snippet=snippet(text, lines[0]),
                count=len(lines),
            )
```

`src/dpr/reviews/owasp_misc.py`:

```python
"""Review 5, OWASP A02, A04 and A10: weak random tokens, secrets in URLs, client prices, SSRF."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Tag
from dpr.parsing import jsts, pyast
from dpr.redact import snippet
from dpr.reviews.owasp_inject import REQUEST_VALUE
from dpr.reviews.owasp_paths import request_params
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule
from dpr.walk import line_of

TOKEN_NAME = re.compile(r"(?i)token|secret|code|otp|reset|nonce|password|salt|api_?key")
PY_RANDOM = re.compile(r"random\.(?:random|choice|choices|randint|randrange|sample|getrandbits)")
SECRET_PARAM = re.compile(
    r"""[?&](password|passwd|pwd|apikey|api_key|secret|client_secret|access_token|token)="""
)
ONE_TIME_LINK = re.compile(r"(?i)reset|verif|confirm|invite|magic|activate|unsubscribe")
PRICE_FIELD = re.compile(
    r"(?:body|req\.body|request\.(?:json|data|POST|form)|payload|data|input|params)"
    r"""(?:\??\.|\[['"])(price|amount|total|unit_amount|discount|plan|is_?paid)\b""",
    re.IGNORECASE,
)
PAYMENT_CALL = re.compile(r"(?i)stripe|checkout|payment_?intent|paddle|lemon")
JS_FETCH = re.compile(r"fetch|axios(?:\.(?:get|post|put|patch|delete|request))?|got|ky|needle")
PY_FETCH = re.compile(
    r"(?:requests|httpx|client|session|aiohttp\.ClientSession\(\))\.(?:get|post|put|patch|delete"
    r"|request|head)|urllib\.request\.urlopen|urlopen"
)
ALLOWLIST = re.compile(r"(?i)allow_?list|allowed_?(?:hosts|domains|origins)|ALLOWED|whitelist")


def _weak(ctx: Context, rel: str, line: int, name: str, call: str) -> Finding:
    return make_finding(
        "OWASP-A02-WEAK-RANDOM-TOKEN",
        tag=Tag.INFERRED,
        locations=[Location(rel, line)],
        snippet=snippet(ctx.index.text(rel), line),
        name=name,
        call=call,
    )


@rule(
    "OWASP-A02-WEAK-RANDOM-TOKEN",
    review="owasp",
    severity="high",
    exploitability="medium",
    owasp="A02",
)
def weak_random_token(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.js_files:
        if is_test(entry.rel) or "Math.random" not in ctx.index.text(entry.rel):
            continue
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for node in jsts.walk(tree.root, {"variable_declarator", "assignment_expression"}):
                field = "name" if node.type == "variable_declarator" else "left"
                name = jsts.node_text(node.child_by_field_name(field))
                value = jsts.node_text(
                    node.child_by_field_name("value" if field == "name" else "right")
                )
                if "Math.random" in value and TOKEN_NAME.search(name):
                    yield _weak(ctx, entry.rel, jsts.line(tree, node), name, "Math.random()")
    for entry in ctx.index.py_files:
        if is_test(entry.rel) or "random" not in ctx.index.text(entry.rel):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for node in ast.walk(tree) if tree else []:
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
                name = node.targets[0].id
                calls = [
                    pyast.dotted(c.func) for c in ast.walk(node.value) if isinstance(c, ast.Call)
                ]
                weak = [c for c in calls if c and PY_RANDOM.fullmatch(c)]
                if weak and TOKEN_NAME.search(name):
                    yield _weak(ctx, entry.rel, node.lineno, name, weak[0])


@rule(
    "OWASP-A02-SECRET-IN-URL",
    review="owasp",
    severity="medium",
    exploitability="low",
    owasp="A02",
)
def secret_in_url(ctx: Context) -> Iterator[Finding]:
    for entry in [*ctx.index.js_files, *ctx.index.py_files]:
        if is_test(entry.rel):
            continue
        text = ctx.index.text(entry.rel)
        for match in SECRET_PARAM.finditer(text):
            line = line_of(text, match.start())
            line_text = text.splitlines()[line - 1]
            if match.group(1) == "token" and ONE_TIME_LINK.search(line_text):
                continue
            if not re.search(r"\$\{|\{\w|%s|\+\s*\w|['\"]\s*\+", line_text):
                continue
            yield make_finding(
                "OWASP-A02-SECRET-IN-URL",
                tag=Tag.INFERRED,
                locations=[Location(entry.rel, line)],
                snippet=snippet(text, line),
                param=match.group(1),
            )


@rule("OWASP-A04-CLIENT-PRICE", review="owasp", severity="high", exploitability="high", owasp="A04")
def client_price(ctx: Context) -> Iterator[Finding]:
    for route in ctx.detection.routes:
        handler = route.handler
        if handler is None or is_test(route.file):
            continue
        if isinstance(handler, ast.AST):
            nodes = [
                (n.lineno, ast.unparse(n)) for n in ast.walk(handler) if isinstance(n, ast.Call)
            ]
            names = [(line, text.split("(", 1)[0]) for line, text in nodes]
        elif route.tree is not None and getattr(handler, "type", "") in jsts.FUNCTION_TYPES:
            calls = list(jsts.calls(route.tree, re.compile(r".*"), handler))
            nodes = [(jsts.line(route.tree, c), jsts.node_text(c)) for c in calls]
            names = [(jsts.line(route.tree, c), jsts.callee(c)) for c in calls]
        else:
            continue
        for (line, text), (_, name) in zip(nodes, names, strict=True):
            field = PRICE_FIELD.search(text)
            if field and PAYMENT_CALL.search(name):
                yield make_finding(
                    "OWASP-A04-CLIENT-PRICE",
                    tag=Tag.INFERRED,
                    locations=[Location(route.file, line)],
                    snippet=snippet(ctx.index.text(route.file), line),
                    field=field.group(1),
                )
                break


@rule("OWASP-A10-SSRF", review="owasp", severity="high", exploitability="high", owasp="A10")
def ssrf(ctx: Context) -> Iterator[Finding]:
    for route in ctx.detection.routes:
        handler = route.handler
        if handler is None or is_test(route.file):
            continue
        if isinstance(handler, ast.FunctionDef | ast.AsyncFunctionDef):
            scope = ast.unparse(handler)
            for call in pyast.calls(route.tree, PY_FETCH, handler):
                target = ast.unparse(call.args[0]) if call.args else ""
                target_names = pyast.names_in(call.args[0]) if call.args else set()
                assigned = [
                    ast.unparse(n.value)
                    for n in ast.walk(handler)
                    if isinstance(n, ast.Assign)
                    and isinstance(n.targets[0], ast.Name)
                    and n.targets[0].id in target_names
                ]
                params = set(request_params(ctx, route)) - {"request"}
                from_request = REQUEST_VALUE.search(" ".join([target, *assigned]))
                if (from_request or target_names & params) and not ALLOWLIST.search(scope):
                    yield _ssrf(ctx, route.file, call.lineno)
        elif route.tree is not None and getattr(handler, "type", "") in jsts.FUNCTION_TYPES:
            scope = jsts.node_text(handler)
            for call in jsts.calls(route.tree, JS_FETCH, handler):
                args = jsts.arguments(call)
                first = jsts.unwrap(args[0]) if args else None
                text = jsts.node_text(first)
                if first is not None and first.type == "identifier":
                    resolved = jsts.resolve_identifier(first)
                    text = jsts.node_text(resolved) if resolved is not None else text
                if REQUEST_VALUE.search(text) and not ALLOWLIST.search(scope):
                    yield _ssrf(ctx, route.file, jsts.line(route.tree, call))


def _ssrf(ctx: Context, rel: str, line: int) -> Finding:
    return make_finding(
        "OWASP-A10-SSRF",
        tag=Tag.INFERRED,
        locations=[Location(rel, line)],
        snippet=snippet(ctx.index.text(rel), line),
    )
```

`src/dpr/data/rule_text/owasp_inject.yaml`:

```yaml
OWASP-A03-RAW-SQL:
  title: SQL built from runtime values
  effort_minutes: 20
  detail: ${what}
  proof_needed: Trace whether any value in the string can come from a request.
  attack: Send a value such as ' OR 1=1 -- in the field that reaches this string and read or change rows the query was not meant to touch.
  blast: Every table the database login can reach.
  fix: Use bound parameters (text("... where id = :id") with a params dict, $queryRaw tagged templates, cursor.execute(sql, params)) and never format values into SQL.
  verify: Send a single quote in the input and confirm the query treats it as data, not an error.
OWASP-A03-XSS-SINK:
  title: HTML inserted without escaping through ${sink}
  effort_minutes: 20
  detail: Content reaches the page through ${sink}, which skips the framework's escaping.
  proof_needed: Check whether the inserted value can contain user-supplied content.
  attack: Store a value such as <img src=x onerror=alert(document.cookie)> where it later renders here.
  blast: Sessions and actions of every user who views the rendered content.
  fix: Render the value as text, or sanitise it with a maintained HTML sanitiser (DOMPurify, bleach) before inserting it.
  verify: Save a value containing a script tag and confirm it renders as text.
OWASP-A03-COMMAND:
  title: Code or shell command built at runtime with ${call}
  effort_minutes: 20
  detail: ${call} receives a value computed at runtime, so a crafted value can run extra commands or code.
  proof_needed: Trace whether any part of the value can come from a request, a file upload or stored user data.
  attack: Put ; or $(...) in the input that reaches this call and run commands on the server.
  blast: Everything the server process can read, write or reach on the network.
  fix: Pass arguments as a list without a shell (subprocess.run([...]), execFile), validate values against an allowlist, and remove eval or new Function.
  verify: Send a value containing ; id and confirm no second command runs.
OWASP-A03-HTML-EMAIL:
  title: Email HTML interpolates values without escaping
  effort_minutes: 15
  detail: ${count} HTML template string(s) in this email code insert values without html.escape, so a name or note containing markup renders as HTML in the recipient's mail client.
  proof_needed: Check which interpolated values users can set, such as names, notes or client details.
  attack: Register or edit a record with a name containing a link or markup; the email goes out under the company's sender with that content rendered.
  blast: Every recipient of emails built from these templates.
  fix: Escape every interpolated value with html.escape (or render through a template engine with autoescape on).
  verify: Set a name to <b>x</b>, trigger the email, and confirm the tags arrive as text.
OWASP-A02-WEAK-RANDOM-TOKEN:
  title: ${name} generated with ${call}
  effort_minutes: 5
  detail: ${name} comes from ${call}, which is predictable and not meant for secrets.
  proof_needed: Confirm the value is used as a token, code or secret.
  attack: Observe a few generated values and predict the next reset code or token.
  blast: Accounts or actions protected by the predictable value.
  fix: Use crypto.randomBytes or crypto.randomUUID in JavaScript and secrets.token_urlsafe in Python.
  verify: Confirm the code path now uses a cryptographic random source.
OWASP-A02-SECRET-IN-URL:
  title: ${param} sent in a URL query string
  effort_minutes: 15
  detail: A URL built here carries ${param} in the query string, which ends up in server logs, proxy logs, browser history and Referer headers.
  proof_needed: Check whether the value is a real credential and where the URL is sent or logged.
  blast: Anyone who can read the logs or history where the URL lands.
  fix: Send the value in a header or a POST body instead of the query string.
  verify: Inspect the outgoing request and confirm the value is not in the URL.
OWASP-A04-CLIENT-PRICE:
  title: Payment uses the ${field} sent by the client
  effort_minutes: 30
  detail: A payment call in this route reads ${field} from the request instead of recomputing it on the server.
  proof_needed: Check whether the value is recomputed or validated before the charge.
  attack: Edit the request in devtools and set ${field} to 1 cent, or a paid plan to the cheapest one.
  blast: Revenue on every purchase made through this route.
  fix: Look up the price or plan from the server-side catalogue by product ID and ignore client-sent amounts.
  verify: Send the request with a changed amount and confirm the charge uses the catalogue price.
OWASP-A10-SSRF:
  title: Server fetches a URL taken from the request
  effort_minutes: 30
  detail: The route passes a request value to an outbound HTTP call with no host allowlist in the handler.
  proof_needed: Check whether a proxy, egress firewall or wrapper restricts where the server can connect.
  attack: Send http://169.254.169.254/latest/meta-data/ or an internal hostname as the URL and read the response.
  blast: Cloud metadata credentials and internal services reachable from the server.
  fix: Parse the URL, allow only https and an explicit host allowlist, resolve and reject private and link-local addresses, and disable redirects.
  verify: Send the metadata address and confirm the request is rejected before any connection.
```

Modify `src/dpr/reviews/owasp.py`, replace:

```python
import dpr.reviews.owasp_assign  # noqa: F401  (registers rules)
```

with:

```python
import dpr.reviews.owasp_assign  # noqa: F401  (registers rules)
import dpr.reviews.owasp_inject  # noqa: F401  (registers rules)
import dpr.reviews.owasp_misc  # noqa: F401  (registers rules)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest -q`
Expected: PASS (all tests, including 6 new ones)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/reviews/owasp_inject.py src/dpr/reviews/owasp_misc.py src/dpr/reviews/owasp.py src/dpr/data/rule_text/owasp_inject.yaml tests/reviews/test_owasp_inject.py
git commit -m "Add OWASP checks for injection, weak tokens, secrets in URLs, client prices and SSRF"
```

---
### Task 42: Supply chain, deserialisation, CI, XML parsing and failed sign-in logging

**Files:**
- Create: `src/dpr/reviews/owasp_integrity.py`, `src/dpr/data/rule_text/owasp_integrity.yaml`
- Modify: `src/dpr/reviews/owasp.py` (import the rule module)
- Test: `tests/reviews/test_owasp_integrity.py`

**Interfaces:**
- Consumes: `START_FILES` (Task 37), `is_test` (Task 37), `Detection.packages` (Task 16), plus the Milestone 1 helpers used by every rule module
- Produces registered rules (review `owasp`):
  - `OWASP-A08-NO-SRI` (low, CONFIRMED): `<script src="https://...">` without `integrity` in markup files, one finding per file
  - `OWASP-A08-UNSAFE-DESERIALISE` (high, INFERRED): `pickle`, `cPickle`, `dill` or `marshal` `load(s)`, `jsonpickle.decode`, `yaml.unsafe_load`, `yaml.load` without a safe loader, `node-serialize` `unserialize`
  - `OWASP-A08-CI-UNTRUSTED` (high, CONFIRMED): a GitHub workflow on `pull_request_target` that references the pull request head SHA or ref
  - `OWASP-A08-UNPINNED-DEPS` (low, CONFIRMED): a `requirements*.txt` where at least half the requirements lack `==`, with no hashes and no lock file in the same folder; a `package.json` with dependencies and no npm, yarn, pnpm or bun lock file in its folder or any parent
  - `OWASP-A08-UNPINNED-INSTALL` (low, CONFIRMED; one finding per file): in start scripts, `pip install` of named packages without `==`; in CI files (`.github/workflows/*`, `azure-pipelines.yml`, `.gitlab-ci.yml`, `bitbucket-pipelines.yml`, `Jenkinsfile`, `cloudbuild.yaml`), the same plus `npx @scope/package` without a version, bare `npm install` instead of `npm ci`, and unversioned global npm installs
  - `OWASP-A09-NO-AUTH-FAIL-LOG` (low, INFERRED): a POST sign-in route (path or handler name with login, sign-in or token) whose handler returns 401 and contains no logger call
  - `OWASP-A05-XML-PARSER` (low, INFERRED): `ElementTree`, `minidom`, `xml.sax`, `lxml.etree` parse calls or `openpyxl.load_workbook` when no manifest declares `defusedxml`, one finding per file

- [ ] **Step 1: Write the failing tests**

`tests/reviews/test_owasp_integrity.py`:

```python
from tests.reviews.helpers import findings_for, write


def locs(found):
    return sorted(str(loc) for f in found for loc in f.locations)


def test_no_sri_and_deserialise(tmp_path):
    write(
        tmp_path,
        "public/index.html",
        '<script src="https://cdn.example.com/a.js"></script>\n'
        '<script src="https://cdn.example.com/b.js" integrity="sha384-x" crossorigin="anonymous"></script>\n'
        '<script src="/local.js"></script>\n',
    )
    write(
        tmp_path,
        "app/cache.py",
        "import pickle, yaml\n"
        "data = pickle.loads(blob)\n"
        "cfg = yaml.load(text)\n"
        "ok = yaml.load(text, Loader=yaml.SafeLoader)\n"
        "ok2 = yaml.safe_load(text)\n",
    )
    assert locs(findings_for(tmp_path, "owasp", "OWASP-A08-NO-SRI")) == ["public/index.html:1"]
    assert locs(findings_for(tmp_path, "owasp", "OWASP-A08-UNSAFE-DESERIALISE")) == [
        "app/cache.py:2",
        "app/cache.py:3",
    ]


def test_ci_untrusted(tmp_path):
    write(
        tmp_path,
        ".github/workflows/pr.yml",
        "on: pull_request_target\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n"
        "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
    )
    write(
        tmp_path,
        ".github/workflows/ci.yml",
        "on: pull_request\njobs:\n  b:\n    steps:\n      - run: echo ${{ github.head_ref }}\n",
    )
    assert locs(findings_for(tmp_path, "owasp", "OWASP-A08-CI-UNTRUSTED")) == [
        ".github/workflows/pr.yml:7"
    ]


def test_unpinned_dependencies(tmp_path):
    write(tmp_path, "api/requirements.txt", "# core\nfastapi>=0.100\nuvicorn\nhttpx==0.27.0\n")
    write(tmp_path, "worker/requirements.txt", "celery>=5\n")
    write(tmp_path, "worker/requirements.lock", "celery==5.3.0\n")
    write(tmp_path, "tools/requirements.txt", "black==24.1.0\nruff==0.6.0\nmypy>=1\n")
    write(tmp_path, "web/package.json", '{"dependencies": {"react": "^18"}}')
    write(tmp_path, "site/package.json", '{"dependencies": {"vue": "^3"}}')
    write(tmp_path, "package-lock.json", "{}")
    write(tmp_path, "site/.keep", "")
    found = findings_for(tmp_path, "owasp", "OWASP-A08-UNPINNED-DEPS")
    assert locs(found) == ["api/requirements.txt:2"]
    (tmp_path / "package-lock.json").unlink()
    assert locs(findings_for(tmp_path, "owasp", "OWASP-A08-UNPINNED-DEPS")) == [
        "api/requirements.txt:2",
        "site/package.json:1",
        "web/package.json:1",
    ]


def test_unpinned_install(tmp_path):
    write(
        tmp_path,
        "api/startup.sh",
        "#!/bin/bash\n# pip install nothing\npip install --quiet pysqlite3-binary\npip install -r requirements.txt\n"
        "pip install tool==1.0\n",
    )
    write(
        tmp_path,
        "azure-pipelines.yml",
        "steps:\n  - script: |\n      npm install\n      npm ci\n      npx tsc --noEmit\n"
        "      npx @azure/static-web-apps-cli deploy dist\n      npx @scope/tool@1.2.3 run\n"
        "      pip install --quiet ruff\n",
    )
    found = {
        f.locations[0].file: f
        for f in findings_for(tmp_path, "owasp", "OWASP-A08-UNPINNED-INSTALL")
    }
    assert [str(loc) for loc in found["api/startup.sh"].locations] == ["api/startup.sh:3"]
    assert "at start-up" in found["api/startup.sh"].detail
    assert [str(loc) for loc in found["azure-pipelines.yml"].locations] == [
        "azure-pipelines.yml:3",
        "azure-pipelines.yml:6",
        "azure-pipelines.yml:8",
    ]


def test_auth_failure_logging(tmp_path):
    write(
        tmp_path,
        "api/auth.py",
        "from fastapi import APIRouter\nrouter = APIRouter()\n"
        "@router.post('/login')\nasync def login(data):\n"
        "    if not ok:\n        raise HTTPException(status_code=401)\n"
        "@router.post('/signin')\nasync def signin(data):\n"
        "    if not ok:\n        logger.warning('failed sign-in')\n        raise HTTPException(status_code=401)\n",
    )
    assert locs(findings_for(tmp_path, "owasp", "OWASP-A09-NO-AUTH-FAIL-LOG")) == ["api/auth.py:4"]


def test_xml_parser_without_defusedxml(tmp_path):
    write(tmp_path, "requirements.txt", "openpyxl==3.1.2\n")
    write(
        tmp_path,
        "app/imports.py",
        "import openpyxl\nimport xml.etree.ElementTree as ET\n"
        "def read(data):\n    wb = openpyxl.load_workbook(data)\n    root = ET.fromstring(data)\n",
    )
    assert locs(findings_for(tmp_path, "owasp", "OWASP-A05-XML-PARSER")) == [
        "app/imports.py:4",
        "app/imports.py:5",
    ]
    write(tmp_path, "requirements.txt", "openpyxl==3.1.2\ndefusedxml==0.7.1\n")
    assert findings_for(tmp_path, "owasp", "OWASP-A05-XML-PARSER") == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/reviews/test_owasp_integrity.py -q`
Expected: FAIL (the rules are not registered, so every assertion compares an empty result with the expected findings)

- [ ] **Step 3: Write the rules and the rule text**

`src/dpr/reviews/owasp_integrity.py`:

```python
"""Review 5, OWASP A05, A08 and A09: supply chain, deserialisation, CI, XML and auth logging."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from pathlib import PurePosixPath

from dpr.model import Finding, Location, Tag
from dpr.parsing import jsts, pyast
from dpr.redact import snippet
from dpr.reviews.baseline_accounts import START_FILES
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule
from dpr.walk import line_of

SCRIPT_TAG = re.compile(r"<script\b[^>]*\bsrc\s*=\s*[\"']https?://[^>]*>", re.IGNORECASE)
MARKUP = (".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte", ".j2", ".jinja", ".jinja2")
PY_DESERIALISE = re.compile(
    r"(?:pickle|cPickle|dill|marshal)\.loads?|jsonpickle\.decode|yaml\.unsafe_load|yaml\.load"
)
SAFE_LOADER = re.compile(r"Safe|CSafe|BaseLoader")
HEAD_CHECKOUT = re.compile(
    r"github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref", re.IGNORECASE
)
CI_FILES = (
    "azure-pipelines.yml",
    ".gitlab-ci.yml",
    "bitbucket-pipelines.yml",
    "Jenkinsfile",
    "cloudbuild.yaml",
)
LOCK_FILES = {"requirements.lock", "poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock"}
JS_LOCKS = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lockb",
    "bun.lock",
    "npm-shrinkwrap.json",
}
PIP_INSTALL = re.compile(r"\bpip3?\s+install\s+(.*)$")
NPX_SCOPED = re.compile(r"\bnpx\s+(?:--?\w+\s+)*(@[\w.-]+/[\w.-]+)(?!@)(?=\s|$)")
NPM_INSTALL = re.compile(r"\bnpm\s+(?:install|i)\b(.*)$")
LOGIN_ROUTE = re.compile(r"(?i)log-?in|sign-?in|/token$")
FAIL_STATUS = re.compile(r"\b401\b|HTTP_401|UNAUTHORIZED|Unauthorized")
LOG_CALL = re.compile(
    r"\b(?:logger|logging|log|console)\.(?:warn|warning|error|info|log|exception)"
)
XML_CALLS = re.compile(
    r"(?:xml\.etree\.)?(?:ElementTree|ET|etree|cElementTree)\.(?:parse|fromstring|XML|iterparse)"
    r"|(?:xml\.dom\.)?minidom\.parse(?:String)?|xml\.sax\.parse(?:String)?|openpyxl\.load_workbook"
    r"|load_workbook"
)


@rule("OWASP-A08-NO-SRI", review="owasp", severity="low", exploitability="low", owasp="A08")
def no_sri(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.files:
        if not entry.rel.lower().endswith(MARKUP) or is_test(entry.rel):
            continue
        text = ctx.index.text(entry.rel)
        lines = [
            line_of(text, m.start())
            for m in SCRIPT_TAG.finditer(text)
            if "integrity" not in m.group(0).lower()
        ]
        if lines:
            yield make_finding(
                "OWASP-A08-NO-SRI",
                tag=Tag.CONFIRMED,
                locations=[Location(entry.rel, n) for n in lines[:5]],
                snippet=snippet(text, lines[0]),
                count=len(lines),
            )


@rule(
    "OWASP-A08-UNSAFE-DESERIALISE",
    review="owasp",
    severity="high",
    exploitability="medium",
    owasp="A08",
)
def unsafe_deserialise(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.py_files:
        if is_test(entry.rel):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for call in pyast.calls(tree, PY_DESERIALISE) if tree else []:
            name = pyast.dotted(call.func)
            loader = pyast.kwarg(call, "Loader")
            if name == "yaml.load" and (
                (loader is not None and SAFE_LOADER.search(ast.unparse(loader)))
                or (len(call.args) > 1 and SAFE_LOADER.search(ast.unparse(call.args[1])))
            ):
                continue
            yield make_finding(
                "OWASP-A08-UNSAFE-DESERIALISE",
                tag=Tag.INFERRED,
                locations=[Location(entry.rel, call.lineno)],
                snippet=snippet(ctx.index.text(entry.rel), call.lineno),
                call=name,
            )
    for entry in ctx.index.js_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel) or "node-serialize" not in text:
            continue
        for match in re.finditer(r"\bunserialize\s*\(", text):
            line = line_of(text, match.start())
            yield make_finding(
                "OWASP-A08-UNSAFE-DESERIALISE",
                tag=Tag.INFERRED,
                locations=[Location(entry.rel, line)],
                snippet=snippet(text, line),
                call="node-serialize unserialize",
            )


@rule(
    "OWASP-A08-CI-UNTRUSTED", review="owasp", severity="high", exploitability="medium", owasp="A08"
)
def ci_untrusted(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.glob(".github/workflows/*"):
        text = ctx.index.text(entry.rel)
        if "pull_request_target" not in text:
            continue
        for match in HEAD_CHECKOUT.finditer(text):
            line = line_of(text, match.start())
            yield make_finding(
                "OWASP-A08-CI-UNTRUSTED",
                tag=Tag.CONFIRMED,
                locations=[Location(entry.rel, line)],
                snippet=snippet(text, line),
            )


def _folder_files(ctx: Context) -> set[str]:
    return {f.rel for f in ctx.index.files}


@rule("OWASP-A08-UNPINNED-DEPS", review="owasp", severity="low", exploitability="low", owasp="A08")
def unpinned_deps(ctx: Context) -> Iterator[Finding]:
    names = _folder_files(ctx)
    for entry in ctx.index.named("requirements*.txt"):
        folder = PurePosixPath(entry.rel).parent
        prefix = "" if str(folder) == "." else f"{folder}/"
        text = ctx.index.text(entry.rel)
        if "--hash" in text or any(f"{prefix}{lock}" in names for lock in LOCK_FILES):
            continue
        specs = []
        for number, raw in enumerate(text.splitlines(), start=1):
            line = raw.split("#", 1)[0].strip()
            if line and not line.startswith("-"):
                specs.append((number, "==" in line))
        unpinned = [n for n, pinned in specs if not pinned]
        if specs and len(unpinned) * 2 >= len(specs):
            yield make_finding(
                "OWASP-A08-UNPINNED-DEPS",
                tag=Tag.CONFIRMED,
                locations=[Location(entry.rel, unpinned[0])],
                snippet=snippet(text, unpinned[0]),
                what=f"{len(unpinned)} of {len(specs)} requirements in {entry.name} have no exact "
                "version and no lock file or hashes sit next to it.",
            )
    for entry in ctx.index.named("package.json"):
        parts = PurePosixPath(entry.rel).parent.parts
        folders = ["/".join(parts[:i]) for i in range(len(parts), -1, -1)]
        locked = any(f"{f}/{lock}".lstrip("/") in names for f in folders for lock in JS_LOCKS)
        if not locked and '"dependencies"' in ctx.index.text(entry.rel):
            yield make_finding(
                "OWASP-A08-UNPINNED-DEPS",
                tag=Tag.CONFIRMED,
                locations=[Location(entry.rel, 1)],
                what="No npm, yarn, pnpm or bun lock file covers this package.json.",
            )


def _install_problems(line: str, runtime: bool) -> str | None:
    pip = PIP_INSTALL.search(line)
    if pip:
        args = [a for a in pip.group(1).split() if not a.startswith("-")]
        if "-r" in pip.group(1).split() or "-e" in pip.group(1).split():
            return None
        packages = [a for a in args if a not in (".", "pip") and "==" not in a]
        if packages:
            where = "at start-up" if runtime else "in CI"
            return f"pip installs {', '.join(packages[:3])} without a pinned version {where}."
    npx = NPX_SCOPED.search(line)
    if npx:
        return f"npx runs {npx.group(1)} without a pinned version."
    npm = NPM_INSTALL.search(line)
    if npm and not runtime:
        extra = [a for a in npm.group(1).split() if not a.startswith("-")]
        if not extra:
            return "npm install in CI can rewrite the lock file; npm ci installs what is locked."
        if "-g" in npm.group(1).split() and not any("@" in a[1:] for a in extra):
            return f"npm installs {extra[0]} globally without a pinned version."
    return None


@rule(
    "OWASP-A08-UNPINNED-INSTALL", review="owasp", severity="low", exploitability="low", owasp="A08"
)
def unpinned_install(ctx: Context) -> Iterator[Finding]:
    starts = [
        e for e in ctx.index.named(*START_FILES) if e.name.endswith(".sh") or e.name == "Procfile"
    ]
    ci = [*ctx.index.glob(".github/workflows/*"), *ctx.index.named(*CI_FILES)]
    for entries, runtime in ((starts, True), (ci, False)):
        for entry in entries:
            text = ctx.index.text(entry.rel)
            problems = []
            for number, raw in enumerate(text.splitlines(), start=1):
                if raw.strip().startswith(("#", "echo ")):
                    continue
                problem = _install_problems(raw, runtime)
                if problem:
                    problems.append((number, problem))
            if problems:
                yield make_finding(
                    "OWASP-A08-UNPINNED-INSTALL",
                    tag=Tag.CONFIRMED,
                    locations=[Location(entry.rel, n) for n, _ in problems[:10]],
                    snippet=snippet(text, problems[0][0]),
                    file=entry.rel,
                    what=" ".join(dict.fromkeys(p for _, p in problems[:3])),
                )


@rule(
    "OWASP-A09-NO-AUTH-FAIL-LOG", review="owasp", severity="low", exploitability="low", owasp="A09"
)
def no_auth_fail_log(ctx: Context) -> Iterator[Finding]:
    for route in ctx.detection.routes:
        handler = route.handler
        name = getattr(handler, "name", "")
        if not LOGIN_ROUTE.search(route.path) and not LOGIN_ROUTE.search(str(name)):
            continue
        if route.method not in ("POST", "ANY", "ACTION") or is_test(route.file):
            continue
        if isinstance(handler, ast.AST):
            text = ast.unparse(handler)
        elif handler is not None and hasattr(handler, "type"):
            text = jsts.node_text(handler)
        else:
            continue
        if FAIL_STATUS.search(text) and not LOG_CALL.search(text):
            yield make_finding(
                "OWASP-A09-NO-AUTH-FAIL-LOG",
                tag=Tag.INFERRED,
                locations=[Location(route.file, route.line)],
                snippet=snippet(ctx.index.text(route.file), route.line),
                path=route.path,
            )


@rule("OWASP-A05-XML-PARSER", review="owasp", severity="low", exploitability="low", owasp="A05")
def xml_parser(ctx: Context) -> Iterator[Finding]:
    if "defusedxml" in ctx.detection.packages:
        return
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel) or not re.search(r"xml|openpyxl|load_workbook", text):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        lines = [c.lineno for c in pyast.calls(tree, XML_CALLS)] if tree else []
        if lines:
            yield make_finding(
                "OWASP-A05-XML-PARSER",
                tag=Tag.INFERRED,
                locations=[Location(entry.rel, n) for n in lines[:5]],
                snippet=snippet(text, lines[0]),
            )
```

`src/dpr/data/rule_text/owasp_integrity.yaml`:

```yaml
OWASP-A08-NO-SRI:
  title: Third-party script loaded without integrity check
  effort_minutes: 10
  detail: ${count} script tag(s) load code from another origin without an integrity attribute, so a change on that server runs on this site.
  attack: Compromise or impersonate the script host and serve modified JavaScript to every visitor.
  blast: Everything the page can read or do for every visitor.
  fix: Pin the script version and add integrity="sha384-..." with crossorigin="anonymous", or self-host the file.
  verify: View the page source and confirm each external script tag has an integrity attribute.
OWASP-A08-UNSAFE-DESERIALISE:
  title: Unsafe deserialisation with ${call}
  effort_minutes: 20
  detail: ${call} can build arbitrary objects, and running it on untrusted bytes can execute code.
  proof_needed: Trace whether the input can come from a request, an upload, a cache or a queue an attacker can write to.
  attack: Send a crafted payload that constructs an object whose loading runs a command.
  blast: Code execution with the server process's rights.
  fix: Use JSON for untrusted data, yaml.safe_load for YAML, and never unpickle data that crossed a trust boundary.
  verify: Confirm the call now uses a safe loader or a data-only format.
OWASP-A08-CI-UNTRUSTED:
  title: CI runs pull request code with repository secrets
  effort_minutes: 15
  detail: A pull_request_target workflow checks out the pull request's head, so code from a fork runs with the base repository's secrets and write token.
  attack: Open a pull request from a fork that changes a build script to print or send the secrets.
  blast: Every secret and write permission available to the workflow.
  fix: Use the pull_request trigger for building fork code, or check out only the base ref in pull_request_target workflows and never run scripts from the pull request there.
  verify: Open a test pull request from a fork and confirm the job does not run its code with secrets.
OWASP-A08-UNPINNED-DEPS:
  title: Dependencies are not pinned
  effort_minutes: 30
  detail: ${what} Each build can install a different version, including a compromised release.
  fix: Generate a lock file (pip-compile with hashes, uv lock, poetry lock, npm install to create package-lock.json) and install from it in every build.
  verify: Build twice from a clean cache and confirm the installed versions match the lock file.
OWASP-A08-UNPINNED-INSTALL:
  title: Packages installed without pinned versions in ${file}
  effort_minutes: 15
  detail: ${what}
  attack: Publish or take over a package version that the unpinned install picks up on the next build or restart.
  blast: The build agent and its deployment credentials, or the running app when the install happens at start-up.
  fix: Pin tool versions (pip install tool==1.2.3, npx @scope/cli@1.2.3), install app packages from the lock file at build time, and use npm ci in CI.
  verify: Search the file for pip install, npm install and npx lines and confirm each one is pinned or uses the lock file.
OWASP-A09-NO-AUTH-FAIL-LOG:
  title: Failed sign-ins on ${path} are not logged
  effort_minutes: 10
  detail: The sign-in handler rejects bad credentials but writes nothing to the log, so password spraying and account takeover attempts leave no trace.
  proof_needed: Check whether a middleware, gateway or auth provider logs these failures instead.
  blast: The ability to tell, after an incident, which accounts were attacked and when.
  fix: Log each failure with a request id, the account identifier (or a hash of it) and the client address, without the password.
  verify: Sign in with a wrong password and confirm a log line appears.
OWASP-A05-XML-PARSER:
  title: XML parsed without defusedxml
  effort_minutes: 10
  detail: The code parses XML (or spreadsheets, which are zipped XML) and the project does not declare defusedxml, so entity expansion and external entity protections depend on library defaults.
  proof_needed: Check whether the parsed files can come from users and which parser versions run in production.
  attack: Upload a document with nested entity definitions that expands to gigabytes in memory.
  blast: Memory and CPU of the API worker, and possibly local file reads with older parsers.
  fix: Add defusedxml to the dependencies (openpyxl uses it automatically when installed) and use defusedxml parsers for direct XML parsing.
  verify: Confirm defusedxml is installed in the deployed environment and that a billion-laughs test file is rejected.
```

Modify `src/dpr/reviews/owasp.py`, replace:

```python
import dpr.reviews.owasp_inject  # noqa: F401  (registers rules)
```

with:

```python
import dpr.reviews.owasp_inject  # noqa: F401  (registers rules)
import dpr.reviews.owasp_integrity  # noqa: F401  (registers rules)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest -q`
Expected: PASS (all tests, including 6 new ones)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/reviews/owasp_integrity.py src/dpr/reviews/owasp.py src/dpr/data/rule_text/owasp_integrity.yaml tests/reviews/test_owasp_integrity.py
git commit -m "Add OWASP checks for unpinned supply chain, unsafe deserialisation, CI, XML parsing and failed sign-in logging"
```

---
### Task 43: OWASP section, route classification table and categories reviewed

Two parts of the OWASP section depend on the findings: the route table marks routes that have an unscoped lookup, and the category list counts findings per category. Review modules therefore get an optional `finish(ctx, section, findings)` hook, which the pipeline calls after the review's checks have run. `run()` keeps its Milestone 1 contract.

**Files:**
- Modify: `src/dpr/api.py` (call `finish` when a review module defines it), `src/dpr/reviews/owasp.py` (replace the whole file)
- Test: `tests/reviews/test_owasp_section.py`

**Interfaces:**
- Consumes: `access`, `ADMIN`, `PUBLIC` (Task 33); `PY_ORM`, `route_lookups` (Task 39); `unscoped` (Task 39); `review()` (Task 23); `render_markdown` (Task 24)
- Produces:
  - Pipeline: after `run_checks(slug, ctx)`, `module.finish(ctx, section, findings_of_that_review)` when the module defines `finish`
  - `dpr.reviews.owasp.CATEGORIES` (A01 to A10 titles); `classify(ctx, route) -> str`, one of `public`, `admin`, `authenticated, no ownership check found`, `authenticated and ownership-checked`, `authenticated`
  - OWASP section parts: text "How to read this section", findings "Findings", table "Route classification" (`Method | Path | Where | Access | Evidence`), text "Categories reviewed" (one line per category with a finding count or "no finding from this review's own rules", plus cross-references: A04 to review 7, A05 to `BASE-DEBUG-ON`, `BASE-HEADER-MISSING-*`, `ABUSE-ERROR-LEAK` and `ABUSE-CORS-*`, A06 not run, A07 to review 3)
  - With `with_audit`, `not_covered` gets `Dependency audit not run: the audit adapters arrive in a later version`

- [ ] **Step 1: Write the failing test**

`tests/reviews/test_owasp_section.py`:

```python
from dpr.api import review
from dpr.report.markdown import render_markdown
from tests.reviews.helpers import write


def app(root):
    write(
        root,
        "api/app/deps.py",
        "from typing import Annotated\nfrom fastapi import Depends\n"
        "CurrentUser = Annotated[dict, Depends(get_current_user)]\n"
        "AdminUser = Annotated[dict, Depends(get_admin_user)]\n",
    )
    write(
        root,
        "api/app/models.py",
        "class Doc(Base):\n    __tablename__ = 'docs'\n    id = Column(String, primary_key=True)\n"
        "    owner_id = Column(String)\n",
    )
    write(
        root,
        "api/app/routes.py",
        "from fastapi import APIRouter\nfrom app.deps import AdminUser, CurrentUser\n"
        "router = APIRouter(prefix='/docs')\n"
        "@router.get('/{doc_id}')\nasync def any_doc(doc_id: str, me: CurrentUser, db=None):\n"
        "    return await db.get(Doc, doc_id)\n"
        "@router.get('/{doc_id}/mine')\nasync def mine(doc_id: str, me: CurrentUser, db=None):\n"
        "    return await db.execute(select(Doc).where(Doc.id == doc_id, Doc.owner_id == me.id))\n"
        "@router.get('')\nasync def listing(me: CurrentUser):\n    return []\n"
        "@router.delete('/{doc_id}')\nasync def purge(doc_id: str, boss: AdminUser, db=None):\n"
        "    return await db.get(Doc, doc_id)\n"
        "@router.get('/health')\nasync def health():\n    return {}\n",
    )
    return root


def test_route_table_and_categories(tmp_path):
    report = review(app(tmp_path), reviews=["owasp"])
    parts = {p.title: p for p in report.sections["owasp"].parts}
    assert list(parts) == [
        "How to read this section",
        "Findings",
        "Route classification",
        "Categories reviewed",
    ]
    access = {(row[0], row[1]): row[3] for row in parts["Route classification"].rows}
    assert access == {
        ("GET", "/docs/{doc_id}"): "authenticated, no ownership check found",
        ("GET", "/docs/{doc_id}/mine"): "authenticated and ownership-checked",
        ("GET", "/docs"): "authenticated",
        ("DELETE", "/docs/{doc_id}"): "admin",
        ("GET", "/docs/health"): "public",
    }
    body = parts["Categories reviewed"].body
    assert "- A01 Broken access control: 1 finding(s) above." in body
    assert (
        "- A06 Vulnerable and outdated components: no finding from this review's own rules. Not run"
        in body
    )
    text = render_markdown(report)
    assert "## 5. OWASP sweep" in text and "#### FINDING 1:" in text


def test_audit_option_is_recorded(tmp_path):
    report = review(app(tmp_path), reviews=["owasp"], with_audit=True)
    assert (
        "Dependency audit not run: the audit adapters arrive in a later version"
        in report.not_covered
    )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/reviews/test_owasp_section.py -q`
Expected: FAIL in both tests: `AssertionError` on the part titles (the section only has "Findings") and on the missing audit note

- [ ] **Step 3: Add the hook and the section**

Modify `src/dpr/api.py`, replace:

```python
        sections[slug] = section
        findings.extend(run_checks(slug, ctx))
```

with:

```python
        sections[slug] = section
        found = run_checks(slug, ctx)
        findings.extend(found)
        finish = getattr(modules[slug], "finish", None)
        if finish is not None:
            finish(ctx, section, found)
```

Replace the whole of `src/dpr/reviews/owasp.py`:

`src/dpr/reviews/owasp.py`:

```python
"""Review 5, OWASP sweep: own rules weighted to broken access control."""

from __future__ import annotations

import ast
import re

import dpr.reviews.owasp_a01  # noqa: F401  (registers rules)
import dpr.reviews.owasp_assign  # noqa: F401  (registers rules)
import dpr.reviews.owasp_inject  # noqa: F401  (registers rules)
import dpr.reviews.owasp_integrity  # noqa: F401  (registers rules)
import dpr.reviews.owasp_misc  # noqa: F401  (registers rules)
import dpr.reviews.owasp_paths  # noqa: F401  (registers rules)
from dpr.model import Finding, Part, ReviewSection, Route
from dpr.parsing import jsts
from dpr.reviews.access import ADMIN, PUBLIC, access
from dpr.reviews.lookups import PY_ORM, route_lookups
from dpr.reviews.owasp_a01 import unscoped
from dpr.rules import Context

CATEGORIES = {
    "A01": "Broken access control",
    "A02": "Cryptographic failures",
    "A03": "Injection",
    "A04": "Insecure design",
    "A05": "Security misconfiguration",
    "A06": "Vulnerable and outdated components",
    "A07": "Identification and authentication failures",
    "A08": "Software and data integrity failures",
    "A09": "Security logging and monitoring failures",
    "A10": "Server-side request forgery",
}
NOTES = {
    "A04": "Missing rate limits and bot protection are reported in review 7.",
    "A05": "Debug mode and missing headers are reported in review 4 (BASE-DEBUG-ON, "
    "BASE-HEADER-MISSING-*); error text and CORS in review 7 (ABUSE-ERROR-LEAK, ABUSE-CORS-*).",
    "A06": "Not run: the dependency audit adapters arrive in a later version.",
    "A07": "Session and account failure paths belong to review 3, which arrives in a later "
    "version; committed passwords are reported in review 4.",
}
INTRO = (
    "Findings are ordered by exploitability and effort. Access control carries the most weight: "
    "the signature is a route that checks who you are but never whether the record is yours. "
    "The route table below shows how every detected route was classified."
)


def _ownership_checked(ctx: Context, route: Route) -> bool:
    level = access(ctx, route)
    if any(check == "owner" for _, check in route_lookups(ctx, route, level)):
        return True
    subjects = level.subjects
    if not subjects or route.handler is None:
        return False
    if isinstance(route.handler, ast.AST):
        statements = [ast.unparse(n) for n in ast.walk(route.handler) if isinstance(n, ast.Call)]
        orm = PY_ORM
    else:
        statements = [jsts.node_text(c) for c in jsts.walk(route.handler, {"call_expression"})]
        orm = re.compile(r"\.(?:findUnique|findFirst|findMany|update|delete|eq|where)\(")
    return any(orm.search(s) and any(subject in s for subject in subjects) for s in statements)


def classify(ctx: Context, route: Route) -> str:
    level = access(ctx, route).level
    if level in (PUBLIC, ADMIN):
        return level
    if any(r is route or r == route for r, _, _ in unscoped(ctx)):
        return "authenticated, no ownership check found"
    if _ownership_checked(ctx, route):
        return "authenticated and ownership-checked"
    return "authenticated"


def run(ctx: Context) -> ReviewSection:
    if ctx.options.with_audit:
        ctx.not_covered.append(
            "Dependency audit not run: the audit adapters arrive in a later version"
        )
    parts = [Part("text", "How to read this section", body=INTRO), Part("findings", "Findings")]
    return ReviewSection("owasp", parts)


def finish(ctx: Context, section: ReviewSection, findings: list[Finding]) -> None:
    rows = tuple(
        (r.method, r.path, f"{r.file}:{r.line}", classify(ctx, r), access(ctx, r).evidence)
        for r in ctx.detection.routes
    )
    columns = ("Method", "Path", "Where", "Access", "Evidence")
    section.parts.append(Part("table", "Route classification", columns, rows))
    counts = {key: sum(f.owasp == key for f in findings) for key in CATEGORIES}
    lines = []
    for key, title in CATEGORIES.items():
        if counts[key]:
            status = f"{counts[key]} finding(s) above"
        else:
            status = "no finding from this review's own rules"
        note = f" {NOTES[key]}" if key in NOTES else ""
        lines.append(f"- {key} {title}: {status}.{note}")
    section.parts.append(Part("text", "Categories reviewed", body="\n".join(lines)))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest -q`
Expected: PASS (all tests, including 2 new ones)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/api.py src/dpr/reviews/owasp.py tests/reviews/test_owasp_section.py
git commit -m "Add the OWASP section with route classification and category coverage"
```

---
### Task 44: Paid routes, missing limits, kill switches and public forms

A paid route is a route handler that reaches a paid SDK from `sdks.yaml`. The SDK's import lines (from detection) give the imported names, for example `OpenAI`, `anthropic` or `Resend`. Module-level clients built from them (`const client = new OpenAI()`, `client = anthropic.Anthropic()`) are added per file. A handler is paid when it calls one of those names, or when a function it calls does, up to two levels deep: Python functions through the helper index, and exported JavaScript functions by name.

**Files:**
- Create: `src/dpr/data/costs.yaml`, `src/dpr/reviews/paid.py`, `src/dpr/reviews/abuse_paid.py`, `src/dpr/data/rule_text/abuse_paid.yaml`
- Modify: `src/dpr/reviews/abuse.py` (import the rule module)
- Test: `tests/reviews/test_abuse_paid.py`

**Interfaces:**
- Consumes: `SdkUse`, `Route` (Task 2); `dpr.data.load` (Task 3); `access`, `PUBLIC` (Task 33); `helper_index` (Task 39); `is_test` (Task 37); plus the Milestone 1 helpers used by every rule module
- Produces:
  - `dpr/data/costs.yaml`: per SDK category (`llm`, `email`, `sms`, `storage`, `image`, `browser`, `maps`, `payments`, `ml`, `search`) a cost note and starting `per_user`, `per_ip` and `window`, plus `login` and `form` rows for public forms (used by the section in Task 47)
  - `dpr.reviews.paid`: `PaidRoute(route, sdk, via)`; `sdk_names(ctx) -> dict[str, SdkUse]` (cached in `ctx.facts["paid_sdk_names"]`); `paid_routes(ctx) -> list[PaidRoute]` (cached in `ctx.facts["paid_routes"]`); `costs() -> dict`
  - `dpr.reviews.abuse_paid`: `slowapi_wired(ctx) -> bool`; `is_limited(ctx, route) -> bool` (a limiter word or `.limit(` in the handler or its decorators, slowapi middleware added anywhere for FastAPI and Flask, an earlier limiter `use()` for Express, a limiter in `middleware.ts` for Next.js)
  - Registered rules (review `abuse`, owasp A04): `ABUSE-PAID-UNAUTH` (critical, CONFIRMED; a paid route classified public), `ABUSE-PAID-UNLIMITED` (high, INFERRED; the fix quotes the starting numbers from `costs.yaml`), `ABUSE-NO-KILL-SWITCH` (low, INFERRED; no `*_ENABLED`, `DISABLE_*`, kill switch or feature flag check in the handler; the fix names a flag built from the path), `ABUSE-FORM-NO-CHALLENGE` (medium, INFERRED; public non-GET routes flagged `is_public_form`, with no Turnstile, hCaptcha, reCAPTCHA, captcha or honeypot in the handler or its file; one finding per file listing every route)

- [ ] **Step 1: Write the failing tests**

`tests/reviews/test_abuse_paid.py`:

```python
from tests.reviews.helpers import findings_for, write


def next_app(root):
    write(root, "package.json", '{"dependencies": {"next": "14", "openai": "4"}}')
    write(
        root,
        "lib/ai.ts",
        "import OpenAI from 'openai'\nconst client = new OpenAI()\n"
        "export async function generate(prompt: string) {\n  return client.chat.completions.create({ messages: [] })\n}\n",
    )
    write(
        root,
        "app/api/generate/route.ts",
        "import { generate } from '@/lib/ai'\n"
        "export async function POST(req: Request) {\n  return Response.json(await generate('x'))\n}\n",
    )
    write(
        root,
        "app/api/chat/route.ts",
        "import OpenAI from 'openai'\nconst openai = new OpenAI()\n"
        "export async function POST(req: Request) {\n  const session = await auth()\n"
        "  if (process.env.CHAT_ENABLED !== 'true') return new Response(null, { status: 503 })\n"
        "  const { success } = await ratelimit.limit(session.user.id)\n"
        "  return Response.json(await openai.chat.completions.create({ messages: [] }))\n}\n",
    )
    write(
        root,
        "app/api/signup/route.ts",
        "export async function POST(req: Request) {\n  return Response.json({})\n}\n",
    )
    write(
        root,
        "app/api/contact/route.ts",
        "export async function POST(req: Request) {\n  await verifyTurnstile(req)\n  return Response.json({})\n}\n",
    )
    return root


def locs(found):
    return sorted(str(f.locations[0]) for f in found)


def test_paid_routes_auth_limits_and_kill_switch(tmp_path):
    root = next_app(tmp_path)
    [unauth] = findings_for(root, "abuse", "ABUSE-PAID-UNAUTH")
    assert str(unauth.locations[0]) == "app/api/generate/route.ts:2"
    assert unauth.title == "POST /api/generate calls openai with no sign-in"
    assert "through generate()" in unauth.detail and "tokens per call" in unauth.detail
    [unlimited] = findings_for(root, "abuse", "ABUSE-PAID-UNLIMITED")
    assert str(unlimited.locations[0]) == "app/api/generate/route.ts:2"
    assert "20 per user and 40 per IP per 1 h" in unlimited.fix
    [switch] = findings_for(root, "abuse", "ABUSE-NO-KILL-SWITCH")
    assert "API_GENERATE_ENABLED" in switch.fix


def test_python_paid_route_through_helper(tmp_path):
    write(tmp_path, "requirements.txt", "fastapi\nanthropic\nslowapi\n")
    write(
        tmp_path,
        "app/chat.py",
        "async def stream_chat(messages):\n    import anthropic\n"
        "    client = anthropic.Anthropic()\n    return client.messages.create(messages=messages)\n",
    )
    write(
        tmp_path,
        "app/routes.py",
        "from fastapi import APIRouter, Depends\nrouter = APIRouter()\n"
        "@router.post('/chat')\nasync def chat(user=Depends(get_current_user)):\n"
        "    from app.chat import stream_chat\n    return await stream_chat([])\n"
        "@router.post('/limited')\n@limiter.limit('5/minute')\nasync def limited(user=Depends(get_current_user)):\n"
        "    return await stream_chat([])\n",
    )
    assert findings_for(tmp_path, "abuse", "ABUSE-PAID-UNAUTH") == []
    assert locs(findings_for(tmp_path, "abuse", "ABUSE-PAID-UNLIMITED")) == ["app/routes.py:4"]
    write(
        tmp_path,
        "app/main.py",
        "from slowapi.middleware import SlowAPIMiddleware\napp.add_middleware(SlowAPIMiddleware)\n",
    )
    assert findings_for(tmp_path, "abuse", "ABUSE-PAID-UNLIMITED") == []


def test_public_forms_without_challenge(tmp_path):
    root = next_app(tmp_path)
    write(
        root,
        "api/auth.py",
        "from fastapi import APIRouter, Depends\nrouter = APIRouter(prefix='/auth')\n"
        "@router.post('/register')\nasync def register(data): ...\n"
        "@router.post('/forgot-password')\nasync def forgot(data): ...\n"
        "@router.post('/logout')\nasync def logout(): ...\n"
        "@router.post('/register/admin')\nasync def admin_register(boss=Depends(get_admin_user)): ...\n",
    )
    found = {f.locations[0].file: f for f in findings_for(root, "abuse", "ABUSE-FORM-NO-CHALLENGE")}
    assert set(found) == {"api/auth.py", "app/api/signup/route.ts"}
    assert [str(loc) for loc in found["api/auth.py"].locations] == [
        "api/auth.py:4",
        "api/auth.py:6",
    ]
    assert "POST /auth/register, POST /auth/forgot-password" in found["api/auth.py"].detail
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/reviews/test_abuse_paid.py -q`
Expected: FAIL (the rules are not registered, so the unpacking and comparisons meet empty results)

- [ ] **Step 3: Write the cost table, the paid route detection, the rules and the rule text**

`src/dpr/data/costs.yaml`:

```yaml
# Starting limits per paid category, taken from the skill's example table. Not measured traffic.
llm: {note: "tokens per call, priced per model", per_user: 20, per_ip: 40, window: "1 h"}
email: {note: "email quota and sender reputation", per_user: 3, per_ip: 10, window: "1 h"}
sms: {note: "per message, varies by country", per_user: 3, per_ip: 5, window: "1 h"}
storage: {note: "storage and egress", per_user: 10, per_ip: 20, window: "1 h"}
image: {note: "per transform or render", per_user: 30, per_ip: 60, window: "1 h"}
browser: {note: "headless browser minutes", per_user: 10, per_ip: 20, window: "1 h"}
maps: {note: "per request to the maps API", per_user: 60, per_ip: 120, window: "1 h"}
payments: {note: "provider fees and card testing", per_user: 10, per_ip: 20, window: "1 h"}
ml: {note: "per document or media minute", per_user: 10, per_ip: 20, window: "1 h"}
search: {note: "per search operation", per_user: 120, per_ip: 240, window: "1 h"}
login: {note: "password hashing CPU and credential stuffing", per_user: 10, per_ip: 20, window: "15 min"}
form: {note: "a stored row and often an email per submission", per_user: 5, per_ip: 10, window: "1 h"}
```

`src/dpr/reviews/paid.py`:

```python
"""Routes that spend money when they run: paid SDK calls reached from a route handler."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from dpr.data import load
from dpr.model import Route, SdkUse
from dpr.parsing import jsts, pyast
from dpr.reviews.lookups import helper_index
from dpr.rules import Context

PY_IMPORT_NAMES = re.compile(r"^\s*(?:from\s+[\w.]+\s+import\s+(.+)|import\s+([\w., ]+))")
JS_IMPORT_NAMES = re.compile(
    r"import\s+(?:(\w+)|\*\s+as\s+(\w+)|\{([^}]*)\})|(?:const|let|var)\s+(?:(\w+)|\{([^}]*)\})\s*="
    r"\s*require\("
)


@dataclass(frozen=True)
class PaidRoute:
    route: Route
    sdk: SdkUse
    via: str


def _names_from_import(text: str, python: bool) -> set[str]:
    names: set[str] = set()
    match = PY_IMPORT_NAMES.match(text) if python else JS_IMPORT_NAMES.search(text)
    groups = match.groups() if match else ()
    for group in groups:
        for part in (group or "").replace("(", " ").replace(")", " ").split(","):
            token = part.strip().split(" as ")[-1].split(":")[-1].strip().split(".")[0]
            if re.fullmatch(r"[A-Za-z_]\w*", token):
                names.add(token)
    return names


def sdk_names(ctx: Context) -> dict[str, SdkUse]:
    """Imported identifier to the paid SDK it comes from, from the import sites."""
    if "paid_sdk_names" not in ctx.facts:
        found: dict[str, SdkUse] = {}
        for sdk in ctx.detection.sdks:
            if not sdk.paid:
                continue
            for loc in sdk.locations:
                line = ctx.index.text(loc.file).splitlines()[loc.line - 1]
                for name in _names_from_import(line, loc.file.endswith(".py")):
                    found[name] = sdk
        ctx.facts["paid_sdk_names"] = found
    return ctx.facts["paid_sdk_names"]


def _uses(text: str, names: dict[str, SdkUse]) -> SdkUse | None:
    for name, sdk in names.items():
        if re.search(rf"\b{re.escape(name)}\b\s*[.(]", text):
            return sdk
    return None


def _tree_names(tree, names: dict[str, SdkUse]) -> dict[str, SdkUse]:
    """Add module-level clients built from an SDK, such as `const ai = new OpenAI()`."""
    local = dict(names)
    if isinstance(tree, ast.Module):
        for name, value in pyast.assignments(tree.body).items():
            sdk = _uses(ast.unparse(value), names)
            if sdk:
                local[name] = sdk
    elif tree is not None and hasattr(tree, "root"):
        for decl in jsts.walk(tree.root, {"variable_declarator"}):
            if jsts.enclosing_function(decl) is not None:
                continue
            sdk = _uses(jsts.node_text(decl.child_by_field_name("value")), names)
            target = decl.child_by_field_name("name")
            if sdk and target is not None and target.type == "identifier":
                local[jsts.node_text(target)] = sdk
    return local


def _js_function_index(ctx: Context) -> dict[str, list]:
    key = ("js-function-index", "")
    if key not in ctx.index.cache:
        found: dict[str, list] = {}
        for entry in ctx.index.js_files:
            for tree in jsts.parse_file(ctx.index, entry.rel):
                for name, fn in jsts.exported_functions(tree).items():
                    found.setdefault(name, []).append((tree, fn))
        ctx.index.cache[key] = found
    return ctx.index.cache[key]


def _py_paid(
    ctx: Context, fn: ast.AST, names: dict[str, SdkUse], depth: int
) -> tuple[SdkUse, str] | None:
    sdk = _uses(ast.unparse(fn), names)
    if sdk:
        return sdk, getattr(fn, "name", "")
    if depth >= 2:
        return None
    base = sdk_names(ctx)
    for call in [n for n in ast.walk(fn) if isinstance(n, ast.Call)]:
        name = (pyast.dotted(call.func) or "").split(".")[-1]
        for rel, helper in helper_index(ctx).get(name, [])[:3]:
            if helper is fn:
                continue
            local = _tree_names(pyast.parse_file(ctx.index, rel), base)
            found = _py_paid(ctx, helper, local, depth + 1)
            if found:
                return found[0], name
    return None


def _js_paid(ctx: Context, fn, names: dict[str, SdkUse], depth: int) -> tuple[SdkUse, str] | None:
    sdk = _uses(jsts.node_text(fn), names)
    if sdk:
        return sdk, ""
    if depth >= 2:
        return None
    base = sdk_names(ctx)
    for call in jsts.walk(fn, {"call_expression"}):
        name = jsts.callee(call).split(".")[-1]
        for tree, helper in _js_function_index(ctx).get(name, [])[:3]:
            if helper is fn:
                continue
            found = _js_paid(ctx, helper, _tree_names(tree, base), depth + 1)
            if found:
                return found[0], name
    return None


def paid_routes(ctx: Context) -> list[PaidRoute]:
    if "paid_routes" not in ctx.facts:
        names = sdk_names(ctx)
        found = []
        for route in ctx.detection.routes if names else []:
            handler = route.handler
            local = _tree_names(route.tree, names)
            if isinstance(handler, ast.FunctionDef | ast.AsyncFunctionDef):
                hit = _py_paid(ctx, handler, local, 0)
            elif handler is not None and getattr(handler, "type", "") in jsts.FUNCTION_TYPES:
                hit = _js_paid(ctx, handler, local, 0)
            else:
                hit = None
            if hit:
                found.append(PaidRoute(route, hit[0], hit[1]))
        ctx.facts["paid_routes"] = found
    return ctx.facts["paid_routes"]


def costs() -> dict:
    return load("costs.yaml")
```

`src/dpr/reviews/abuse_paid.py`:

```python
"""Review 7, abuse: paid routes without auth, limits or a kill switch; public forms."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Route, Tag
from dpr.parsing import jsts
from dpr.redact import snippet
from dpr.reviews.access import PUBLIC, access
from dpr.reviews.paid import PaidRoute, costs, paid_routes
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule

LIMITER_WORD = re.compile(r"(?i)rate_?limit|limiter|\.limit\(|throttle|slowdown")
KILL_SWITCH = re.compile(
    r"(?i)\w*_enabled\b|\benabled\b|\bdisable_?\w*|kill_?switch|feature_?flag|is_?feature_?enabled"
    r"|isEnabled\(|unleash|launchdarkly|growthbook|flagsmith"
)
CHALLENGE = re.compile(r"(?i)turnstile|hcaptcha|recaptcha|captcha|honeypot")


def _handler_text(route: Route) -> str:
    handler = route.handler
    if isinstance(handler, ast.AST):
        return "\n".join(ast.unparse(d) for d in getattr(handler, "decorator_list", [])) + (
            "\n" + ast.unparse(handler)
        )
    if handler is not None and hasattr(handler, "type"):
        return jsts.node_text(handler)
    return ""


def slowapi_wired(ctx: Context) -> bool:
    return any(
        "SlowAPIMiddleware" in ctx.index.text(f.rel) and "add_middleware" in ctx.index.text(f.rel)
        for f in ctx.index.py_files
    )


def is_limited(ctx: Context, route: Route) -> bool:
    text = _handler_text(route)
    if LIMITER_WORD.search(text):
        return True
    if route.framework in ("fastapi", "flask") and slowapi_wired(ctx):
        return True
    if route.framework == "express" and route.tree is not None:
        for call in jsts.calls(route.tree, r"(?:\w+\.)*use"):
            if (
                LIMITER_WORD.search(jsts.node_text(call))
                and jsts.line(route.tree, call) < route.line
            ):
                return True
    if route.framework.startswith("next"):
        for entry in ctx.index.named("middleware.ts", "middleware.js"):
            if LIMITER_WORD.search(ctx.index.text(entry.rel)):
                return True
    return False


def _paid_detail(paid: PaidRoute) -> dict[str, object]:
    cost = costs().get(paid.sdk.category, {"note": "provider pricing"})
    via = f" through {paid.via}()" if paid.via else ""
    return {
        "method": paid.route.method,
        "path": paid.route.path,
        "sdk": paid.sdk.name,
        "via": via,
        "cost": cost["note"],
    }


@rule("ABUSE-PAID-UNAUTH", review="abuse", severity="critical", exploitability="high", owasp="A04")
def paid_unauth(ctx: Context) -> Iterator[Finding]:
    for paid in paid_routes(ctx):
        route = paid.route
        if access(ctx, route).level == PUBLIC and not is_test(route.file):
            yield make_finding(
                "ABUSE-PAID-UNAUTH",
                tag=Tag.CONFIRMED,
                locations=[Location(route.file, route.line)],
                snippet=snippet(ctx.index.text(route.file), route.line),
                **_paid_detail(paid),
            )


@rule("ABUSE-PAID-UNLIMITED", review="abuse", severity="high", exploitability="high", owasp="A04")
def paid_unlimited(ctx: Context) -> Iterator[Finding]:
    for paid in paid_routes(ctx):
        route = paid.route
        if not is_limited(ctx, route) and not is_test(route.file):
            cost = costs().get(paid.sdk.category, {})
            yield make_finding(
                "ABUSE-PAID-UNLIMITED",
                tag=Tag.INFERRED,
                locations=[Location(route.file, route.line)],
                snippet=snippet(ctx.index.text(route.file), route.line),
                per_user=cost.get("per_user", 20),
                per_ip=cost.get("per_ip", 40),
                window=cost.get("window", "1 h"),
                **_paid_detail(paid),
            )


@rule("ABUSE-NO-KILL-SWITCH", review="abuse", severity="low", exploitability="low", owasp="A04")
def no_kill_switch(ctx: Context) -> Iterator[Finding]:
    for paid in paid_routes(ctx):
        route = paid.route
        if KILL_SWITCH.search(_handler_text(route)) or is_test(route.file):
            continue
        flag = re.sub(r"[^A-Z0-9]+", "_", route.path.upper()).strip("_") or "PAID_ROUTE"
        yield make_finding(
            "ABUSE-NO-KILL-SWITCH",
            tag=Tag.INFERRED,
            locations=[Location(route.file, route.line)],
            flag=f"{flag}_ENABLED",
            **_paid_detail(paid),
        )


@rule(
    "ABUSE-FORM-NO-CHALLENGE",
    review="abuse",
    severity="medium",
    exploitability="medium",
    owasp="A04",
)
def form_no_challenge(ctx: Context) -> Iterator[Finding]:
    by_file: dict[str, list[Route]] = {}
    for route in ctx.detection.routes:
        if not route.is_public_form or is_test(route.file):
            continue
        if access(ctx, route).level != PUBLIC or route.method in ("GET", "HEAD", "OPTIONS"):
            continue
        if CHALLENGE.search(_handler_text(route)):
            continue
        by_file.setdefault(route.file, []).append(route)
    for rel, routes in sorted(by_file.items()):
        if CHALLENGE.search(ctx.index.text(rel)):
            continue
        yield make_finding(
            "ABUSE-FORM-NO-CHALLENGE",
            tag=Tag.INFERRED,
            locations=[Location(r.file, r.line) for r in routes],
            snippet=snippet(ctx.index.text(rel), routes[0].line),
            routes=", ".join(f"{r.method} {r.path}" for r in routes),
        )
```

`src/dpr/data/rule_text/abuse_paid.yaml`:

```yaml
ABUSE-PAID-UNAUTH:
  title: ${method} ${path} calls ${sdk} with no sign-in
  effort_minutes: 10
  detail: ${method} ${path} reaches the ${sdk} SDK${via} and no authentication check or middleware covers the route. Cost per call is ${cost}.
  attack: Script the route in a loop from one machine; every call is billed to your ${sdk} account.
  blast: Unbounded spend on ${sdk} until a provider cap or the card limit stops it, plus whatever data the call sends out.
  fix: Require a signed-in caller before the paid call, add per-user and per-IP limits, and set a hard monthly cap in the provider dashboard.
  verify: Call ${method} ${path} without a session and expect 401 before any provider request is made.
ABUSE-PAID-UNLIMITED:
  title: ${method} ${path} calls ${sdk} with no rate limit
  effort_minutes: 30
  detail: ${method} ${path} reaches the ${sdk} SDK${via} and no limiter covers the route. Cost per call is ${cost}.
  proof_needed: Check whether a gateway, WAF or provider-side quota limits this route outside the code.
  attack: Any account that can reach the route calls it in a loop; spend grows with every request.
  blast: Provider spend for the whole account, and degraded service for everyone once the quota is gone.
  fix: 'Limit per signed-in user first and per IP second. Starting numbers, not measured traffic: ${per_user} per user and ${per_ip} per IP per ${window}, plus a global daily ceiling and a provider hard cap. If the limiter store is unreachable, reject the call rather than pass it through.'
  verify: Send ${per_user} plus one requests within ${window} as one user and expect 429 on the last one.
ABUSE-NO-KILL-SWITCH:
  title: No kill switch for the paid route ${method} ${path}
  effort_minutes: 15
  detail: ${method} ${path} reaches ${sdk}${via} and nothing in the handler checks an enable flag, so stopping the spend needs a deploy or a key rotation.
  proof_needed: Check whether a feature flag service or gateway rule can switch this route off without a deploy.
  blast: Spend keeps running while a fix is written, reviewed and deployed.
  fix: Read an environment or feature flag such as ${flag} on every request and return 503 when it is off.
  verify: Set ${flag}=false in a test environment and confirm the route returns 503 without calling ${sdk}.
ABUSE-FORM-NO-CHALLENGE:
  title: Public forms accept unlimited automated submissions
  effort_minutes: 30
  detail: 'These unauthenticated form routes have no bot challenge or honeypot: ${routes}. Each is a free write into the system and, when it sends email, a free send from your quota.'
  proof_needed: Check whether a WAF, edge rule or provider-side challenge protects these routes.
  attack: Script sign-ups, resets or messages in bulk, or use them to test stolen credentials.
  blast: Fake accounts and rows, email quota and sender reputation, and credential stuffing against sign-in.
  fix: Add an invisible challenge (Cloudflare Turnstile or hCaptcha) verified on the server, a honeypot field as the free first line, and per-IP limits on every route listed.
  verify: Submit one of these forms from a script without a challenge token and expect a rejection.
```

Modify `src/dpr/reviews/abuse.py`, replace:

```python
from dpr.model import Part, ReviewSection
```

with:

```python
import dpr.reviews.abuse_paid  # noqa: F401  (registers rules)
from dpr.model import Part, ReviewSection
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest -q`
Expected: PASS (all tests, including 3 new ones)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/data/costs.yaml src/dpr/reviews/paid.py src/dpr/reviews/abuse_paid.py src/dpr/reviews/abuse.py src/dpr/data/rule_text/abuse_paid.yaml tests/reviews/test_abuse_paid.py
git commit -m "Add abuse checks for paid routes without auth, limits or kill switch, and unchallenged public forms"
```

---
### Task 45: Limiters that do not hold, and uploads read without a limit

A limiter that counts in process memory only works when one process serves every request. "More than one process" is proven by serverless hosting, or by a start file, `gunicorn.conf.py`, YAML file or PM2 config that asks for more than one worker, replica or instance (`--workers 2`, `-w 4`, `WEB_CONCURRENCY=3`, `replicas: 2`, `-i max`). The evidence closest to the limiter's file is cited as the second location.

**Files:**
- Create: `src/dpr/reviews/abuse_limits.py`, `src/dpr/data/rule_text/abuse_limits.yaml`
- Modify: `src/dpr/reviews/abuse.py` (import the rule module)
- Test: `tests/reviews/test_abuse_limits.py`

**Interfaces:**
- Consumes: `START_FILES`, `is_test` (Task 37), plus the Milestone 1 helpers used by every rule module
- Produces:
  - `dpr.reviews.abuse_limits.multi_process(ctx, near: str = "") -> Location | None`
  - Registered rules (review `abuse`, owasp A04):
    - `ABUSE-INMEMORY-LIMITER` (medium; only on a multi-process deploy): slowapi or Flask-Limiter `Limiter(...)` with no `storage_uri` or a `memory://` literal (CONFIRMED), or a `storage_uri` variable that one branch sets to `memory://` (INFERRED); `rateLimit(...)` or `slowDown(...)` without `store` (CONFIRMED); a module-level `new Map()` named like a counter (INFERRED)
    - `ABUSE-LIMITER-NOT-APPLIED` (medium, CONFIRMED): a slowapi `Limiter` with `default_limits` while no file adds `SlowAPIMiddleware`
    - `ABUSE-LIMITER-PROXY-IP` (medium, INFERRED): hosting config present, no forwarded-address trust anywhere (`--forwarded-allow-ips`, `FORWARDED_ALLOW_IPS`, `ProxyHeadersMiddleware`, `ProxyFix`, `trust proxy`, `get_ipaddr`, `X-Forwarded-For`), and a limiter keyed on `get_remote_address` or an express-rate-limit without `keyGenerator`
    - `ABUSE-UPLOAD-UNBOUNDED` (low, CONFIRMED): a route handler calls `.read()` with no size on an `UploadFile` parameter or a Flask `request.files` entry; the detail says whether a `len(...) >` check follows

- [ ] **Step 1: Write the failing tests**

`tests/reviews/test_abuse_limits.py`:

```python
from tests.reviews.helpers import findings_for, write

LIMITER = (
    "from slowapi import Limiter\nfrom slowapi.util import get_remote_address\n"
    "def get_limiter():\n"
    "    if settings.redis_url:\n        storage_uri = settings.redis_url\n"
    "    else:\n        storage_uri = 'memory://'\n"
    "    return Limiter(\n        key_func=get_remote_address,\n        storage_uri=storage_uri,\n"
    "        default_limits=['100/minute'],\n    )\n"
    "plain = Limiter(key_func=get_remote_address)\n"
)


def api(root):
    write(root, "api/requirements.txt", "fastapi\nslowapi\n")
    write(root, "api/app/rate_limit.py", LIMITER)
    write(root, "api/startup.sh", "gunicorn app.main:app --workers 2\n")
    write(root, "render.yaml", "services: []\n")
    return root


def test_inmemory_limiter_needs_multiple_processes(tmp_path):
    root = api(tmp_path)
    found = findings_for(root, "abuse", "ABUSE-INMEMORY-LIMITER")
    assert sorted((str(f.locations[0]), f.tag.value) for f in found) == [
        ("api/app/rate_limit.py:13", "CONFIRMED"),
        ("api/app/rate_limit.py:8", "INFERRED"),
    ]
    assert str(found[0].locations[1]) == "api/startup.sh:1"
    write(root, "api/startup.sh", "gunicorn app.main:app --workers 1\n")
    assert findings_for(root, "abuse", "ABUSE-INMEMORY-LIMITER") == []


def test_express_limiter_without_store(tmp_path):
    write(tmp_path, "vercel.json", "{}")
    write(
        tmp_path,
        "server/app.js",
        "const limiter = rateLimit({ windowMs: 60000, max: 5 })\n"
        "const shared = rateLimit({ windowMs: 60000, max: 5, store: new RedisStore(), keyGenerator: (r) => r.user.id })\n"
        "const attempts = new Map()\n",
    )
    found = findings_for(tmp_path, "abuse", "ABUSE-INMEMORY-LIMITER")
    assert sorted((str(f.locations[0]), f.tag.value) for f in found) == [
        ("server/app.js:1", "CONFIRMED"),
        ("server/app.js:3", "INFERRED"),
    ]
    assert [
        str(f.locations[0]) for f in findings_for(tmp_path, "abuse", "ABUSE-LIMITER-PROXY-IP")
    ] == ["server/app.js:1"]


def test_default_limits_not_applied_and_proxy_key(tmp_path):
    root = api(tmp_path)
    [unwired] = findings_for(root, "abuse", "ABUSE-LIMITER-NOT-APPLIED")
    assert str(unwired.locations[0]) == "api/app/rate_limit.py:11"
    proxy = findings_for(root, "abuse", "ABUSE-LIMITER-PROXY-IP")
    assert sorted(str(f.locations[0]) for f in proxy) == [
        "api/app/rate_limit.py:13",
        "api/app/rate_limit.py:9",
    ]
    write(root, "api/app/main.py", "app.add_middleware(SlowAPIMiddleware)\n")
    write(root, "api/startup.sh", "gunicorn app.main:app --workers 2 --forwarded-allow-ips='*'\n")
    assert findings_for(root, "abuse", "ABUSE-LIMITER-NOT-APPLIED") == []
    assert findings_for(root, "abuse", "ABUSE-LIMITER-PROXY-IP") == []


def test_upload_read_without_limit(tmp_path):
    write(
        tmp_path,
        "api/files.py",
        "from fastapi import APIRouter, File, UploadFile\nrouter = APIRouter()\n"
        "@router.post('/a')\nasync def a(file: UploadFile = File(...)):\n"
        "    content = await file.read()\n    if len(content) > MAX:\n        raise ValueError()\n"
        "@router.post('/b')\nasync def b(file: UploadFile = File(...)):\n    data = await file.read()\n"
        "@router.post('/c')\nasync def c(file: UploadFile = File(...)):\n    chunk = await file.read(1024)\n",
    )
    found = sorted(
        findings_for(tmp_path, "abuse", "ABUSE-UPLOAD-UNBOUNDED"), key=lambda f: f.locations[0].line
    )
    assert [(str(f.locations[0]), f.detail) for f in found] == [
        (
            "api/files.py:5",
            "The handler reads the whole upload into memory and only then checks its size.",
        ),
        ("api/files.py:10", "The handler reads the whole upload into memory with no size limit."),
    ]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/reviews/test_abuse_limits.py -q`
Expected: FAIL (the rules are not registered, so the comparisons and unpacking meet empty results)

- [ ] **Step 3: Write the rules and the rule text**

`src/dpr/reviews/abuse_limits.py`:

```python
"""Review 7, abuse: limiters that do not hold across workers or proxies, and unbounded uploads."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Tag
from dpr.parsing import jsts, pyast
from dpr.redact import snippet
from dpr.reviews.baseline_accounts import START_FILES
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule
from dpr.walk import line_of

WORKERS = re.compile(
    r"(?:--workers|-w)[ =](\d+)|WEB_CONCURRENCY=(\d+)|^\s*workers\s*=\s*(\d+)"
    r"|replicas:\s*(\d+)|-i\s+(max|\d+)|instances:\s*(max|\d+)",
    re.MULTILINE,
)
PROXY_TRUST = re.compile(
    r"forwarded-allow-ips|FORWARDED_ALLOW_IPS|ProxyHeadersMiddleware|ProxyFix|trust proxy"
    r"|trustProxy|get_ipaddr|x-forwarded-for",
    re.IGNORECASE,
)
PY_LIMITER = re.compile(r"(?:\w+\.)*Limiter")
COUNTER_NAME = re.compile(r"(?i)rate|limit|attempt|hits|count|bucket")
UPLOAD_READ = re.compile(r"(?:\w+)\.read")


def multi_process(ctx: Context, near: str = "") -> Location | None:
    """Evidence that more than one process or instance serves requests, closest to `near`."""
    if ctx.detection.serverless:
        return Location(ctx.detection.hosting[0] if ctx.detection.hosting else ".", 1)
    names = (*START_FILES, "gunicorn.conf.py", "*.yaml", "*.yml", "ecosystem.config.js")
    found = []
    for entry in ctx.index.named(*names):
        text = ctx.index.text(entry.rel)
        for match in WORKERS.finditer(text):
            value = next(g for g in match.groups() if g)
            if value == "max" or int(value) > 1:
                found.append(Location(entry.rel, line_of(text, match.start())))
                break
    if not found:
        return None
    return max(found, key=lambda loc: len(_common(loc.file, near)))


def _common(a: str, b: str) -> list[str]:
    shared = []
    for left, right in zip(a.split("/"), b.split("/"), strict=False):
        if left != right:
            break
        shared.append(left)
    return shared


def _limiters(ctx: Context) -> Iterator[tuple[str, ast.Module, ast.Call]]:
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel) or "Limiter(" not in text:
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for call in pyast.calls(tree, PY_LIMITER) if tree else []:
            yield entry.rel, tree, call


def _memory_storage(tree: ast.Module, call: ast.Call) -> str | None:
    """'always' when the limiter can only use memory, 'fallback' when one branch picks memory."""
    storage = pyast.kwarg(call, "storage_uri")
    if storage is None:
        return "always"
    value = pyast.constant(storage, None)
    if isinstance(value, str):
        return "always" if value.startswith("memory://") else None
    if isinstance(storage, ast.Name):
        fn = pyast.function_at(tree, call.lineno)
        for node in ast.walk(fn or tree):
            if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == storage.id for t in node.targets
            ):
                literal = pyast.constant(node.value, None)
                if isinstance(literal, str) and literal.startswith("memory://"):
                    return "fallback"
    return None


def _inmemory(
    ctx: Context, rel: str, line: int, tag: Tag, what: str, evidence: Location
) -> Finding:
    return make_finding(
        "ABUSE-INMEMORY-LIMITER",
        tag=tag,
        locations=[Location(rel, line), evidence],
        snippet=snippet(ctx.index.text(rel), line),
        proof_needed="Check whether production sets the shared store (for example REDIS_URL).",
        what=what,
    )


@rule(
    "ABUSE-INMEMORY-LIMITER",
    review="abuse",
    severity="medium",
    exploitability="medium",
    owasp="A04",
)
def inmemory_limiter(ctx: Context) -> Iterator[Finding]:
    if multi_process(ctx) is None:
        return
    for rel, tree, call in _limiters(ctx):
        evidence = multi_process(ctx, rel)
        kind = _memory_storage(tree, call)
        if kind == "always":
            what = "The limiter keeps its counters in process memory."
            yield _inmemory(ctx, rel, call.lineno, Tag.CONFIRMED, what, evidence)
        elif kind == "fallback":
            what = "The limiter falls back to process memory when no shared store is configured."
            yield _inmemory(ctx, rel, call.lineno, Tag.INFERRED, what, evidence)
    for entry in ctx.index.js_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel) or not re.search(r"rateLimit|new Map\(", text):
            continue
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for call in jsts.calls(tree, r"rateLimit|slowDown"):
                args = jsts.arguments(call)
                if not args or "store" not in jsts.object_pairs(args[0]):
                    what = "express-rate-limit has no store option, so it counts in process memory."
                    line = jsts.line(tree, call)
                    evidence = multi_process(ctx, entry.rel)
                    yield _inmemory(ctx, entry.rel, line, Tag.CONFIRMED, what, evidence)
            for decl in jsts.walk(tree.root, {"variable_declarator"}):
                name = jsts.node_text(decl.child_by_field_name("name"))
                value = jsts.node_text(decl.child_by_field_name("value"))
                top_level = jsts.enclosing_function(decl) is None
                if top_level and value.startswith("new Map(") and COUNTER_NAME.search(name):
                    what = f"The module-level Map {name} counts requests in process memory."
                    line = jsts.line(tree, decl)
                    evidence = multi_process(ctx, entry.rel)
                    yield _inmemory(ctx, entry.rel, line, Tag.INFERRED, what, evidence)


@rule(
    "ABUSE-LIMITER-NOT-APPLIED",
    review="abuse",
    severity="medium",
    exploitability="medium",
    owasp="A04",
)
def limiter_not_applied(ctx: Context) -> Iterator[Finding]:
    wired = any(
        "SlowAPI" in ctx.index.text(f.rel) and "add_middleware" in ctx.index.text(f.rel)
        for f in ctx.index.py_files
    )
    if wired:
        return
    for rel, _tree, call in _limiters(ctx):
        defaults = pyast.kwarg(call, "default_limits")
        if defaults is not None and "slowapi" in ctx.index.text(rel):
            yield make_finding(
                "ABUSE-LIMITER-NOT-APPLIED",
                tag=Tag.CONFIRMED,
                locations=[Location(rel, defaults.lineno)],
                snippet=snippet(ctx.index.text(rel), defaults.lineno),
            )


@rule(
    "ABUSE-LIMITER-PROXY-IP",
    review="abuse",
    severity="medium",
    exploitability="medium",
    owasp="A04",
)
def limiter_proxy_ip(ctx: Context) -> Iterator[Finding]:
    if not ctx.detection.hosting:
        return
    if any(PROXY_TRUST.search(ctx.index.text(f.rel)) for f in ctx.index.files):
        return
    for rel, _tree, call in _limiters(ctx):
        key = pyast.kwarg(call, "key_func")
        if key is not None and (pyast.dotted(key) or "").endswith("get_remote_address"):
            yield make_finding(
                "ABUSE-LIMITER-PROXY-IP",
                tag=Tag.INFERRED,
                locations=[Location(rel, key.lineno)],
                snippet=snippet(ctx.index.text(rel), key.lineno),
                key="get_remote_address",
            )
    for entry in ctx.index.js_files:
        if is_test(entry.rel) or "rateLimit" not in ctx.index.text(entry.rel):
            continue
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for call in jsts.calls(tree, r"rateLimit"):
                args = jsts.arguments(call)
                if not args or "keyGenerator" not in jsts.object_pairs(args[0]):
                    line = jsts.line(tree, call)
                    yield make_finding(
                        "ABUSE-LIMITER-PROXY-IP",
                        tag=Tag.INFERRED,
                        locations=[Location(entry.rel, line)],
                        snippet=snippet(ctx.index.text(entry.rel), line),
                        key="req.ip",
                    )


@rule(
    "ABUSE-UPLOAD-UNBOUNDED",
    review="abuse",
    severity="low",
    exploitability="medium",
    owasp="A04",
)
def upload_unbounded(ctx: Context) -> Iterator[Finding]:
    for route in ctx.detection.routes:
        fn = route.handler
        if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef) or is_test(route.file):
            continue
        uploads = {
            a.arg
            for a in [*fn.args.args, *fn.args.kwonlyargs]
            if a.annotation is not None and "UploadFile" in ast.unparse(a.annotation)
        }
        for call in pyast.calls(route.tree, UPLOAD_READ, fn):
            target = call.func.value if isinstance(call.func, ast.Attribute) else None
            is_upload = isinstance(target, ast.Name) and target.id in uploads
            is_flask = target is not None and "request.files" in ast.unparse(target)
            if (is_upload or is_flask) and not call.args:
                later = ast.unparse(fn)[ast.unparse(fn).find(ast.unparse(call)) :]
                checked = bool(re.search(r"len\(\w+\)\s*>", later))
                what = (
                    "reads the whole upload into memory and only then checks its size"
                    if checked
                    else "reads the whole upload into memory with no size limit"
                )
                yield make_finding(
                    "ABUSE-UPLOAD-UNBOUNDED",
                    tag=Tag.CONFIRMED,
                    locations=[Location(route.file, call.lineno)],
                    snippet=snippet(ctx.index.text(route.file), call.lineno),
                    method=route.method,
                    path=route.path,
                    what=what,
                )
```

`src/dpr/data/rule_text/abuse_limits.yaml`:

```yaml
ABUSE-INMEMORY-LIMITER:
  title: Rate limiter counts in process memory on a multi-process deploy
  effort_minutes: 45
  detail: ${what} The deploy runs more than one process or instance (second location), and each keeps its own count, so the real limit is the configured limit times the number of processes, and counters reset on every restart.
  attack: Send requests fast enough to spread across workers, or wait for a restart, and exceed the intended limit.
  blast: Every route this limiter protects, including sign-in and paid routes.
  fix: Point the limiter at a shared store (Redis or the platform's rate limiting), refuse to start without it outside development, and fail closed on paid routes when the store is unreachable.
  verify: Run two workers locally with the shared store and confirm the limit holds across both.
ABUSE-LIMITER-NOT-APPLIED:
  title: Default rate limits are configured but never applied
  effort_minutes: 10
  detail: The slowapi Limiter sets default_limits, but SlowAPIMiddleware is never added to the app, so every route without its own @limiter.limit decorator is unlimited.
  attack: Script any undecorated route; nothing counts the requests.
  blast: Every route without an explicit limit decorator.
  fix: Add app.add_middleware(SlowAPIMiddleware) after setting app.state.limiter, then check that the default limit fits every route.
  verify: Call an undecorated route more times than the default limit within its window and expect 429.
ABUSE-LIMITER-PROXY-IP:
  title: Rate limits keyed on the connection address behind a proxy
  effort_minutes: 20
  detail: Limits are keyed with ${key}, which is the address of the direct connection. Hosted behind a load balancer or platform proxy, and with no forwarded-address trust configured anywhere, that is the proxy's address, so all users share one counter.
  proof_needed: Log the key value in production and compare it with the caller's real address.
  attack: Legitimate users lock each other out, while an attacker behind the same proxy exhausts the shared budget for everyone.
  blast: Every route limited by this key, including sign-in and password reset.
  fix: Trust forwarded headers only from the platform proxy (uvicorn or gunicorn --forwarded-allow-ips, Express app.set('trust proxy', 1)), and key authenticated routes on the user id.
  verify: From two networks, confirm the sixth request inside the window is limited only for the network that sent six.
ABUSE-UPLOAD-UNBOUNDED:
  title: ${method} ${path} buffers the whole upload
  effort_minutes: 15
  detail: The handler ${what}.
  attack: Send a multi-gigabyte upload, or many large ones in parallel, and exhaust the worker's memory.
  blast: Availability of the API worker for every user.
  fix: Reject requests whose Content-Length exceeds the limit before reading, read in chunks with a running total, and set a body size limit at the proxy or server.
  verify: Upload a file just over the limit and confirm a 413 before the worker's memory grows.
```

Modify `src/dpr/reviews/abuse.py`, replace:

```python
import dpr.reviews.abuse_paid  # noqa: F401  (registers rules)
```

with:

```python
import dpr.reviews.abuse_limits  # noqa: F401  (registers rules)
import dpr.reviews.abuse_paid  # noqa: F401  (registers rules)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest -q`
Expected: PASS (all tests, including 4 new ones)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/reviews/abuse_limits.py src/dpr/reviews/abuse.py src/dpr/data/rule_text/abuse_limits.yaml tests/reviews/test_abuse_limits.py
git commit -m "Add abuse checks for in-memory and unwired limiters, proxy-keyed limits and unbounded uploads"
```

---
### Task 46: CORS and exception text in responses

**Files:**
- Create: `src/dpr/reviews/abuse_cors.py`, `src/dpr/data/rule_text/abuse_cors.yaml`
- Modify: `src/dpr/reviews/abuse.py` (import the rule module)
- Test: `tests/reviews/test_abuse_cors.py`

**Interfaces:**
- Consumes: `access`, `PUBLIC` (Task 33), `is_test` (Task 37), plus the Milestone 1 helpers used by every rule module
- Produces registered rules (review `abuse`, owasp A05), sharing one parse through `ctx.facts["cors_findings"]`:
  - `ABUSE-CORS-WILDCARD` (high, CONFIRMED; only when the repository has at least one route that is not public): `cors()` with no options or `origin: '*'`, an `Access-Control-Allow-Origin: *` header literal, Django `CORS_ALLOW_ALL_ORIGINS` or `CORS_ORIGIN_ALLOW_ALL = True`, a CORS middleware with `allow_origins=['*']` or Flask-CORS `origins='*'`
  - `ABUSE-CORS-REFLECT` (CONFIRMED; critical when credentials are allowed anywhere in the file, else high): `origin: true`, an origin callback that approves with `(null, true)` and has no `includes`, `indexOf`, `.test`, `===` or allowlist, `Access-Control-Allow-Origin` copied from the request Origin header, `allow_origin_regex` of `.*`
  - `ABUSE-CORS-LOOSE-REGEX` (medium, CONFIRMED): a JS regex origin, `allow_origin_regex` or `CORS_ALLOWED_ORIGIN_REGEXES` entry not anchored with `^` and `$`
  - `ABUSE-ERROR-LEAK` (medium, CONFIRMED): in a file that defines routes, an `except` clause for `Exception`, `BaseException` or a bare `except` whose exception name, anything assigned from it, or `traceback.format_exc()` reaches a later `return` or a response call (`HTTPException`, `JSONResponse`, `Response`, `JsonResponse`, `HttpResponse`, `jsonify`, `make_response`, `abort`) in the same function; in JavaScript, a `catch` block whose `json`, `send` or `status` call includes `err.message` or `err.stack`. Narrow exception types such as `ValueError` are left alone: their messages are usually written for users.

- [ ] **Step 1: Write the failing tests**

`tests/reviews/test_abuse_cors.py`:

```python
from tests.reviews.helpers import findings_for, write


def with_auth_route(root):
    write(
        root,
        "app/api/me/route.ts",
        "export async function GET() {\n  const session = await auth()\n}\n",
    )


def summary(found):
    return sorted((str(f.locations[0]), f.severity.value) for f in found)


def test_js_cors(tmp_path):
    with_auth_route(tmp_path)
    write(
        tmp_path,
        "server/app.js",
        "app.use(cors())\n"
        "app.use(cors({ origin: true, credentials: true }))\n"
        "app.use(cors({ origin: (origin, cb) => cb(null, true) }))\n"
        "app.use(cors({ origin: (origin, cb) => cb(null, allowed.includes(origin)) }))\n"
        "app.use(cors({ origin: /example\\.com/ }))\n"
        "app.use(cors({ origin: /^https:\\/\\/app\\.example\\.com$/ }))\n"
        "app.use(cors({ origin: ['https://app.example.com'] }))\n"
        "res.setHeader('Access-Control-Allow-Origin', req.headers.origin)\n",
    )
    assert summary(findings_for(tmp_path, "abuse", "ABUSE-CORS-WILDCARD")) == [
        ("server/app.js:1", "high")
    ]
    assert summary(findings_for(tmp_path, "abuse", "ABUSE-CORS-REFLECT")) == [
        ("server/app.js:2", "critical"),
        ("server/app.js:3", "critical"),
        ("server/app.js:8", "critical"),
    ]
    assert summary(findings_for(tmp_path, "abuse", "ABUSE-CORS-LOOSE-REGEX")) == [
        ("server/app.js:5", "medium")
    ]


def test_python_cors(tmp_path):
    with_auth_route(tmp_path)
    write(
        tmp_path,
        "site/settings.py",
        "CORS_ALLOW_ALL_ORIGINS = True\nCORS_ALLOWED_ORIGIN_REGEXES = [r'https://.*\\.example\\.com']\n",
    )
    write(
        tmp_path,
        "api/main.py",
        "app.add_middleware(CORSMiddleware, allow_origins=['*'])\n"
        "app.add_middleware(CORSMiddleware, allow_origin_regex='.*', allow_credentials=True)\n"
        "app.add_middleware(CORSMiddleware, allow_origins=settings.origins, allow_credentials=True)\n",
    )
    assert summary(findings_for(tmp_path, "abuse", "ABUSE-CORS-WILDCARD")) == [
        ("api/main.py:1", "high"),
        ("site/settings.py:1", "high"),
    ]
    assert summary(findings_for(tmp_path, "abuse", "ABUSE-CORS-REFLECT")) == [
        ("api/main.py:2", "critical")
    ]
    assert summary(findings_for(tmp_path, "abuse", "ABUSE-CORS-LOOSE-REGEX")) == [
        ("site/settings.py:2", "medium")
    ]


def test_wildcard_ignored_without_signed_in_routes(tmp_path):
    write(
        tmp_path,
        "server/app.js",
        "app.use(cors())\napp.get('/status', (req, res) => res.send('ok'))\n",
    )
    assert findings_for(tmp_path, "abuse", "ABUSE-CORS-WILDCARD") == []


def test_error_leak(tmp_path):
    write(
        tmp_path,
        "api/routes.py",
        "from fastapi import APIRouter\nrouter = APIRouter()\n"
        "@router.get('/report')\nasync def report():\n"
        "    try:\n        build()\n    except Exception as e:\n"
        "        raise HTTPException(status_code=500, detail=f'Report error: {type(e).__name__}: {e}')\n"
        "@router.get('/health')\nasync def health():\n"
        "    status = 'ok'\n    try:\n        ping()\n    except Exception as e:\n"
        "        status = f'error: {type(e).__name__}'\n"
        "    return {'database': status}\n"
        "@router.post('/items')\nasync def create():\n"
        "    try:\n        save()\n    except ValueError as e:\n        raise HTTPException(status_code=400, detail=str(e))\n"
        "@router.get('/safe')\nasync def safe():\n"
        "    try:\n        build()\n    except Exception:\n        logger.exception('failed')\n"
        "        raise HTTPException(status_code=500, detail='Internal error')\n",
    )
    write(
        tmp_path,
        "app/api/export/route.ts",
        "export async function GET() {\n  try {\n    await run()\n  } catch (err) {\n"
        "    return NextResponse.json({ error: err.message }, { status: 500 })\n  }\n}\n"
        "export async function POST() {\n  try {\n    await run()\n  } catch (err) {\n"
        "    return NextResponse.json({ error: 'failed' }, { status: 500 })\n  }\n}\n",
    )
    found = findings_for(tmp_path, "abuse", "ABUSE-ERROR-LEAK")
    assert summary(found) == [
        ("api/routes.py:16", "medium"),
        ("api/routes.py:8", "medium"),
        ("app/api/export/route.ts:5", "medium"),
    ]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/reviews/test_abuse_cors.py -q`
Expected: FAIL in 3 tests (the rules are not registered, so every comparison meets an empty result); `test_wildcard_ignored_without_signed_in_routes` already passes

- [ ] **Step 3: Write the rules and the rule text**

`src/dpr/reviews/abuse_cors.py`:

```python
"""Review 7, abuse: CORS that trusts any origin, loose origin patterns, error text in responses."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Tag
from dpr.parsing import jsts, pyast
from dpr.redact import snippet
from dpr.reviews.access import PUBLIC, access
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule
from dpr.walk import line_of

JS_CREDENTIALS = re.compile(r"credentials\s*:\s*true|Allow-Credentials['\"]?\s*[,:]\s*['\"]true")
PY_CREDENTIALS = re.compile(
    r"allow_credentials\s*=\s*True|CORS_ALLOW_CREDENTIALS\s*=\s*True|supports_credentials\s*=\s*True"
)
ACAO_WILDCARD = re.compile(r"""Access-Control-Allow-Origin['"]?\s*[,:]\s*['"]\*['"]""", re.I)
ACAO_REFLECT = re.compile(
    r"""Access-Control-Allow-Origin['"]?\s*[,:]\s*(?:req|request)\.(?:headers\.origin|headers\.get\(\s*['"]origin)""",
    re.I,
)
BROAD_EXCEPTIONS = {None, "Exception", "BaseException"}
RESPONSE_CALLS = re.compile(
    r"(?:\w+\.)*(?:HTTPException|JSONResponse|Response|PlainTextResponse|HTMLResponse|JsonResponse"
    r"|HttpResponse|jsonify|make_response|abort)"
)
JS_ERROR_TEXT = re.compile(r"\b(?:err|error|e|ex|exception)\.(?:message|stack)\b")


def _has_auth_routes(ctx: Context) -> bool:
    return any(access(ctx, r).level != PUBLIC for r in ctx.detection.routes)


def _cors(
    ctx: Context, rule_id: str, rel: str, line: int, severity: str | None, what: str
) -> Finding:
    return make_finding(
        rule_id,
        tag=Tag.CONFIRMED,
        locations=[Location(rel, line)],
        severity=severity,
        snippet=snippet(ctx.index.text(rel), line),
        what=what,
    )


def _js_cors(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.js_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel) or not re.search(r"cors|Access-Control-Allow-Origin", text, re.I):
            continue
        credentials = bool(JS_CREDENTIALS.search(text))
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for call in jsts.calls(tree, r"cors"):
                args = jsts.arguments(call)
                line = jsts.line(tree, call)
                origin = jsts.object_pairs(args[0]).get("origin") if args else None
                value = jsts.node_text(origin) if origin is not None else None
                if not args or value in ("'*'", '"*"'):
                    yield _cors(
                        ctx,
                        "ABUSE-CORS-WILDCARD",
                        entry.rel,
                        line,
                        None,
                        "cors() allows every origin.",
                    )
                elif value == "true":
                    severity = "critical" if credentials else "high"
                    what = "cors() reflects any request origin back as allowed."
                    yield _cors(ctx, "ABUSE-CORS-REFLECT", entry.rel, line, severity, what)
                elif origin is not None and origin.type in jsts.FUNCTION_TYPES:
                    body = jsts.node_text(origin)
                    if re.search(r"\(\s*null\s*,\s*true\s*\)", body) and not re.search(
                        r"includes\(|indexOf\(|\.test\(|===|allow", body
                    ):
                        severity = "critical" if credentials else "high"
                        what = (
                            "The origin callback approves every origin without an allowlist check."
                        )
                        yield _cors(ctx, "ABUSE-CORS-REFLECT", entry.rel, line, severity, what)
                elif origin is not None and origin.type == "regex":
                    pattern = jsts.node_text(origin.child_by_field_name("pattern"))
                    if not (pattern.startswith("^") and pattern.endswith("$")):
                        what = f"The origin pattern /{pattern}/ is not anchored with ^ and $."
                        yield _cors(ctx, "ABUSE-CORS-LOOSE-REGEX", entry.rel, line, None, what)
        for match in ACAO_WILDCARD.finditer(text):
            what = "Access-Control-Allow-Origin is set to *."
            yield _cors(
                ctx, "ABUSE-CORS-WILDCARD", entry.rel, line_of(text, match.start()), None, what
            )
        for match in ACAO_REFLECT.finditer(text):
            severity = "critical" if credentials else "high"
            what = "Access-Control-Allow-Origin is copied from the request Origin header."
            line = line_of(text, match.start())
            yield _cors(ctx, "ABUSE-CORS-REFLECT", entry.rel, line, severity, what)


def _py_cors(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel) or not re.search(r"CORS|allow_origin", text):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        if tree is None:
            continue
        credentials = bool(PY_CREDENTIALS.search(text))
        for stmt in tree.body:
            if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name):
                name = stmt.targets[0].id
                if (
                    name in ("CORS_ALLOW_ALL_ORIGINS", "CORS_ORIGIN_ALLOW_ALL")
                    and pyast.constant(stmt.value) is True
                ):
                    what = f"{name} = True allows every origin."
                    yield _cors(ctx, "ABUSE-CORS-WILDCARD", entry.rel, stmt.lineno, None, what)
                if name == "CORS_ALLOWED_ORIGIN_REGEXES" and isinstance(
                    stmt.value, ast.List | ast.Tuple
                ):
                    for item in stmt.value.elts:
                        yield from _regex(ctx, entry.rel, item)
        for call in pyast.calls(tree, r"(?:\w+\.)*(?:add_middleware|CORSMiddleware|CORS)"):
            origins = pyast.kwarg(call, "allow_origins") or pyast.kwarg(call, "origins")
            if origins is not None and "'*'" in ast.unparse(origins):
                what = "The CORS middleware allows every origin."
                yield _cors(ctx, "ABUSE-CORS-WILDCARD", entry.rel, origins.lineno, None, what)
            regex = pyast.kwarg(call, "allow_origin_regex")
            if regex is not None and pyast.constant(regex, "") in (".*", "^.*$", ".+"):
                severity = "critical" if credentials else "high"
                what = (
                    "allow_origin_regex matches every origin, so any site is reflected as allowed."
                )
                yield _cors(ctx, "ABUSE-CORS-REFLECT", entry.rel, regex.lineno, severity, what)
            elif regex is not None:
                yield from _regex(ctx, entry.rel, regex)


def _regex(ctx: Context, rel: str, node: ast.AST) -> Iterator[Finding]:
    pattern = pyast.constant(node, None)
    if isinstance(pattern, str) and not (pattern.startswith("^") and pattern.endswith("$")):
        what = f"The origin pattern {pattern} is not anchored with ^ and $."
        yield _cors(ctx, "ABUSE-CORS-LOOSE-REGEX", rel, node.lineno, None, what)


def _cors_findings(ctx: Context) -> list[Finding]:
    if "cors_findings" not in ctx.facts:
        ctx.facts["cors_findings"] = [*_js_cors(ctx), *_py_cors(ctx)]
    return ctx.facts["cors_findings"]


@rule("ABUSE-CORS-WILDCARD", review="abuse", severity="high", exploitability="medium", owasp="A05")
def cors_wildcard(ctx: Context) -> Iterator[Finding]:
    if _has_auth_routes(ctx):
        yield from (f for f in _cors_findings(ctx) if f.rule_id == "ABUSE-CORS-WILDCARD")


@rule("ABUSE-CORS-REFLECT", review="abuse", severity="high", exploitability="high", owasp="A05")
def cors_reflect(ctx: Context) -> Iterator[Finding]:
    yield from (f for f in _cors_findings(ctx) if f.rule_id == "ABUSE-CORS-REFLECT")


@rule(
    "ABUSE-CORS-LOOSE-REGEX",
    review="abuse",
    severity="medium",
    exploitability="medium",
    owasp="A05",
)
def cors_loose_regex(ctx: Context) -> Iterator[Finding]:
    yield from (f for f in _cors_findings(ctx) if f.rule_id == "ABUSE-CORS-LOOSE-REGEX")


def _error_names(handler: ast.ExceptHandler) -> set[str]:
    names = {handler.name} if handler.name else set()
    for node in ast.walk(handler):
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            if pyast.names_in(node.value) & names or "format_exc" in ast.unparse(node.value):
                names.add(node.targets[0].id)
    return names


def _py_error_leaks(tree: ast.Module) -> Iterator[int]:
    for fn in pyast.functions(tree):
        for handler in [n for n in ast.walk(fn) if isinstance(n, ast.ExceptHandler)]:
            kind = pyast.dotted(handler.type) if handler.type is not None else None
            if kind not in BROAD_EXCEPTIONS:
                continue
            names = _error_names(handler)
            for node in ast.walk(fn):
                if getattr(node, "lineno", 0) < handler.lineno:
                    continue
                if isinstance(node, ast.Return) and node.value is not None:
                    value = node.value
                elif isinstance(node, ast.Call) and RESPONSE_CALLS.fullmatch(
                    pyast.dotted(node.func) or ""
                ):
                    value = node
                else:
                    continue
                text = ast.unparse(value)
                if pyast.names_in(value) & names or "format_exc()" in text:
                    yield node.lineno
                    break


@rule("ABUSE-ERROR-LEAK", review="abuse", severity="medium", exploitability="medium", owasp="A05")
def error_leak(ctx: Context) -> Iterator[Finding]:
    route_files = {r.file for r in ctx.detection.routes}
    for entry in ctx.index.py_files:
        if entry.rel not in route_files or is_test(entry.rel):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for line in sorted(set(_py_error_leaks(tree))) if tree else []:
            yield make_finding(
                "ABUSE-ERROR-LEAK",
                tag=Tag.CONFIRMED,
                locations=[Location(entry.rel, line)],
                snippet=snippet(ctx.index.text(entry.rel), line),
            )
    for entry in ctx.index.js_files:
        if entry.rel not in route_files or is_test(entry.rel):
            continue
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for clause in jsts.walk(tree.root, {"catch_clause"}):
                body = clause.child_by_field_name("body")
                for call in jsts.calls(
                    tree, r"(?:\w+\.)*(?:json|send|status|Response\.json|NextResponse\.json)", body
                ):
                    if JS_ERROR_TEXT.search(jsts.node_text(call)):
                        line = jsts.line(tree, call)
                        yield make_finding(
                            "ABUSE-ERROR-LEAK",
                            tag=Tag.CONFIRMED,
                            locations=[Location(entry.rel, line)],
                            snippet=snippet(ctx.index.text(entry.rel), line),
                        )
                        break
```

`src/dpr/data/rule_text/abuse_cors.yaml`:

```yaml
ABUSE-CORS-WILDCARD:
  title: CORS allows every origin on an API with signed-in routes
  effort_minutes: 10
  detail: ${what} CORS does not authorise anything, but it widens which sites can script calls to this API from a visitor's browser.
  attack: Host a page that calls the API from the visitor's browser and reads any response the browser is allowed to share.
  blast: Responses readable cross-site, and every weakness in the API reachable from any web page.
  fix: Allow only the exact production and preview origins, and keep authorisation checks in every route.
  verify: curl -sSI -H "Origin https://evil.example" against an API route and confirm no Access-Control-Allow-Origin for it.
ABUSE-CORS-REFLECT:
  title: CORS reflects any origin
  effort_minutes: 15
  detail: ${what} With credentials allowed, any website can make signed-in requests and read the responses.
  attack: A page on any domain calls the API with credentials included; the API echoes that origin as allowed, and the page reads the victim's data.
  blast: Every response the signed-in victim can fetch, for every visitor who opens the attacker's page.
  fix: Compare the Origin header against an explicit allowlist and only then echo it back; never combine a reflected origin with credentials.
  verify: curl -sSI -H "Origin https://evil.example" against an API route and confirm the origin is not echoed.
ABUSE-CORS-LOOSE-REGEX:
  title: CORS origin pattern is not anchored
  effort_minutes: 10
  detail: ${what} A lookalike domain that contains the allowed text also matches.
  attack: Register a domain such as yourapp.com.evil.example or evil-yourapp.vercel.app that satisfies the pattern.
  blast: The same as an allowed origin, including credentialed requests when they are enabled.
  fix: Anchor the pattern with ^ and $, escape the dots, and prefer an explicit list of origins.
  verify: Test the pattern against a lookalike origin and confirm it does not match.
ABUSE-ERROR-LEAK:
  title: Exception text returned to the caller
  effort_minutes: 10
  detail: A catch-all error handler puts the exception message, type or traceback into the response, which tells an attacker about the schema, libraries and internal state.
  attack: Send malformed input until the handler fails, then read table names, file paths or library errors from the response.
  blast: Internal details that make other attacks faster.
  fix: Log the exception with a request id and return a generic message with that id; keep specific messages only for errors written for users.
  verify: Force the error path in a test and confirm the response body holds only the generic message and the id.
```

Modify `src/dpr/reviews/abuse.py`, replace:

```python
import dpr.reviews.abuse_limits  # noqa: F401  (registers rules)
```

with:

```python
import dpr.reviews.abuse_cors  # noqa: F401  (registers rules)
import dpr.reviews.abuse_limits  # noqa: F401  (registers rules)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest -q`
Expected: PASS (all tests, including 4 new ones)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/reviews/abuse_cors.py src/dpr/reviews/abuse.py src/dpr/data/rule_text/abuse_cors.yaml tests/reviews/test_abuse_cors.py
git commit -m "Add abuse checks for permissive CORS and exception text in responses"
```

---
### Task 47: Abuse section, cost surface, limits, implementation and alerts

**Files:**
- Modify: `src/dpr/reviews/abuse.py` (replace the whole file)
- Test: `tests/reviews/test_abuse_section.py`

**Interfaces:**
- Consumes: `paid_routes`, `costs` (Task 44); `is_limited` (Task 44); `access`, `PUBLIC` (Task 33); the `finish` hook (Task 43)
- Produces abuse section parts in order: text "How to read the limits"; table "Cost surface" (`Route | Calls | Cost per call | Auth required | Current limit`, one row per paid route, then one per public non-GET form route); table "Limits per endpoint" (`Endpoint | Cost | Per user | Per IP | Window | Reasoning` from `costs.yaml`, reasoning always "starting default, not measured traffic"); text "Implementation for this stack" (slowapi for FastAPI, Upstash for Next.js, express-rate-limit with a Redis store for Express, django-ratelimit, Flask-Limiter); findings "Guards"; text "CORS and error messages" (CORS summary and one rewrite line per `ABUSE-ERROR-LEAK` location); text "Alerts and kill switches" (rate of spend, provider hard caps, signup anomaly, error spike, and one named `*_ENABLED` flag per paid route)

- [ ] **Step 1: Write the failing test**

`tests/reviews/test_abuse_section.py`:

```python
from dpr.api import review
from dpr.report.markdown import render_markdown
from tests.reviews.helpers import write


def app(root):
    write(root, "requirements.txt", "fastapi\nanthropic\n")
    write(
        root,
        "api/chat.py",
        "import anthropic\nclient = anthropic.Anthropic()\n"
        "def ask(messages):\n    return client.messages.create(messages=messages)\n",
    )
    write(
        root,
        "api/routes.py",
        "from fastapi import APIRouter, Depends\nrouter = APIRouter(prefix='/api')\n"
        "@router.post('/chat')\nasync def chat(user=Depends(get_current_user)):\n    return ask([])\n"
        "@router.post('/auth/register')\nasync def register(data): ...\n"
        "@router.post('/auth/login')\nasync def login(data): ...\n"
        "@router.get('/report')\nasync def report(user=Depends(get_current_user)):\n"
        "    try:\n        build()\n    except Exception as e:\n"
        "        raise HTTPException(status_code=500, detail=str(e))\n",
    )
    return root


def test_abuse_section_parts(tmp_path):
    report = review(app(tmp_path), reviews=["abuse"])
    parts = {p.title: p for p in report.sections["abuse"].parts}
    assert list(parts) == [
        "How to read the limits",
        "Cost surface",
        "Limits per endpoint",
        "Implementation for this stack",
        "Guards",
        "CORS and error messages",
        "Alerts and kill switches",
    ]
    assert parts["Cost surface"].rows == (
        ("POST /api/chat", "anthropic", "tokens per call, priced per model", "yes", "none found"),
        (
            "POST /api/auth/register",
            "public form",
            "a stored row and often an email per submission",
            "no",
            "none found",
        ),
        (
            "POST /api/auth/login",
            "public form",
            "password hashing CPU and credential stuffing",
            "no",
            "none found",
        ),
    )
    assert parts["Limits per endpoint"].rows[0] == (
        "POST /api/chat",
        "tokens per call, priced per model",
        "20",
        "40",
        "1 h",
        "starting default, not measured traffic",
    )
    assert parts["Limits per endpoint"].rows[2][2:5] == ("10", "20", "15 min")
    assert "SlowAPIMiddleware" in parts["Implementation for this stack"].body
    assert "- `api/routes.py:15`: return a generic message" in parts["CORS and error messages"].body
    assert "- `API_CHAT_ENABLED` for POST /api/chat" in parts["Alerts and kill switches"].body
    text = render_markdown(report)
    assert "## 7. Abuse and bill guard" in text and "#### GUARD 1:" in text
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/reviews/test_abuse_section.py -q`
Expected: FAIL with `AssertionError` on the part titles (the section only has "Guards")

- [ ] **Step 3: Write the section**

Replace the whole of `src/dpr/reviews/abuse.py`:

`src/dpr/reviews/abuse.py`:

````python
"""Review 7, abuse and bill guard: paid routes, limits, forms, CORS and error text."""

from __future__ import annotations

import re

import dpr.reviews.abuse_cors  # noqa: F401  (registers rules)
import dpr.reviews.abuse_limits  # noqa: F401  (registers rules)
import dpr.reviews.abuse_paid  # noqa: F401  (registers rules)
from dpr.model import Finding, Part, ReviewSection
from dpr.reviews.abuse_paid import is_limited
from dpr.reviews.access import PUBLIC, access
from dpr.reviews.paid import costs, paid_routes
from dpr.rules import Context

INTRO = (
    "Limits below are starting defaults, not measured traffic. Start from the real peak per user, "
    "roughly double it, and limit per signed-in user before per IP."
)
SNIPPETS = {
    "fastapi": (
        "```python\nlimiter = Limiter(key_func=user_or_ip, storage_uri=settings.redis_url,\n"
        '                  default_limits=["600/10minutes"])\n'
        "app.state.limiter = limiter\napp.add_middleware(SlowAPIMiddleware)\n\n"
        '@router.post("/generate")\n@limiter.limit("20/hour")\n'
        "async def generate(request: Request, user: CurrentUser): ...\n```\n\n"
        "Run the server with --forwarded-allow-ips set to the platform proxy so the IP key is "
        "the caller, and refuse to start without the shared store outside development."
    ),
    "next": (
        "```ts\nconst ratelimit = new Ratelimit({ redis: Redis.fromEnv(), "
        'limiter: Ratelimit.slidingWindow(20, "1 h") })\n'
        "const { success } = await ratelimit.limit(session.user.id)\n"
        'if (!success) return new Response("Too many requests", { status: 429 })\n```'
    ),
    "express": (
        "```js\napp.set('trust proxy', 1)\napp.use('/api/generate', rateLimit({ windowMs: 60 * 60 "
        "* 1000, limit: 20,\n  keyGenerator: (req) => req.user?.id ?? req.ip,\n"
        "  store: new RedisStore({ sendCommand: (...args) => redis.sendCommand(args) }) }))\n```"
    ),
    "django": (
        "```python\n@ratelimit(key='user_or_ip', rate='20/h', block=True)\n"
        "def generate(request): ...\n```\n\nSet CACHES to a shared Redis cache so every worker "
        "counts together."
    ),
    "flask": (
        "```python\nlimiter = Limiter(get_remote_address, app=app, storage_uri=REDIS_URL)\n\n"
        '@app.post("/generate")\n@limiter.limit("20 per hour")\ndef generate(): ...\n```'
    ),
}
ALERTS = (
    "- Rate of spend, not total: alert when paid calls in the last hour exceed 3 times the "
    "trailing 7-day hourly average.\n"
    "- Provider-side hard caps: set a monthly limit in every paid provider's dashboard; a cap is "
    "the only thing that stops the bill.\n"
    "- Signup rate anomaly: bot registration usually starts minutes before the abuse.\n"
    "- Error spike on paid routes: failures that still cost money are the worst case."
)


def _flag(path: str) -> str:
    return (re.sub(r"[^A-Z0-9]+", "_", path.upper()).strip("_") or "PAID_ROUTE") + "_ENABLED"


def _cost_rows(ctx: Context) -> tuple[tuple[str, ...], ...]:
    rows = []
    for paid in paid_routes(ctx):
        route = paid.route
        cost = costs().get(paid.sdk.category, {"note": "provider pricing"})
        rows.append(
            (
                f"{route.method} {route.path}",
                paid.sdk.name,
                cost["note"],
                "no" if access(ctx, route).level == PUBLIC else "yes",
                "yes" if is_limited(ctx, route) else "none found",
            )
        )
    for route in ctx.detection.routes:
        if route.is_public_form and access(ctx, route).level == PUBLIC and route.method != "GET":
            kind = "login" if re.search(r"(?i)log-?in|sign-?in", route.path) else "form"
            limited = "yes" if is_limited(ctx, route) else "none found"
            rows.append(
                (
                    f"{route.method} {route.path}",
                    "public form",
                    costs()[kind]["note"],
                    "no",
                    limited,
                )
            )
    return tuple(rows)


def _limit_rows(rows: tuple[tuple[str, ...], ...], ctx: Context) -> tuple[tuple[str, ...], ...]:
    by_route = {f"{p.route.method} {p.route.path}": p.sdk.category for p in paid_routes(ctx)}
    limits = []
    for endpoint, _calls, note, _auth, _limited in rows:
        if endpoint in by_route:
            key = by_route[endpoint]
        else:
            key = "login" if re.search(r"(?i)log-?in|sign-?in", endpoint) else "form"
        cost = costs().get(key, costs()["form"])
        limits.append(
            (
                endpoint,
                note,
                str(cost["per_user"]),
                str(cost["per_ip"]),
                cost["window"],
                "starting default, not measured traffic",
            )
        )
    return tuple(limits)


def _snippet(ctx: Context) -> str:
    for framework in ("fastapi", "next", "express", "django", "flask"):
        if framework in ctx.detection.frameworks:
            return SNIPPETS[framework]
    return "No supported server framework was detected, so no implementation snippet is given."


def run(ctx: Context) -> ReviewSection:
    return ReviewSection(
        "abuse", [Part("text", "How to read the limits", body=INTRO), Part("findings", "Guards")]
    )


def finish(ctx: Context, section: ReviewSection, findings: list[Finding]) -> None:
    rows = _cost_rows(ctx)
    position = next(i for i, p in enumerate(section.parts) if p.kind == "findings")
    added = [
        Part(
            "table",
            "Cost surface",
            ("Route", "Calls", "Cost per call", "Auth required", "Current limit"),
            rows,
        ),
        Part(
            "table",
            "Limits per endpoint",
            ("Endpoint", "Cost", "Per user", "Per IP", "Window", "Reasoning"),
            _limit_rows(rows, ctx),
        ),
        Part("text", "Implementation for this stack", body=_snippet(ctx)),
    ]
    section.parts[position:position] = added
    leaks = [f for f in findings if f.rule_id == "ABUSE-ERROR-LEAK"]
    cors = [f for f in findings if f.rule_id.startswith("ABUSE-CORS-")]
    lines = [
        f"- `{f.locations[0]}`: return a generic message with a request id; log the exception."
        for f in leaks
    ]
    cors_text = (
        f"{len(cors)} CORS finding(s) above. Allow only exact production and preview origins."
        if cors
        else "No wildcard, reflected or loose CORS origin was found."
    )
    body = cors_text + "\n\nError messages to rewrite:\n\n" + ("\n".join(lines) or "None found.")
    section.parts.append(Part("text", "CORS and error messages", body=body))
    switches = [
        f"- `{_flag(p.route.path)}` for {p.route.method} {p.route.path}" for p in paid_routes(ctx)
    ]
    kill = "\n\nKill switches, read on every request:\n\n" + "\n".join(switches) if switches else ""
    section.parts.append(Part("text", "Alerts and kill switches", body=ALERTS + kill))
````

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest -q`
Expected: PASS (all tests, including 1 new one)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/reviews/abuse.py tests/reviews/test_abuse_section.py
git commit -m "Add the abuse section with cost surface, starting limits, implementation and alerts"
```

---
### Task 48: Browser-shipped gate keys and committed default credentials

Both rules report where a value is and never the value: neither sets a snippet.

**Files:**
- Create: `src/dpr/reviews/leaks_creds.py`, `src/dpr/data/rule_text/leaks_creds.yaml`
- Modify: `src/dpr/reviews/leaks.py` (import the rule module)
- Test: `tests/reviews/test_leaks_creds.py`

**Interfaces:**
- Consumes: `public_prefix` (Task 6), `EnvVar` locations from detection (Task 15), `is_test` (Task 37), `review()`, `render_markdown`, `render_json` (Tasks 23 to 25)
- Produces registered rules (review `leaks`):
  - `LEAK-PUBLIC-GATE-KEY` (low, CONFIRMED, owasp A05): a public-prefixed variable whose name says it opens a gate (`BYPASS`, `UNLOCK`, `OVERRIDE`, `BACKDOOR`, `MASTER_KEY`, `ACCESS_CODE`, `INVITE_CODE`, `STAFF_KEY`, `MAINTENANCE_KEY`, `PREVIEW_KEY`, `DEBUG_KEY`). Locations are literal assignments of that name in YAML, TOML, JSON, Terraform or a Dockerfile (not `$(...)`, `${...}` or `${{ }}` references), then its code references.
  - `LEAK-DEFAULT-CREDENTIAL` (low, CONFIRMED, owasp A07; one finding per file): in compose files, a literal value for a key named like a password, secret, token, API key, private key or JWT; in compose files and scripts, `${NAME:-default}` fallbacks for such names, connection URLs with an inline password (outside Markdown and text files, and outside non-compose files when the host is localhost), and `--password value` style command lines in scripts and docs. Placeholders (`changeme`, `password`, `your-...`, `<...>`, `xxx`, `***`) are not reported.

- [ ] **Step 1: Write the failing tests**

`tests/reviews/test_leaks_creds.py`:

```python
from dpr.api import review
from dpr.report.json_out import render_json
from dpr.report.markdown import render_markdown
from tests.reviews.helpers import findings_for, write

BYPASS_VALUE = "cutover" + "-gate-" + "2031"
DB_DEFAULT = "localdev" + "pw" + "31"


def repo(root):
    write(
        root,
        "web/src/Gate.tsx",
        "export const ok = (k) => k === import.meta.env.VITE_STAFF_BYPASS_KEY\n",
    )
    write(root, "web/src/api.ts", "export const base = import.meta.env.VITE_API_URL\n")
    write(
        root,
        "azure-pipelines.yml",
        f"variables:\n  VITE_STAFF_BYPASS_KEY: '{BYPASS_VALUE}'\n  VITE_API_URL: $(API_URL)\n",
    )
    write(
        root,
        "docker-compose.yml",
        "services:\n  db:\n    environment:\n"
        f"      POSTGRES_PASSWORD: ${{DB_PASSWORD:-{DB_DEFAULT}}}\n"
        "      POSTGRES_USER: app\n"
        "      JWT_SECRET: ${JWT_SECRET}\n"
        f"      DATABASE_URL: postgresql://app:{DB_DEFAULT}@db:5432/app\n"
        "      API_TOKEN: changeme\n",
    )
    write(
        root,
        "scripts/restore.sh",
        f'SQL_PASSWORD="${{SQL_PASSWORD:-{DB_DEFAULT}}}"\nUSER="${{DB_USER:-sa}}"\n',
    )
    write(
        root,
        "scripts/migrate.py",
        f'"""Usage: migrate.py --src-password {DB_DEFAULT} --src-host localhost"""\n',
    )
    write(
        root,
        "docs/setup.md",
        "Run with --password <your-password> and postgresql://user:password@host/db\n",
    )
    write(
        root,
        "app/config.py",
        f"database_url = 'postgresql://app:{DB_DEFAULT}@localhost:5432/app'\n",
    )
    return root


def test_public_gate_key(tmp_path):
    [f] = findings_for(repo(tmp_path), "leaks", "LEAK-PUBLIC-GATE-KEY")
    assert [str(loc) for loc in f.locations] == ["azure-pipelines.yml:2", "web/src/Gate.tsx:1"]
    assert "committed at azure-pipelines.yml:2" in f.detail


def test_default_credentials(tmp_path):
    found = {
        f.locations[0].file: f
        for f in findings_for(repo(tmp_path), "leaks", "LEAK-DEFAULT-CREDENTIAL")
    }
    assert set(found) == {"docker-compose.yml", "scripts/restore.sh", "scripts/migrate.py"}
    assert [str(loc) for loc in found["docker-compose.yml"].locations] == [
        "docker-compose.yml:4",
        "docker-compose.yml:7",
    ]
    assert "a default value for DB_PASSWORD" in found["docker-compose.yml"].detail


def test_values_never_printed(tmp_path):
    report = review(repo(tmp_path))
    text = render_markdown(report) + render_json(report)
    assert BYPASS_VALUE not in text and DB_DEFAULT not in text
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/reviews/test_leaks_creds.py -q`
Expected: FAIL (the rules are not registered, so the unpacking and comparisons meet empty results; `test_values_never_printed` passes already)

- [ ] **Step 3: Write the rules and the rule text**

`src/dpr/reviews/leaks_creds.py`:

```python
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
```

`src/dpr/data/rule_text/leaks_creds.yaml`:

```yaml
LEAK-PUBLIC-GATE-KEY:
  title: Access gate key ${name} ships to the browser
  effort_minutes: 15
  detail: ${name} starts with ${prefix}, so its value is compiled into JavaScript anyone can download, yet its name says it unlocks something.${where}
  attack: Download the bundle, search for the key, and use it to pass the gate it protects.
  blast: Whatever the gate hides, such as a maintenance bypass or a preview area. The value is also in git history when it was committed.
  fix: Enforce the gate on the server (a signed cookie or a server-side check), drop the public prefix, and rotate the value because shipped bundles and history keep the old one.
  verify: Search the built JavaScript for the variable's value and confirm it is gone; confirm the gate still holds with the old value.
LEAK-DEFAULT-CREDENTIAL:
  title: Default or example credentials committed in ${file}
  effort_minutes: 15
  detail: ${file} contains ${kinds}. The values are not printed here. They are low risk only while nothing outside a local machine uses them.
  attack: Try the committed values against any environment that was started from this file or copied its settings.
  blast: Whatever database or service accepts the committed value.
  fix: Read the values from an untracked environment file or a secret store with no committed fallback, and change any deployed service that still uses them.
  verify: Search the file for password, secret and URL defaults and confirm each one is a variable reference with no fallback value.
```

Modify `src/dpr/reviews/leaks.py`, replace:

```python
from dpr.model import Finding, Location, Part, ReviewSection, Tag
```

with:

```python
import dpr.reviews.leaks_creds  # noqa: F401  (registers rules)
from dpr.model import Finding, Location, Part, ReviewSection, Tag
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest -q`
Expected: PASS (all tests, including 3 new ones)

- [ ] **Step 5: Commit**

```bash
git add src/dpr/reviews/leaks_creds.py src/dpr/reviews/leaks.py src/dpr/data/rule_text/leaks_creds.yaml tests/reviews/test_leaks_creds.py
git commit -m "Add leak checks for browser-shipped gate keys and committed default credentials"
```

---
### Task 49: Next.js fixtures carry the Milestone 2 defects

The spec's `next-supabase-bad` fixture lists defects that Milestone 1 could not detect yet: an invoice route with an unscoped `findUnique`, a generate route calling OpenAI with no auth and no limiter, a signup cookie without `httpOnly`, reflected CORS with credentials and `dangerouslySetInnerHTML` with user content. This task adds them, fixes each in `next-supabase-good` (which also gets every security header and a lock file), and makes the fixture test exact for all reviews again: the leaks and RLS filter from Task 31 goes away. The bad fixture also reports what these additions imply on their own: the existing users route now counts as an unscoped, guessable lookup, the Next.js config sends no security headers and keeps `X-Powered-By`, and `package.json` has no lock file.

The fixture builder gains a table of extras per fixture, so Tasks 50 and 51 can add fixtures without touching the Next.js extras.

**Files:**
- Modify (whole files below): `tests/fixtures/next-supabase-bad/app/api/signup/route.ts`, `tests/fixtures/next-supabase-bad/package.json`, `tests/fixtures/next-supabase-bad/expected.yaml`, `tests/fixtures/next-supabase-good/app/api/signup/route.ts`, `tests/fixtures/next-supabase-good/app/api/users/[id]/route.ts`, `tests/fixtures/next-supabase-good/package.json`, `tests/fixtures/next-supabase-good/next.config.js`, `tests/fixtures/next-supabase-good/prisma/schema.prisma`, `tests/fixtures/next-supabase-good/expected.yaml`, `tests/fixture_builder.py`, `tests/test_fixtures.py`
- Create: `tests/fixtures/next-supabase-bad/app/api/invoices/[id]/route.ts`, `tests/fixtures/next-supabase-bad/app/api/generate/route.ts`, `tests/fixtures/next-supabase-bad/components/Bio.tsx`, `tests/fixtures/next-supabase-good/app/api/invoices/[id]/route.ts`, `tests/fixtures/next-supabase-good/app/api/generate/route.ts`, `tests/fixtures/next-supabase-good/components/Bio.tsx`, `tests/fixtures/next-supabase-good/package-lock.json`

**Interfaces:**
- Consumes: every rule from Tasks 34 to 48; `build`, `FIXTURES`, `SECRETS` from the Milestone 1 builder (Task 27)
- Produces:
  - `tests.fixture_builder.EXTRAS: dict[str, Callable[[Path], None]]` and `_commit(root)`; `build(name, tmp_path)` looks the extras up by fixture name
  - `tests/test_fixtures.py`: `BAD` tuple and `GOOD` dict (fixture name to expected review sections), parametrised exact comparison for every bad fixture and must-not-report check for every good fixture
  - `next-supabase-good/expected.yaml` lists every rule id planted in any bad fixture of this milestone, so later tasks do not need to touch it

- [ ] **Step 1: Update the fixture test and the builder**

Replace the whole of `tests/test_fixtures.py`:

`tests/test_fixtures.py`:

```python
import pytest
import yaml

from dpr.api import review
from tests.fixture_builder import FIXTURES, build

BAD = ("next-supabase-bad",)
GOOD = {
    "next-supabase-good": {"leaks", "rls", "baseline", "owasp", "abuse"},
}


def found(report):
    return {
        (f.rule_id, f.locations[0].file, f.locations[0].line, f.tag.value) for f in report.findings
    }


@pytest.mark.parametrize("name", BAD)
def test_bad_fixture_reports_exactly_the_planted_defects(tmp_path, name):
    root = build(name, tmp_path)
    expected = yaml.safe_load((FIXTURES / name / "expected.yaml").read_text())
    want = {(e["rule"], e["file"], e["line"], e["tag"]) for e in expected["findings"]}
    got = found(review(root))
    assert got - want == set(), "unexpected findings"
    assert want - got == set(), "missing findings"


def test_bad_fixture_severities(tmp_path):
    report = review(build("next-supabase-bad", tmp_path))
    severity = {(f.rule_id, f.locations[0].line): f.severity.value for f in report.findings}
    assert severity[("RLS-TABLE-OFF", 10)] == "critical"
    assert severity[("LEAK-BROAD-RESPONSE", 6)] == "high"
    assert severity[("RLS-WEAK-WITH-CHECK", 3)] == "high"
    assert severity[("RLS-DEFINER-FUNCTION", 17)] == "high"
    assert severity[("ABUSE-PAID-UNAUTH", 6)] == "critical"
    assert severity[("ABUSE-CORS-REFLECT", 12)] == "critical"
    assert severity[("BASE-COOKIE-HTTPONLY", 9)] == "high"


@pytest.mark.parametrize("name", sorted(GOOD))
def test_good_fixture_reports_none_of_the_defects(tmp_path, name):
    report = review(build(name, tmp_path))
    banned = set(yaml.safe_load((FIXTURES / name / "expected.yaml").read_text())["must_not_report"])
    assert [f for f in report.findings if f.rule_id in banned] == []
    assert set(report.sections) == GOOD[name]
```

Replace the whole of `tests/fixture_builder.py`:

`tests/fixture_builder.py`:

```python
"""Copy a fixture app to a temporary folder and add what must never be committed."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
LIVE_STRIPE = "sk_" + "live_" + "Fx7Qp2Lm9Zr4Tb8Kw3Yd6Hn1"
ENV_VALUE = "ENVVALUE-" + "DO-NOT-PRINT-7731"
SECRETS = (LIVE_STRIPE, ENV_VALUE)


def git(root: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "-c",
            "user.name=dpr",
            "-c",
            "user.email=dpr@example.invalid",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        check=True,
        capture_output=True,
    )


def _commit(root: Path) -> None:
    git(root, "init", "-q")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "initial")


def _bad_extras(root: Path) -> None:
    (root / "lib/stripe.ts").write_text(
        'import Stripe from "stripe"\n\nexport const stripe = new Stripe("' + LIVE_STRIPE + '")\n'
    )
    chunks = root / ".next/static/chunks"
    chunks.mkdir(parents=True)
    (chunks / "main.js").write_text('var cfg={k:"' + LIVE_STRIPE + '"};')
    (chunks / "main.js.map").write_text("{}")
    git(root, "init", "-q")
    (root / ".env.production").write_text(f"OLD_TOKEN={ENV_VALUE}\n")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "initial")
    git(root, "rm", "-q", "--cached", ".env.production")
    (root / ".env.production").unlink()
    (root / ".env").write_text(f"DEBUG_LABEL={ENV_VALUE}\n")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "second")


def _good_extras(root: Path) -> None:
    (root / "lib/stripe.ts").write_text(
        'import Stripe from "stripe"\n\nexport const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)\n'
    )
    (root / ".env").write_text(f"STRIPE_SECRET_KEY={ENV_VALUE}\n")
    _commit(root)


EXTRAS = {
    "next-supabase-bad": _bad_extras,
    "next-supabase-good": _good_extras,
}


def build(name: str, tmp_path: Path) -> Path:
    root = tmp_path / name
    shutil.copytree(FIXTURES / name, root)
    EXTRAS[name](root)
    return root
```

- [ ] **Step 2: Run the fixture test to verify it fails**

Run: `uv run pytest tests/test_fixtures.py -q`
Expected: FAIL in 2 tests: `unexpected findings` for the bad fixture (headers, version disclosure, the users route lookup and the missing lock file, which the Milestone 1 expected list does not name) and `KeyError: ('ABUSE-PAID-UNAUTH', 6)` in the severity test

- [ ] **Step 3: Add the defects, the fixes and the expectations**

`tests/fixtures/next-supabase-bad/app/api/signup/route.ts`:

```ts
import { NextResponse } from "next/server"
import { cookies } from "next/headers"
import { prisma } from "@/lib/db"

export async function POST(req: Request) {
  const body = await req.json()
  try {
    const user = await prisma.user.create({ data: body })
    cookies().set("session", String(user.id), { path: "/" })
  } catch (err) {
    console.error("signup failed", body)
    return NextResponse.json({ error: "failed" }, { status: 500 })
  }
  return NextResponse.json({ ok: true })
}
```

`tests/fixtures/next-supabase-bad/app/api/invoices/[id]/route.ts`:

```ts
import { NextResponse } from "next/server"
import { prisma } from "@/lib/db"
import { auth } from "@/lib/auth"

export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await auth()
  const invoice = await prisma.invoice.findUnique({ where: { id: Number(params.id) } })
  return withCors(req, NextResponse.json({ amount: invoice?.amount }))
}

function withCors(req: Request, res: Response) {
  res.headers.set("Access-Control-Allow-Origin", req.headers.get("origin") ?? "")
  res.headers.set("Access-Control-Allow-Credentials", "true")
  return res
}
```

`tests/fixtures/next-supabase-bad/app/api/generate/route.ts`:

```ts
import OpenAI from "openai"
import { NextResponse } from "next/server"

const openai = new OpenAI()

export async function POST(req: Request) {
  const { prompt } = await req.json()
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: prompt }],
  })
  return NextResponse.json({ text: completion.choices[0].message.content })
}
```

`tests/fixtures/next-supabase-bad/components/Bio.tsx`:

```tsx
export function Bio({ bio }: { bio: string }) {
  return <section dangerouslySetInnerHTML={{ __html: bio }} />
}
```

`tests/fixtures/next-supabase-bad/package.json`:

```json
{
  "name": "next-supabase-bad",
  "private": true,
  "dependencies": {
    "next": "14.2.0",
    "@supabase/supabase-js": "2.45.0",
    "@prisma/client": "5.18.0",
    "@sentry/nextjs": "8.20.0",
    "stripe": "16.0.0",
    "openai": "4.56.0"
  }
}
```

`tests/fixtures/next-supabase-bad/expected.yaml`:

```yaml
# Every finding the scan must report, and nothing else.
findings:
  - {rule: ABUSE-CORS-REFLECT, file: "app/api/invoices/[id]/route.ts", line: 12, tag: CONFIRMED}
  - {rule: ABUSE-FORM-NO-CHALLENGE, file: app/api/signup/route.ts, line: 5, tag: INFERRED}
  - {rule: ABUSE-NO-KILL-SWITCH, file: app/api/generate/route.ts, line: 6, tag: INFERRED}
  - {rule: ABUSE-PAID-UNAUTH, file: app/api/generate/route.ts, line: 6, tag: CONFIRMED}
  - {rule: ABUSE-PAID-UNLIMITED, file: app/api/generate/route.ts, line: 6, tag: INFERRED}
  - {rule: BASE-COOKIE-HTTPONLY, file: app/api/signup/route.ts, line: 9, tag: CONFIRMED}
  - {rule: BASE-COOKIE-SAMESITE, file: app/api/signup/route.ts, line: 9, tag: CONFIRMED}
  - {rule: BASE-COOKIE-SECURE, file: app/api/signup/route.ts, line: 9, tag: CONFIRMED}
  - {rule: BASE-HEADER-MISSING-CSP, file: next.config.js, line: 1, tag: UNVERIFIED}
  - {rule: BASE-HEADER-MISSING-FRAME, file: next.config.js, line: 1, tag: UNVERIFIED}
  - {rule: BASE-HEADER-MISSING-HSTS, file: next.config.js, line: 1, tag: UNVERIFIED}
  - {rule: BASE-HEADER-MISSING-PERMISSIONS, file: next.config.js, line: 1, tag: UNVERIFIED}
  - {rule: BASE-HEADER-MISSING-REFERRER, file: next.config.js, line: 1, tag: UNVERIFIED}
  - {rule: BASE-HEADER-MISSING-XCTO, file: next.config.js, line: 1, tag: UNVERIFIED}
  - {rule: BASE-VERSION-DISCLOSURE, file: next.config.js, line: 1, tag: INFERRED}
  - {rule: LEAK-BROAD-RESPONSE, file: "app/api/users/[id]/route.ts", line: 6, tag: INFERRED}
  - {rule: LEAK-ENV-IN-HISTORY, file: .env.production, line: 1, tag: CONFIRMED}
  - {rule: LEAK-ENV-TRACKED, file: .env, line: 1, tag: CONFIRMED}
  - {rule: LEAK-HARDCODED-KEY, file: lib/stripe.ts, line: 3, tag: CONFIRMED}
  - {rule: LEAK-KEY-IN-BUILD, file: .next/static/chunks/main.js, line: 1, tag: CONFIRMED}
  - {rule: LEAK-LOGGED-PII, file: app/api/signup/route.ts, line: 11, tag: INFERRED}
  - {rule: LEAK-PUBLIC-SECRET, file: .env.example, line: 3, tag: CONFIRMED}
  - {rule: LEAK-SENTRY-PII, file: sentry.client.config.ts, line: 5, tag: CONFIRMED}
  - {rule: LEAK-SOURCEMAP, file: .next/static/chunks/main.js.map, line: 1, tag: CONFIRMED}
  - {rule: LEAK-SOURCEMAP, file: next.config.js, line: 2, tag: CONFIRMED}
  - {rule: OWASP-A01-GUESSABLE-ID, file: "app/api/invoices/[id]/route.ts", line: 7, tag: CONFIRMED}
  - {rule: OWASP-A01-GUESSABLE-ID, file: "app/api/users/[id]/route.ts", line: 5, tag: CONFIRMED}
  - {rule: OWASP-A01-MASS-ASSIGNMENT, file: app/api/signup/route.ts, line: 8, tag: INFERRED}
  - {rule: OWASP-A01-UNSCOPED-QUERY, file: "app/api/invoices/[id]/route.ts", line: 7, tag: CONFIRMED}
  - {rule: OWASP-A01-UNSCOPED-QUERY, file: "app/api/users/[id]/route.ts", line: 5, tag: CONFIRMED}
  - {rule: OWASP-A03-XSS-SINK, file: components/Bio.tsx, line: 2, tag: INFERRED}
  - {rule: OWASP-A08-UNPINNED-DEPS, file: package.json, line: 1, tag: CONFIRMED}
  - {rule: RLS-AUTHENTICATED-NOT-OWNER, file: supabase/migrations/20240101000000_init.sql, line: 8, tag: CONFIRMED}
  - {rule: RLS-CLIENT-OWNER, file: supabase/migrations/20240101000000_init.sql, line: 4, tag: CONFIRMED}
  - {rule: RLS-DEFINER-FUNCTION, file: supabase/migrations/20240101000000_init.sql, line: 17, tag: CONFIRMED}
  - {rule: RLS-NO-POLICIES, file: supabase/migrations/20240101000000_init.sql, line: 13, tag: CONFIRMED}
  - {rule: RLS-POLICY-TRUE, file: supabase/migrations/20240101000000_init.sql, line: 7, tag: CONFIRMED}
  - {rule: RLS-PUBLIC-BUCKET, file: supabase/migrations/20240101000000_init.sql, line: 18, tag: CONFIRMED}
  - {rule: RLS-SELECT-ONLY, file: supabase/migrations/20240101000000_init.sql, line: 16, tag: CONFIRMED}
  - {rule: RLS-TABLE-OFF, file: supabase/migrations/20240101000000_init.sql, line: 10, tag: CONFIRMED}
  - {rule: RLS-TENANT-UNBOUND, file: supabase/migrations/20240101000000_init.sql, line: 16, tag: INFERRED}
  - {rule: RLS-VIEW-BYPASS, file: supabase/migrations/20240101000000_init.sql, line: 11, tag: CONFIRMED}
  - {rule: RLS-WEAK-WITH-CHECK, file: supabase/migrations/20240101000000_init.sql, line: 3, tag: CONFIRMED}
  - {rule: RLS-WRONG-ROLE, file: supabase/migrations/20240101000000_init.sql, line: 9, tag: CONFIRMED}
```

`tests/fixtures/next-supabase-good/app/api/signup/route.ts`:

```ts
import { NextResponse } from "next/server"
import { cookies } from "next/headers"
import { prisma } from "@/lib/db"
import { verifyTurnstile } from "@/lib/turnstile"

export async function POST(req: Request) {
  const body = await req.json()
  await verifyTurnstile(body.turnstileToken)
  try {
    const user = await prisma.user.create({ data: { email: body.email, name: body.name } })
    cookies().set("session", String(user.id), { path: "/", httpOnly: true, secure: true, sameSite: "lax" })
  } catch (err) {
    console.error("signup failed", { requestId: crypto.randomUUID() })
    return NextResponse.json({ error: "failed" }, { status: 500 })
  }
  return NextResponse.json({ ok: true })
}
```

`tests/fixtures/next-supabase-good/app/api/users/[id]/route.ts`:

```ts
import { NextResponse } from "next/server"
import { prisma } from "@/lib/db"
import { auth } from "@/lib/auth"

export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await auth()
  if (!session || String(session.user.id) !== params.id) {
    return NextResponse.json({ error: "not found" }, { status: 404 })
  }
  const user = await prisma.user.findUnique({
    where: { id: Number(session.user.id) },
    select: { id: true, name: true },
  })
  return NextResponse.json(user)
}
```

`tests/fixtures/next-supabase-good/app/api/invoices/[id]/route.ts`:

```ts
import { NextResponse } from "next/server"
import { prisma } from "@/lib/db"
import { auth } from "@/lib/auth"

const ALLOWED_ORIGINS = ["https://app.example.com"]

export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await auth()
  const invoice = await prisma.invoice.findFirst({
    where: { id: Number(params.id), userId: session.user.id },
    select: { amount: true },
  })
  return withCors(req, NextResponse.json({ amount: invoice?.amount }))
}

function withCors(req: Request, res: Response) {
  const origin = req.headers.get("origin")
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.headers.set("Access-Control-Allow-Origin", origin)
  }
  return res
}
```

`tests/fixtures/next-supabase-good/app/api/generate/route.ts`:

```ts
import OpenAI from "openai"
import { NextResponse } from "next/server"
import { auth } from "@/lib/auth"
import { ratelimit } from "@/lib/ratelimit"

const openai = new OpenAI()

export async function POST(req: Request) {
  if (process.env.GENERATE_ENABLED !== "true") {
    return NextResponse.json({ error: "disabled" }, { status: 503 })
  }
  const session = await auth()
  const { success } = await ratelimit.limit(String(session.user.id))
  if (!success) return NextResponse.json({ error: "slow down" }, { status: 429 })
  const { prompt } = await req.json()
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: prompt }],
  })
  return NextResponse.json({ text: completion.choices[0].message.content })
}
```

`tests/fixtures/next-supabase-good/components/Bio.tsx`:

```tsx
export function Bio({ bio }: { bio: string }) {
  return <section>{bio}</section>
}
```

`tests/fixtures/next-supabase-good/package.json`:

```json
{
  "name": "next-supabase-good",
  "private": true,
  "dependencies": {
    "next": "14.2.0",
    "@supabase/supabase-js": "2.45.0",
    "@prisma/client": "5.18.0",
    "@sentry/nextjs": "8.20.0",
    "stripe": "16.0.0",
    "openai": "4.56.0",
    "@upstash/ratelimit": "2.0.0"
  }
}
```

`tests/fixtures/next-supabase-good/package-lock.json`:

```json
{
  "name": "next-supabase-good",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {}
}
```

`tests/fixtures/next-supabase-good/next.config.js`:

```js
module.exports = {
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          { key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" },
          { key: "Content-Security-Policy", value: "default-src 'self'; frame-ancestors 'none'" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
        ],
      },
    ]
  },
}
```

`tests/fixtures/next-supabase-good/prisma/schema.prisma`:

```prisma
model User {
  id           Int       @id @default(autoincrement())
  email        String    @unique
  passwordHash String
  name         String?
  invoices     Invoice[]
}

model Invoice {
  id     Int    @id @default(autoincrement())
  userId Int
  amount Int
  user   User   @relation(fields: [userId], references: [id])
}
```

`tests/fixtures/next-supabase-good/expected.yaml`:

```yaml
# Rule ids that must not appear anywhere in this fixture's report.
must_not_report:
  - ABUSE-CORS-REFLECT
  - ABUSE-CORS-WILDCARD
  - ABUSE-ERROR-LEAK
  - ABUSE-FORM-NO-CHALLENGE
  - ABUSE-INMEMORY-LIMITER
  - ABUSE-LIMITER-NOT-APPLIED
  - ABUSE-LIMITER-PROXY-IP
  - ABUSE-NO-KILL-SWITCH
  - ABUSE-PAID-UNAUTH
  - ABUSE-PAID-UNLIMITED
  - ABUSE-UPLOAD-UNBOUNDED
  - BASE-COOKIE-HTTPONLY
  - BASE-COOKIE-SAMESITE
  - BASE-COOKIE-SECURE
  - BASE-DB-ADMIN-LOGIN
  - BASE-DB-NETWORK-OPEN
  - BASE-DEBUG-ON
  - BASE-HEADER-MISSING-CSP
  - BASE-HEADER-MISSING-FRAME
  - BASE-HEADER-MISSING-HSTS
  - BASE-HEADER-MISSING-PERMISSIONS
  - BASE-HEADER-MISSING-REFERRER
  - BASE-HEADER-MISSING-XCTO
  - BASE-HTTPS-NOT-ENFORCED
  - BASE-LITERAL-PASSWORD-HASH
  - BASE-SAMESITE-NONE-NO-CSRF
  - BASE-SEED-ON-START
  - BASE-SHORT-PASSWORD-MIN
  - BASE-VERSION-DISCLOSURE
  - BASE-WEAK-HASH
  - LEAK-BROAD-RESPONSE
  - LEAK-DEFAULT-CREDENTIAL
  - LEAK-ENV-IN-HISTORY
  - LEAK-ENV-TRACKED
  - LEAK-HARDCODED-KEY
  - LEAK-KEY-IN-BUILD
  - LEAK-LOGGED-PII
  - LEAK-PUBLIC-GATE-KEY
  - LEAK-PUBLIC-SECRET
  - LEAK-SENTRY-PII
  - LEAK-SOURCEMAP
  - OWASP-A01-EMAIL-OWNERSHIP
  - OWASP-A01-GUESSABLE-ID
  - OWASP-A01-MASS-ASSIGNMENT
  - OWASP-A01-PATH-TRAVERSAL
  - OWASP-A01-UNSCOPED-QUERY
  - OWASP-A03-HTML-EMAIL
  - OWASP-A03-RAW-SQL
  - OWASP-A03-XSS-SINK
  - OWASP-A05-XML-PARSER
  - OWASP-A08-UNPINNED-DEPS
  - OWASP-A08-UNPINNED-INSTALL
  - OWASP-A10-SSRF
  - RLS-AUTHENTICATED-NOT-OWNER
  - RLS-CLIENT-OWNER
  - RLS-DEFINER-FUNCTION
  - RLS-NO-POLICIES
  - RLS-POLICY-TRUE
  - RLS-PUBLIC-BUCKET
  - RLS-SELECT-ONLY
  - RLS-TABLE-OFF
  - RLS-TENANT-UNBOUND
  - RLS-VIEW-BYPASS
  - RLS-WEAK-WITH-CHECK
  - RLS-WRONG-ROLE
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest -q`
Expected: PASS (all tests)

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/next-supabase-bad tests/fixtures/next-supabase-good tests/fixture_builder.py tests/test_fixtures.py
git commit -m "Plant and fix the Milestone 2 defects in the Next.js fixtures and compare all reviews exactly"
```

---
### Task 50: django-bad fixture

The spec's Django fixture: `DEBUG = True`, MD5 first in `PASSWORD_HASHERS`, `get_object_or_404(Invoice, pk=pk)` without a user filter, `CORS_ALLOW_ALL_ORIGINS = True`, `SESSION_COOKIE_SECURE = False`, `requests.get(request.GET["url"])`, f-string SQL with a request value, `traceback.format_exc()` in a response, serializer `fields = "__all__"` and `send_default_pii=True`. Because the Django settings add neither `SecurityMiddleware` nor clickjacking middleware, the fixture also reports all six missing headers, and the integer primary key in the URL is a guessable ID.

**Files:**
- Create: `tests/fixtures/django-bad/requirements.txt`, `tests/fixtures/django-bad/manage.py`, `tests/fixtures/django-bad/shop/__init__.py` (empty), `tests/fixtures/django-bad/shop/settings.py`, `tests/fixtures/django-bad/shop/models.py`, `tests/fixtures/django-bad/shop/serializers.py`, `tests/fixtures/django-bad/shop/urls.py`, `tests/fixtures/django-bad/shop/views.py`, `tests/fixtures/django-bad/expected.yaml`
- Modify: `tests/fixture_builder.py`, `tests/test_fixtures.py`

**Interfaces:**
- Consumes: `EXTRAS`, `_commit`, `BAD` (Task 49)
- Produces: fixture `django-bad` (committed to a throwaway git repository by `build`)

- [ ] **Step 1: Register the fixture in the tests**

Modify `tests/test_fixtures.py`, replace:

```python
BAD = ("next-supabase-bad",)
```

with:

```python
BAD = ("next-supabase-bad", "django-bad")
```

Modify `tests/test_fixtures.py`, replace:

```python
@pytest.mark.parametrize("name", sorted(GOOD))
```

with:

```python
def test_django_bad_severities(tmp_path):
    django = {f.rule_id: f.severity.value for f in review(build("django-bad", tmp_path)).findings}
    assert django["BASE-WEAK-HASH"] == "critical"
    assert django["BASE-DEBUG-ON"] == "high"
    assert django["OWASP-A03-RAW-SQL"] == "high"


@pytest.mark.parametrize("name", sorted(GOOD))
```

Modify `tests/fixture_builder.py`, replace:

```python
    "next-supabase-good": _good_extras,
}
```

with:

```python
    "next-supabase-good": _good_extras,
    "django-bad": _commit,
}
```

- [ ] **Step 2: Run the fixture test to verify it fails**

Run: `uv run pytest tests/test_fixtures.py -q`
Expected: FAIL with `FileNotFoundError` for `tests/fixtures/django-bad`

- [ ] **Step 3: Write the fixture**

`tests/fixtures/django-bad/shop/__init__.py`: empty file.

`tests/fixtures/django-bad/requirements.txt`:

```text
Django==5.0.6
djangorestframework==3.15.1
django-cors-headers==4.4.0
requests==2.32.3
sentry-sdk==2.10.0
```

`tests/fixtures/django-bad/manage.py`:

```python
import os
import sys

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "shop.settings")
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
```

`tests/fixtures/django-bad/shop/settings.py`:

```python
import sentry_sdk

DEBUG = True
ALLOWED_HOSTS = ["*"]
INSTALLED_APPS = ["django.contrib.auth", "rest_framework", "corsheaders", "shop"]
MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
]
ROOT_URLCONF = "shop.urls"
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.MD5PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]
CORS_ALLOW_ALL_ORIGINS = True
SESSION_COOKIE_SECURE = False

sentry_sdk.init(
    dsn="https://public@sentry.example.invalid/1",
    send_default_pii=True,
)
```

`tests/fixtures/django-bad/shop/models.py`:

```python
from django.conf import settings
from django.db import models


class Invoice(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    user_id = models.IntegerField()
    number = models.CharField(max_length=32)
    total = models.IntegerField()
```

`tests/fixtures/django-bad/shop/serializers.py`:

```python
from rest_framework import serializers

from shop.models import Invoice


class InvoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invoice
        fields = "__all__"
```

`tests/fixtures/django-bad/shop/urls.py`:

```python
from django.urls import path

from shop import views

urlpatterns = [
    path("invoices/<int:pk>/", views.invoice_detail),
    path("invoices/search/", views.invoice_search),
    path("preview/", views.link_preview),
    path("export/", views.export_invoices),
]
```

`tests/fixtures/django-bad/shop/views.py`:

```python
import traceback

import requests
from django.contrib.auth.decorators import login_required
from django.db import connection
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404

from shop.models import Invoice


@login_required
def invoice_detail(request, pk):
    invoice = get_object_or_404(Invoice, pk=pk)
    return JsonResponse({"number": invoice.number, "total": invoice.total})


@login_required
def invoice_search(request):
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT id FROM shop_invoice WHERE number = '{request.GET['number']}'")
        rows = cursor.fetchall()
    return JsonResponse({"ids": [row[0] for row in rows]})


@login_required
def link_preview(request):
    page = requests.get(request.GET["url"], timeout=5)
    return JsonResponse({"status": page.status_code})


@login_required
def export_invoices(request):
    try:
        data = [invoice.number for invoice in Invoice.objects.filter(user=request.user)]
    except Exception:
        return HttpResponse(traceback.format_exc(), status=500)
    return JsonResponse({"numbers": data})
```

`tests/fixtures/django-bad/expected.yaml`:

```yaml
# Every finding the scan must report, and nothing else.
findings:
  - {rule: ABUSE-CORS-WILDCARD, file: shop/settings.py, line: 15, tag: CONFIRMED}
  - {rule: ABUSE-ERROR-LEAK, file: shop/views.py, line: 37, tag: CONFIRMED}
  - {rule: BASE-COOKIE-SECURE, file: shop/settings.py, line: 16, tag: CONFIRMED}
  - {rule: BASE-DEBUG-ON, file: shop/settings.py, line: 3, tag: INFERRED}
  - {rule: BASE-HEADER-MISSING-CSP, file: shop/settings.py, line: 1, tag: UNVERIFIED}
  - {rule: BASE-HEADER-MISSING-FRAME, file: shop/settings.py, line: 1, tag: UNVERIFIED}
  - {rule: BASE-HEADER-MISSING-HSTS, file: shop/settings.py, line: 1, tag: UNVERIFIED}
  - {rule: BASE-HEADER-MISSING-PERMISSIONS, file: shop/settings.py, line: 1, tag: UNVERIFIED}
  - {rule: BASE-HEADER-MISSING-REFERRER, file: shop/settings.py, line: 1, tag: UNVERIFIED}
  - {rule: BASE-HEADER-MISSING-XCTO, file: shop/settings.py, line: 1, tag: UNVERIFIED}
  - {rule: BASE-WEAK-HASH, file: shop/settings.py, line: 12, tag: CONFIRMED}
  - {rule: LEAK-BROAD-RESPONSE, file: shop/serializers.py, line: 9, tag: INFERRED}
  - {rule: LEAK-SENTRY-PII, file: shop/settings.py, line: 20, tag: CONFIRMED}
  - {rule: OWASP-A01-GUESSABLE-ID, file: shop/views.py, line: 14, tag: CONFIRMED}
  - {rule: OWASP-A01-UNSCOPED-QUERY, file: shop/views.py, line: 14, tag: CONFIRMED}
  - {rule: OWASP-A03-RAW-SQL, file: shop/views.py, line: 21, tag: CONFIRMED}
  - {rule: OWASP-A10-SSRF, file: shop/views.py, line: 28, tag: INFERRED}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest -q`
Expected: PASS (all tests, including the new fixture case and `test_django_bad_severities`)

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/django-bad tests/fixture_builder.py tests/test_fixtures.py
git commit -m "Add the django-bad fixture"
```

---
### Task 51: fastapi-bad and fastapi-good fixtures

`fastapi-bad` is a small FastAPI API with a React static site and Terraform, holding one instance of every pattern the comparison report found on a real FastAPI and Azure repository: a seed script that hashes a committed password and runs on every start, a limiter that falls back to memory on a four-worker deploy with default limits never wired and keyed on the proxy address, a paid LLM route with no limit or kill switch, an attachment download with no owner check, an upload written to the caller's file name and read before its size is checked, exception text in the health response, a public registration form with no challenge, a six-character password minimum, an email-matched client lookup, unescaped HTML email, spreadsheet parsing without defusedxml, unpinned requirements, runtime and CI installs without versions, a debug default of `True`, missing headers on both the API and the static site, a maintenance bypass key shipped to the browser, a compose file with a default password, source maps, and Terraform with an open database firewall, an admin connection string, no `https_only` and `SameSite=None` with no CSRF defence anywhere.

`fastapi-good` is the same application with each defect fixed: response models, `get_current_user` scoping, a Redis-backed slowapi limiter with `SlowAPIMiddleware` and trusted forwarded addresses, a CORS allowlist, bcrypt hashing with the seed password read from the environment, security header middleware, generated upload names with a size check before reading, Turnstile on public forms, a chat kill switch, pinned requirements with defusedxml, and Terraform with a narrow firewall rule, an app login and `https_only`.

The password, bypass key and compose default are written by the fixture builder at test time, so no committed fixture file holds them and the safety tests in Task 52 can assert they never reach any output. The builder also creates `api/app/db/`, because git does not keep empty folders.

**Files:**
- Create: every file under `tests/fixtures/fastapi-bad/` and `tests/fixtures/fastapi-good/` in Step 3, including the empty `__init__.py` files named there
- Modify: `tests/fixture_builder.py`, `tests/test_fixtures.py`

**Interfaces:**
- Consumes: `EXTRAS`, `_commit`, `BAD`, `GOOD` (Task 49)
- Produces: fixtures `fastapi-bad` and `fastapi-good`; `tests.fixture_builder.SEED_PASSWORD`, `BYPASS_KEY`, `COMPOSE_PASSWORD`, all three added to `SECRETS`

- [ ] **Step 1: Register the fixtures in the tests and the builder**

Modify `tests/test_fixtures.py`, replace:

```python
BAD = ("next-supabase-bad", "django-bad")
```

with:

```python
BAD = ("next-supabase-bad", "django-bad", "fastapi-bad")
```

Modify `tests/test_fixtures.py`, replace:

```python
    "next-supabase-good": {"leaks", "rls", "baseline", "owasp", "abuse"},
}
```

with:

```python
    "next-supabase-good": {"leaks", "rls", "baseline", "owasp", "abuse"},
    "fastapi-good": {"leaks", "baseline", "owasp", "abuse"},
}
```

Modify `tests/test_fixtures.py`, replace:

```python
@pytest.mark.parametrize("name", sorted(GOOD))
```

with:

```python
def test_fastapi_bad_severities(tmp_path):
    fastapi = {f.rule_id: f.severity.value for f in review(build("fastapi-bad", tmp_path)).findings}
    assert fastapi["BASE-LITERAL-PASSWORD-HASH"] == "critical"
    assert fastapi["BASE-SEED-ON-START"] == "critical"
    assert fastapi["OWASP-A01-UNSCOPED-QUERY"] == "high"


@pytest.mark.parametrize("name", sorted(GOOD))
```

Modify `tests/fixture_builder.py`, replace:

```python
SECRETS = (LIVE_STRIPE, ENV_VALUE)
```

with:

```python
SEED_PASSWORD = "Demo" + "-Admin-" + "2031!"
BYPASS_KEY = "maint" + "enance-bypass-" + "7731"
COMPOSE_PASSWORD = "compose" + "-local-" + "4412"
SECRETS = (LIVE_STRIPE, ENV_VALUE, SEED_PASSWORD, BYPASS_KEY, COMPOSE_PASSWORD)
```

Modify `tests/fixture_builder.py`, replace:

```python
EXTRAS = {
    "next-supabase-bad": _bad_extras,
    "next-supabase-good": _good_extras,
```

with:

```python
def _fastapi_bad_extras(root: Path) -> None:
    (root / "api/app/db").mkdir(parents=True, exist_ok=True)
    (root / "api/app/db/seed.py").write_text(
        "from app.core.security import get_password_hash\n"
        "from app.models import User\n\n"
        f'ADMIN_PASSWORD = "{SEED_PASSWORD}"\n\n\n'
        "async def seed(db):\n"
        '    db.add(User(email="admin@example.invalid", password_hash=get_password_hash(ADMIN_PASSWORD)))\n'
    )
    (root / "README.md").write_text(
        f"# Demo\n\nSign in as admin@example.invalid with {SEED_PASSWORD}\n"
    )
    (root / "docker-compose.yml").write_text(
        "services:\n  db:\n    image: postgres:16\n    environment:\n"
        f"      POSTGRES_PASSWORD: ${{DB_PASSWORD:-{COMPOSE_PASSWORD}}}\n"
    )
    workflow = root / ".github/workflows/deploy.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "on: push\nenv:\n"
        f"  VITE_MAINTENANCE_BYPASS_KEY: '{BYPASS_KEY}'\n"
        "jobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: npx @azure/static-web-apps-cli deploy web/dist\n"
    )
    _commit(root)


def _fastapi_good_extras(root: Path) -> None:
    (root / ".env").write_text(f"SEED_ADMIN_PASSWORD={ENV_VALUE}\n")
    _commit(root)


EXTRAS = {
    "next-supabase-bad": _bad_extras,
    "next-supabase-good": _good_extras,
    "fastapi-bad": _fastapi_bad_extras,
    "fastapi-good": _fastapi_good_extras,
```

- [ ] **Step 2: Run the fixture test to verify it fails**

Run: `uv run pytest tests/test_fixtures.py -q`
Expected: FAIL with `FileNotFoundError` for `tests/fixtures/fastapi-bad` and `tests/fixtures/fastapi-good`

- [ ] **Step 3: Write the fixtures**

`tests/fixtures/fastapi-bad/api/app/__init__.py`: empty file.

`tests/fixtures/fastapi-bad/api/app/routes/__init__.py`: empty file.

`tests/fixtures/fastapi-bad/api/app/services/__init__.py`: empty file.

`tests/fixtures/fastapi-bad/api/app/config.py`:

```python
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    debug: bool = True
    redis_url: str | None = None
    upload_dir: str = "data/uploads"
    anthropic_api_key: str = ""


settings = Settings()
```

`tests/fixtures/fastapi-bad/api/app/core/deps.py`:

```python
from typing import Annotated

from fastapi import Depends

from app.core.security import get_current_user

CurrentUser = Annotated[dict, Depends(get_current_user)]
```

`tests/fixtures/fastapi-bad/api/app/core/rate_limit.py`:

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import settings


def get_limiter() -> Limiter:
    if settings.redis_url:
        storage_uri = settings.redis_url
    else:
        storage_uri = "memory://"
    return Limiter(
        key_func=get_remote_address,
        storage_uri=storage_uri,
        default_limits=["100/minute"],
    )


limiter = get_limiter()
```

`tests/fixtures/fastapi-bad/api/app/main.py`:

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.core.rate_limit import limiter
from app.routes import auth, chat, files

app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.example.com"],
    allow_credentials=True,
)
app.include_router(auth.router)
app.include_router(chat.router)
app.include_router(files.router)


@app.get("/health")
async def health():
    status = "ok"
    try:
        await ping_database()
    except Exception as e:
        status = f"error: {type(e).__name__}: {e}"
    return {"database": status}
```

`tests/fixtures/fastapi-bad/api/app/models.py`:

```python
from sqlalchemy import Column, String

from app.db.base import Base


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True)
    email = Column(String, unique=True)
    password_hash = Column(String)


class Client(Base):
    __tablename__ = "clients"
    id = Column(String, primary_key=True)
    email = Column(String)
    manager_id = Column(String)


class Attachment(Base):
    __tablename__ = "attachments"
    id = Column(String, primary_key=True)
    uploaded_by_id = Column(String)
    path = Column(String)
```

`tests/fixtures/fastapi-bad/api/app/routes/auth.py`:

```python
import logging

from fastapi import APIRouter, HTTPException, Request

from app.core.rate_limit import limiter

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth")


@router.post("/register")
@limiter.limit("3/hour")
async def register(request: Request, data: dict):
    return {"ok": True}


@router.post("/login")
@limiter.limit("5/minute")
async def login(request: Request, data: dict):
    if not await check_credentials(data):
        logger.warning("failed login")
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"ok": True}
```

`tests/fixtures/fastapi-bad/api/app/routes/chat.py`:

```python
from fastapi import APIRouter

from app.core.deps import CurrentUser
from app.services.assistant import ask_assistant

router = APIRouter(prefix="/chat")


@router.post("")
async def chat(current_user: CurrentUser, body: dict):
    return {"answer": await ask_assistant(body["messages"])}
```

`tests/fixtures/fastapi-bad/api/app/routes/files.py`:

```python
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile
from sqlalchemy import select

from app.config import settings
from app.core.deps import CurrentUser
from app.db.session import db
from app.models import Attachment

router = APIRouter(prefix="/files")
MAX_BYTES = 10 * 1024 * 1024


@router.post("")
async def upload(current_user: CurrentUser, file: UploadFile = File(...)):
    content = await file.read()
    if len(content) > MAX_BYTES:
        raise HTTPException(status_code=413, detail="Too large")
    target = Path(settings.upload_dir) / file.filename
    target.write_bytes(content)
    return {"stored": True}


@router.get("/{attachment_id}")
async def download(attachment_id: str, current_user: CurrentUser):
    result = await db.execute(select(Attachment).where(Attachment.id == attachment_id))
    return result.scalar_one_or_none()


@router.post("/import")
async def import_rows(current_user: CurrentUser, file: UploadFile = File(...)):
    import openpyxl

    workbook = openpyxl.load_workbook(file.file, read_only=True)
    return {"sheets": workbook.sheetnames}
```

`tests/fixtures/fastapi-bad/api/app/schemas.py`:

```python
from pydantic import BaseModel, field_validator


class AdminCreateUser(BaseModel):
    email: str
    password: str

    @field_validator("password")
    @classmethod
    def check_password(cls, value: str) -> str:
        if len(value) < 6:
            raise ValueError("Password must be at least 6 characters")
        return value
```

`tests/fixtures/fastapi-bad/api/app/services/assistant.py`:

```python
import anthropic

from app.config import settings

client = anthropic.Anthropic(api_key=settings.anthropic_api_key)


async def ask_assistant(messages: list[dict]) -> str:
    reply = client.messages.create(model="example-chat-model", max_tokens=1024, messages=messages)
    return reply.content[0].text
```

`tests/fixtures/fastapi-bad/api/app/services/email_service.py`:

```python
def welcome_email(first_name: str, link: str) -> str:
    return f"<h2>Welcome, {first_name}!</h2><p><a href='{link}'>Verify your email</a></p>"
```

`tests/fixtures/fastapi-bad/api/app/services/portal.py`:

```python
from sqlalchemy import func, select

from app.models import Client


async def client_for(db, user):
    result = await db.execute(select(Client).where(func.lower(Client.email) == user.email.lower()))
    return result.scalar_one_or_none()
```

`tests/fixtures/fastapi-bad/api/requirements.txt`:

```text
fastapi>=0.110
uvicorn>=0.29
gunicorn>=22.0
sqlalchemy>=2.0
slowapi>=0.1.9
anthropic>=0.30
passlib[bcrypt]>=1.7
openpyxl==3.1.2
```

`tests/fixtures/fastapi-bad/api/startup.sh`:

```bash
#!/bin/bash
pip install --quiet pysqlite3-binary
python -m app.db.seed
gunicorn app.main:app --worker-class uvicorn.workers.UvicornWorker --workers 4
```

`tests/fixtures/fastapi-bad/expected.yaml`:

```yaml
# Every finding the scan must report, and nothing else.
findings:
  - {rule: ABUSE-ERROR-LEAK, file: api/app/main.py, line: 29, tag: CONFIRMED}
  - {rule: ABUSE-FORM-NO-CHALLENGE, file: api/app/routes/auth.py, line: 13, tag: INFERRED}
  - {rule: ABUSE-INMEMORY-LIMITER, file: api/app/core/rate_limit.py, line: 12, tag: INFERRED}
  - {rule: ABUSE-LIMITER-NOT-APPLIED, file: api/app/core/rate_limit.py, line: 15, tag: CONFIRMED}
  - {rule: ABUSE-LIMITER-PROXY-IP, file: api/app/core/rate_limit.py, line: 13, tag: INFERRED}
  - {rule: ABUSE-NO-KILL-SWITCH, file: api/app/routes/chat.py, line: 10, tag: INFERRED}
  - {rule: ABUSE-PAID-UNLIMITED, file: api/app/routes/chat.py, line: 10, tag: INFERRED}
  - {rule: ABUSE-UPLOAD-UNBOUNDED, file: api/app/routes/files.py, line: 17, tag: CONFIRMED}
  - {rule: BASE-DB-ADMIN-LOGIN, file: infra/main.tf, line: 9, tag: INFERRED}
  - {rule: BASE-DB-NETWORK-OPEN, file: infra/main.tf, line: 1, tag: CONFIRMED}
  - {rule: BASE-DEBUG-ON, file: api/app/config.py, line: 5, tag: INFERRED}
  - {rule: BASE-HEADER-MISSING-CSP, file: api/app/main.py, line: 9, tag: UNVERIFIED}
  - {rule: BASE-HEADER-MISSING-FRAME, file: api/app/main.py, line: 9, tag: UNVERIFIED}
  - {rule: BASE-HEADER-MISSING-HSTS, file: api/app/main.py, line: 9, tag: UNVERIFIED}
  - {rule: BASE-HEADER-MISSING-PERMISSIONS, file: api/app/main.py, line: 9, tag: UNVERIFIED}
  - {rule: BASE-HEADER-MISSING-REFERRER, file: api/app/main.py, line: 9, tag: UNVERIFIED}
  - {rule: BASE-HEADER-MISSING-XCTO, file: api/app/main.py, line: 9, tag: UNVERIFIED}
  - {rule: BASE-HTTPS-NOT-ENFORCED, file: infra/main.tf, line: 12, tag: CONFIRMED}
  - {rule: BASE-LITERAL-PASSWORD-HASH, file: api/app/db/seed.py, line: 8, tag: CONFIRMED}
  - {rule: BASE-SAMESITE-NONE-NO-CSRF, file: infra/main.tf, line: 15, tag: INFERRED}
  - {rule: BASE-SEED-ON-START, file: api/startup.sh, line: 3, tag: INFERRED}
  - {rule: BASE-SHORT-PASSWORD-MIN, file: api/app/schemas.py, line: 11, tag: CONFIRMED}
  - {rule: LEAK-DEFAULT-CREDENTIAL, file: docker-compose.yml, line: 5, tag: CONFIRMED}
  - {rule: LEAK-PUBLIC-GATE-KEY, file: .github/workflows/deploy.yml, line: 3, tag: CONFIRMED}
  - {rule: LEAK-SOURCEMAP, file: web/vite.config.ts, line: 5, tag: CONFIRMED}
  - {rule: OWASP-A01-EMAIL-OWNERSHIP, file: api/app/services/portal.py, line: 7, tag: INFERRED}
  - {rule: OWASP-A01-PATH-TRAVERSAL, file: api/app/routes/files.py, line: 16, tag: CONFIRMED}
  - {rule: OWASP-A01-UNSCOPED-QUERY, file: api/app/routes/files.py, line: 27, tag: CONFIRMED}
  - {rule: OWASP-A03-HTML-EMAIL, file: api/app/services/email_service.py, line: 2, tag: INFERRED}
  - {rule: OWASP-A05-XML-PARSER, file: api/app/routes/files.py, line: 35, tag: INFERRED}
  - {rule: OWASP-A08-UNPINNED-DEPS, file: api/requirements.txt, line: 1, tag: CONFIRMED}
  - {rule: OWASP-A08-UNPINNED-INSTALL, file: .github/workflows/deploy.yml, line: 8, tag: CONFIRMED}
  - {rule: OWASP-A08-UNPINNED-INSTALL, file: api/startup.sh, line: 2, tag: CONFIRMED}
```

`tests/fixtures/fastapi-bad/infra/main.tf`:

```hcl
resource "azurerm_postgresql_flexible_server_firewall_rule" "azure" {
  name             = "AllowAzureServices"
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

resource "azurerm_key_vault_secret" "database_url" {
  name  = "database-url"
  value = "postgresql://${var.db_admin_username}:${var.db_admin_password}@${azurerm_postgresql_flexible_server.main.fqdn}/app"
}

resource "azurerm_linux_web_app" "api" {
  name = "api"
  app_settings = {
    COOKIE_SAMESITE = "none"
  }
}
```

`tests/fixtures/fastapi-bad/web/package-lock.json`:

```json
{
  "name": "fastapi-bad-web",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {}
}
```

`tests/fixtures/fastapi-bad/web/package.json`:

```json
{
  "name": "fastapi-bad-web",
  "private": true,
  "dependencies": {
    "react": "18.3.1",
    "vite": "5.4.0"
  }
}
```

`tests/fixtures/fastapi-bad/web/src/main.tsx`:

```tsx
export const canBypass = (key: string) => key === import.meta.env.VITE_MAINTENANCE_BYPASS_KEY
```

`tests/fixtures/fastapi-bad/web/staticwebapp.config.json`:

```json
{
  "navigationFallback": { "rewrite": "/index.html" },
  "globalHeaders": {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()"
  }
}
```

`tests/fixtures/fastapi-bad/web/vite.config.ts`:

```ts
import { defineConfig } from "vite"

export default defineConfig({
  build: {
    sourcemap: true,
  },
})
```

`tests/fixtures/fastapi-good/api/app/__init__.py`: empty file.

`tests/fixtures/fastapi-good/api/app/routes/__init__.py`: empty file.

`tests/fixtures/fastapi-good/api/app/services/__init__.py`: empty file.

`tests/fixtures/fastapi-good/.github/workflows/deploy.yml`:

```yaml
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: npx @azure/static-web-apps-cli@1.1.10 deploy web/dist
```

`tests/fixtures/fastapi-good/.gitignore`:

```text
.env
```

`tests/fixtures/fastapi-good/api/app/config.py`:

```python
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    debug: bool = False
    redis_url: str
    upload_dir: str = "data/uploads"
    anthropic_api_key: str = ""
    chat_enabled: bool = False


settings = Settings()
```

`tests/fixtures/fastapi-good/api/app/core/deps.py`:

```python
from typing import Annotated

from fastapi import Depends

from app.core.security import get_current_user

CurrentUser = Annotated[dict, Depends(get_current_user)]
```

`tests/fixtures/fastapi-good/api/app/core/rate_limit.py`:

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import settings

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=settings.redis_url,
    default_limits=["600/10minutes"],
)
```

`tests/fixtures/fastapi-good/api/app/core/security.py`:

```python
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)
```

`tests/fixtures/fastapi-good/api/app/db/seed.py`:

```python
import os

from app.core.security import get_password_hash
from app.models import User


async def seed(db):
    password = os.environ["SEED_ADMIN_PASSWORD"]
    db.add(User(email="admin@example.invalid", password_hash=get_password_hash(password)))
```

`tests/fixtures/fastapi-good/api/app/main.py`:

```python
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.core.rate_limit import limiter
from app.routes import auth, chat, files

app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.example.com"],
    allow_credentials=True,
)
app.include_router(auth.router)
app.include_router(chat.router)
app.include_router(files.router)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


@app.get("/health")
async def health():
    status = "ok"
    try:
        await ping_database()
    except Exception:
        logger.exception("database ping failed")
        status = "degraded"
    return {"database": status}
```

`tests/fixtures/fastapi-good/api/app/models.py`:

```python
from sqlalchemy import Column, String

from app.db.base import Base


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True)
    email = Column(String, unique=True)
    password_hash = Column(String)


class Client(Base):
    __tablename__ = "clients"
    id = Column(String, primary_key=True)
    user_id = Column(String)
    manager_id = Column(String)


class Attachment(Base):
    __tablename__ = "attachments"
    id = Column(String, primary_key=True)
    uploaded_by_id = Column(String)
    path = Column(String)
```

`tests/fixtures/fastapi-good/api/app/routes/auth.py`:

```python
import logging

from fastapi import APIRouter, HTTPException, Request

from app.core.rate_limit import limiter
from app.services.turnstile import verify_turnstile

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth")


@router.post("/register")
@limiter.limit("3/hour")
async def register(request: Request, data: dict):
    await verify_turnstile(data["turnstile_token"])
    return {"ok": True}


@router.post("/login")
@limiter.limit("5/minute")
async def login(request: Request, data: dict):
    await verify_turnstile(data["turnstile_token"])
    if not await check_credentials(data):
        logger.warning("failed login")
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"ok": True}
```

`tests/fixtures/fastapi-good/api/app/routes/chat.py`:

```python
from fastapi import APIRouter, HTTPException, Request

from app.config import settings
from app.core.deps import CurrentUser
from app.core.rate_limit import limiter
from app.services.assistant import ask_assistant

router = APIRouter(prefix="/chat")


@router.post("")
@limiter.limit("20/hour")
async def chat(request: Request, current_user: CurrentUser, body: dict):
    if not settings.chat_enabled:
        raise HTTPException(status_code=503, detail="Chat is switched off")
    return {"answer": await ask_assistant(body["messages"])}
```

`tests/fixtures/fastapi-good/api/app/routes/files.py`:

```python
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from sqlalchemy import select

from app.config import settings
from app.core.deps import CurrentUser
from app.db.session import db
from app.models import Attachment
from app.schemas import AttachmentOut

router = APIRouter(prefix="/files")
MAX_BYTES = 10 * 1024 * 1024


@router.post("")
async def upload(request: Request, current_user: CurrentUser, file: UploadFile = File(...)):
    if int(request.headers.get("content-length", "0")) > MAX_BYTES:
        raise HTTPException(status_code=413, detail="Too large")
    target = Path(settings.upload_dir) / f"{uuid4().hex}{Path(file.filename).suffix}"
    with target.open("wb") as out:
        while chunk := await file.read(64 * 1024):
            out.write(chunk)
    return {"stored": True}


@router.get("/{attachment_id}", response_model=AttachmentOut)
async def download(attachment_id: str, current_user: CurrentUser):
    result = await db.execute(
        select(Attachment).where(
            Attachment.id == attachment_id, Attachment.uploaded_by_id == current_user.id
        )
    )
    return result.scalar_one_or_none()


@router.post("/import")
async def import_rows(current_user: CurrentUser, file: UploadFile = File(...)):
    import openpyxl

    workbook = openpyxl.load_workbook(file.file, read_only=True)
    return {"sheets": workbook.sheetnames}
```

`tests/fixtures/fastapi-good/api/app/schemas.py`:

```python
from pydantic import BaseModel, Field


class AdminCreateUser(BaseModel):
    email: str
    password: str = Field(min_length=12)


class AttachmentOut(BaseModel):
    id: str
    path: str
```

`tests/fixtures/fastapi-good/api/app/services/assistant.py`:

```python
import anthropic

from app.config import settings

client = anthropic.Anthropic(api_key=settings.anthropic_api_key)


async def ask_assistant(messages: list[dict]) -> str:
    reply = client.messages.create(model="example-chat-model", max_tokens=1024, messages=messages)
    return reply.content[0].text
```

`tests/fixtures/fastapi-good/api/app/services/email_service.py`:

```python
import html


def welcome_email(first_name: str, link: str) -> str:
    return f"<h2>Welcome, {html.escape(first_name)}!</h2><p><a href='{html.escape(link)}'>Verify</a></p>"
```

`tests/fixtures/fastapi-good/api/app/services/portal.py`:

```python
from sqlalchemy import select

from app.models import Client


async def client_for(db, user):
    result = await db.execute(select(Client).where(Client.user_id == user.id))
    return result.scalar_one_or_none()
```

`tests/fixtures/fastapi-good/api/app/services/turnstile.py`:

```python
async def verify_turnstile(token: str) -> None:
    """Verify a Cloudflare Turnstile token with the siteverify endpoint."""
```

`tests/fixtures/fastapi-good/api/requirements.txt`:

```text
fastapi==0.111.0
uvicorn==0.30.1
gunicorn==22.0.0
sqlalchemy==2.0.31
slowapi==0.1.9
anthropic==0.30.1
passlib[bcrypt]==1.7.4
openpyxl==3.1.2
defusedxml==0.7.1
```

`tests/fixtures/fastapi-good/api/startup.sh`:

```bash
#!/bin/bash
alembic upgrade head
gunicorn app.main:app --worker-class uvicorn.workers.UvicornWorker --workers 4 --forwarded-allow-ips="10.0.0.0/8"
```

`tests/fixtures/fastapi-good/docker-compose.yml`:

```yaml
services:
  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: ${DB_PASSWORD:?set DB_PASSWORD}
```

`tests/fixtures/fastapi-good/expected.yaml`:

```yaml
# Rule ids that must not appear anywhere in this fixture's report.
must_not_report:
  - ABUSE-CORS-REFLECT
  - ABUSE-CORS-WILDCARD
  - ABUSE-ERROR-LEAK
  - ABUSE-FORM-NO-CHALLENGE
  - ABUSE-INMEMORY-LIMITER
  - ABUSE-LIMITER-NOT-APPLIED
  - ABUSE-LIMITER-PROXY-IP
  - ABUSE-NO-KILL-SWITCH
  - ABUSE-PAID-UNAUTH
  - ABUSE-PAID-UNLIMITED
  - ABUSE-UPLOAD-UNBOUNDED
  - BASE-COOKIE-HTTPONLY
  - BASE-COOKIE-SAMESITE
  - BASE-COOKIE-SECURE
  - BASE-DB-ADMIN-LOGIN
  - BASE-DB-NETWORK-OPEN
  - BASE-DEBUG-ON
  - BASE-HEADER-MISSING-CSP
  - BASE-HEADER-MISSING-FRAME
  - BASE-HEADER-MISSING-HSTS
  - BASE-HEADER-MISSING-PERMISSIONS
  - BASE-HEADER-MISSING-REFERRER
  - BASE-HEADER-MISSING-XCTO
  - BASE-HTTPS-NOT-ENFORCED
  - BASE-LITERAL-PASSWORD-HASH
  - BASE-SAMESITE-NONE-NO-CSRF
  - BASE-SEED-ON-START
  - BASE-SHORT-PASSWORD-MIN
  - BASE-VERSION-DISCLOSURE
  - BASE-WEAK-HASH
  - LEAK-BROAD-RESPONSE
  - LEAK-DEFAULT-CREDENTIAL
  - LEAK-ENV-IN-HISTORY
  - LEAK-ENV-TRACKED
  - LEAK-HARDCODED-KEY
  - LEAK-KEY-IN-BUILD
  - LEAK-LOGGED-PII
  - LEAK-PUBLIC-GATE-KEY
  - LEAK-PUBLIC-SECRET
  - LEAK-SENTRY-PII
  - LEAK-SOURCEMAP
  - OWASP-A01-EMAIL-OWNERSHIP
  - OWASP-A01-GUESSABLE-ID
  - OWASP-A01-MASS-ASSIGNMENT
  - OWASP-A01-PATH-TRAVERSAL
  - OWASP-A01-UNSCOPED-QUERY
  - OWASP-A03-HTML-EMAIL
  - OWASP-A03-RAW-SQL
  - OWASP-A03-XSS-SINK
  - OWASP-A05-XML-PARSER
  - OWASP-A08-UNPINNED-DEPS
  - OWASP-A08-UNPINNED-INSTALL
  - OWASP-A10-SSRF
  - RLS-AUTHENTICATED-NOT-OWNER
  - RLS-CLIENT-OWNER
  - RLS-DEFINER-FUNCTION
  - RLS-NO-POLICIES
  - RLS-POLICY-TRUE
  - RLS-PUBLIC-BUCKET
  - RLS-SELECT-ONLY
  - RLS-TABLE-OFF
  - RLS-TENANT-UNBOUND
  - RLS-VIEW-BYPASS
  - RLS-WEAK-WITH-CHECK
  - RLS-WRONG-ROLE
```

`tests/fixtures/fastapi-good/infra/main.tf`:

```hcl
resource "azurerm_postgresql_flexible_server_firewall_rule" "api_outbound" {
  name             = "ApiOutbound"
  start_ip_address = "203.0.113.10"
  end_ip_address   = "203.0.113.10"
}

resource "azurerm_key_vault_secret" "database_url" {
  name  = "database-url"
  value = "postgresql://${var.app_db_user}:${var.app_db_password}@${azurerm_postgresql_flexible_server.main.fqdn}/app"
}

resource "azurerm_linux_web_app" "api" {
  name       = "api"
  https_only = true
  app_settings = {
    COOKIE_SAMESITE = "lax"
  }
}
```

`tests/fixtures/fastapi-good/web/package-lock.json`:

```json
{
  "name": "fastapi-good-web",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {}
}
```

`tests/fixtures/fastapi-good/web/package.json`:

```json
{
  "name": "fastapi-good-web",
  "private": true,
  "dependencies": {
    "react": "18.3.1",
    "vite": "5.4.0"
  }
}
```

`tests/fixtures/fastapi-good/web/src/main.tsx`:

```tsx
export const apiBase = import.meta.env.VITE_API_URL
```

`tests/fixtures/fastapi-good/web/staticwebapp.config.json`:

```json
{
  "navigationFallback": { "rewrite": "/index.html" },
  "globalHeaders": {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()"
  }
}
```

`tests/fixtures/fastapi-good/web/vite.config.ts`:

```ts
import { defineConfig } from "vite"

export default defineConfig({
  build: {
    sourcemap: false,
  },
})
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest -q`
Expected: PASS (all tests, including the two new fixture cases and `test_fastapi_bad_severities`)

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/fastapi-bad tests/fixtures/fastapi-good tests/fixture_builder.py tests/test_fixtures.py
git commit -m "Add the fastapi-bad and fastapi-good fixtures"
```

---
### Task 52: Safety tests across every bad fixture, header config detection, local test report

**Files:**
- Create: `tests/test_safety_m2.py`, `tests/discovery/test_detect_headers.py`
- Modify: `src/dpr/data/stack.yaml` (static host configs count as header config), `tasks/todo.md` (Milestone 2 review section)

**Interfaces:**
- Consumes: every fixture (Tasks 49 to 51), `SECRETS` (Task 51), `render_sarif` (Task 32), `main` (Task 26), `BANNED_PHRASES` (Task 24)
- Produces: the safety guarantees of spec section 4 checked for all three bad fixtures and all three output formats; the detection table's "Security headers configured" row lists `staticwebapp.config.json` and `firebase.json` files that set security headers

The CI workflow from Milestone 1 needs no change: it runs `uv run pytest -m "not semgrep"`, which collects every test added in this milestone.

- [ ] **Step 1: Write the tests**

`tests/test_safety_m2.py`:

```python
import json
import socket

import pytest

from dpr import reviews, rules
from dpr.api import review
from dpr.cli import main
from dpr.model import Tag
from dpr.report.markdown import BANNED_PHRASES, render_markdown
from dpr.report.sarif import render_sarif
from tests.fixture_builder import SECRETS, build

BAD = ("next-supabase-bad", "django-bad", "fastapi-bad")


@pytest.mark.parametrize("name", BAD)
def test_no_secret_value_in_any_format(tmp_path, capsys, name):
    root = build(name, tmp_path)
    report = review(root)
    outputs = [render_markdown(report), render_sarif(report), repr(report.findings)]
    out_dir = tmp_path / "out"
    assert main(["scan", str(root), "--format", "md,json,sarif", "--out", str(out_dir)]) == 0
    outputs += [p.read_text() for p in out_dir.iterdir()]
    captured = capsys.readouterr()
    outputs += [captured.out, captured.err]
    for secret in SECRETS:
        for text in outputs:
            assert secret not in text
    sarif = json.loads(next(p for p in out_dir.iterdir() if p.suffix == ".sarif").read_text())
    assert len(sarif["runs"][0]["results"]) == len(report.findings)


@pytest.mark.parametrize("name", BAD)
def test_evidence_rules_and_wording_hold(tmp_path, name):
    report = review(build(name, tmp_path))
    for finding in report.findings:
        assert finding.tag is not Tag.UNKNOWN
        if finding.tag is Tag.CONFIRMED:
            assert finding.locations, finding.rule_id
        if finding.tag is Tag.INFERRED:
            assert finding.proof_needed, finding.rule_id
    text = render_markdown(report)
    assert not any(phrase in text.lower() for phrase in BANNED_PHRASES)
    assert chr(0x2014) not in text


@pytest.mark.parametrize("name", BAD)
def test_default_run_opens_no_network_connection(tmp_path, monkeypatch, name):
    root = build(name, tmp_path)

    def refuse(*args, **kwargs):
        raise AssertionError("network connection attempted")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    review(root, semgrep="off")


def test_every_milestone_2_rule_has_owasp_or_is_a_leak_or_rls_rule():
    reviews.available()
    for rule_id, spec in rules.SPECS.items():
        if spec.review in ("baseline", "owasp", "abuse"):
            assert spec.owasp, rule_id
```

`tests/discovery/test_detect_headers.py`:

```python
from dpr.discovery.detect import detect
from dpr.walk import RepoIndex
from tests.reviews.helpers import write


def test_static_host_header_configs_are_detected(tmp_path):
    write(
        tmp_path, "web/staticwebapp.config.json", '{"globalHeaders": {"X-Frame-Options": "DENY"}}'
    )
    write(tmp_path, "site/firebase.json", '{"hosting": {"headers": []}}')
    write(tmp_path, "web/src/main.ts", "export {}\n")
    assert detect(RepoIndex(tmp_path)).header_config == ["web/staticwebapp.config.json"]
```

- [ ] **Step 2: Run tests to verify the detection test fails**

Run: `uv run pytest tests/test_safety_m2.py tests/discovery/test_detect_headers.py -q`
Expected: FAIL in `test_static_host_header_configs_are_detected` only (`assert [] == ['web/staticwebapp.config.json']`); the safety tests already pass, because Tasks 34 to 48 never put a value into a snippet or detail

- [ ] **Step 3: Count static host configs as header config**

Modify `src/dpr/data/stack.yaml`, replace:

```yaml
  files: ["next.config.*", "middleware.[jt]s", nginx.conf, vercel.json, netlify.toml, _headers, settings.py]
```

with:

```yaml
  files: ["next.config.*", "middleware.[jt]s", nginx.conf, vercel.json, netlify.toml, _headers, settings.py, staticwebapp.config.json, firebase.json]
```

- [ ] **Step 4: Format, lint and run everything**

Run: `uv run ruff format && uv run ruff check && uv run ruff format --check`
Expected: `All checks passed!` and every file already formatted

Run: `uv run pytest -m "not semgrep" --cov=dpr --cov-report=term-missing`
Expected: every test passes (243 in the run that checked this plan); note the count and the coverage percentage

- [ ] **Step 5: Smoke run the CLI on the Milestone 2 fixtures**

Run:

```bash
uv run python -c "
import pathlib, tempfile
from tests.fixture_builder import build
root = build('fastapi-bad', pathlib.Path(tempfile.mkdtemp()))
print(root)
" > /tmp/dpr-fastapi-bad.txt
uv run dpr scan "$(cat /tmp/dpr-fastapi-bad.txt)" --format md,json,sarif --fail-on critical; echo "exit $?"
```

Expected: a summary starting `dpr: 33 findings (critical 2, high 6, medium 9, low 16)`, three `Wrote` lines, and `exit 1`. Open the written `REPORT-*.md` and read sections 4, 5 and 7 once end to end.

- [ ] **Step 6: Record the local test report**

Append to `tasks/todo.md`, filling in the real numbers from Steps 4 and 5:

```markdown
## Milestone 2 review

- Tests: <count> passed, 0 failed (`uv run pytest -m "not semgrep" --cov=dpr`)
- Coverage: <percent>% of `src/dpr`
- Lint and format: `ruff check` and `ruff format --check` clean
- CLI smoke run on fastapi-bad: 33 findings, exit code 1 with `--fail-on critical`, Markdown, JSON and SARIF written
- Not done in this milestone: inventory and auth reviews, Semgrep and audit adapters, snapshot test, smoke runs on real repositories (Milestone 3)
```

- [ ] **Step 7: Commit**

```bash
git add tests/test_safety_m2.py tests/discovery/test_detect_headers.py src/dpr/data/stack.yaml tasks/todo.md
git commit -m "Check output safety across every bad fixture and record the Milestone 2 test report"
```

Do not push. Do not merge into `develop`. Tell the owner the branch is ready and wait for the instruction to push and open a pull request.
