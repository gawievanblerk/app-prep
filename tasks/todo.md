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

- [ ] **Milestone 1: core, leaks, RLS** (this plan, Tasks 1 to 29)
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


def f(rule_id="R", sev="high", expl="high", tag="CONFIRMED", effort=10, file="a.ts", line=1,
      owasp=None, source="dpr", review="leaks"):
    return Finding(
        rule_id=rule_id, review=review, title=rule_id, tag=tag, severity=sev,
        exploitability=expl, effort_minutes=effort, locations=(Location(file, line),),
        detail="d", fix="x", proof_needed="p" if tag == "INFERRED" else None,
        owasp=owasp, source=source,
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


def rule(rule_id: str, *, review: str, severity: str, exploitability: str,
         owasp: str | None = None) -> Callable[[CheckFn], CheckFn]:
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


def make_finding(rule_id: str, *, tag: Tag | str, locations: Iterable, detail: str | None = None,
                 snippet: str | None = None, severity: str | None = None,
                 exploitability: str | None = None, fix: str | None = None,
                 proof_needed: str | None = None, attack: str | None = None,
                 blast: str | None = None, verify: str | None = None,
                 refs: Iterable[str] = (), **fmt: object) -> Finding:
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

SKIP_DIRS = frozenset({
    "node_modules", ".git", ".next", "dist", "build", "out", "vendor", ".venv", "venv",
    "__pycache__", ".turbo", "coverage", ".pytest_cache", ".mypy_cache",
    "data-protection-review",
})
BUILD_DIR_NAMES = frozenset({"dist", "build", "out"})
SOURCE_MAX_BYTES = 1_000_000
BUILD_MAX_BYTES = 10_000_000
JS_EXTS = frozenset({
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte",
})
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
        "<script setup lang=\"ts\">\nconst a = fetchIt()\n</script>\n"
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

FUNCTION_TYPES = frozenset({
    "function_declaration", "generator_function_declaration", "function_expression",
    "function", "arrow_function", "method_definition",
})
WRAPPERS = frozenset({
    "await_expression", "parenthesized_expression", "as_expression", "non_null_expression",
    "satisfies_expression", "type_assertion",
})
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


def calls(tree: JsTree, pattern: str | re.Pattern[str],
          within: Node | None = None) -> Iterator[Node]:
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

CODE = '''
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
'''


def tree():
    return ast.parse(CODE)


def test_dotted_and_calls():
    t = tree()
    names = [pyast.dotted(c.func) for c in pyast.calls(t, r".*")]
    assert names == [
        "models.IntegerField", "requests.get", "request.GET.get", "cookies().set", "cookies",
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


def calls(tree: ast.AST, pattern: str | re.Pattern[str],
          within: ast.AST | None = None) -> Iterator[ast.Call]:
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
        "/* block /* nested; */ still; */ select \"Mixed;Case\" from t;\n"
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
    assert split_top_level("a int, b numeric(10, 2), 'x,y'") == ["a int", "b numeric(10, 2)", "'x,y'"]
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
    assert (update.command, update.roles, update.roles_explicit) == ("update", ("authenticated",), True)
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
    problems = apply_dump(SchemaState(), " schemaname | tablename | rowsecurity\n public | x\n", "d")
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
    rf"(?:if\s+not\s+exists\s+)?({QNAME})\s*(.*)$", re.S)
ALTER_TABLE = re.compile(
    rf"^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?({QNAME})\s+(.*)$", re.S)
RLS_ACTION = re.compile(r"^(enable|disable|force|no\s+force)\s+row\s+level\s+security")
CREATE_POLICY = re.compile(rf"^create\s+policy\s+({IDENT})\s+on\s+({QNAME})\s*(.*)$", re.S)
ALTER_POLICY = re.compile(rf"^alter\s+policy\s+({IDENT})\s+on\s+({QNAME})\s*(.*)$", re.S)
DROP_POLICY = re.compile(rf"^drop\s+policy\s+(?:if\s+exists\s+)?({IDENT})\s+on\s+({QNAME})")
CREATE_VIEW = re.compile(
    rf"^create\s+(?:or\s+replace\s+)?(?:(?:temp|temporary)\s+)?(?:recursive\s+)?view\s+"
    rf"({QNAME})\s*(.*)$", re.S)
ALTER_VIEW = re.compile(rf"^alter\s+view\s+(?:if\s+exists\s+)?({QNAME})\s+set\s*(\(.*\))", re.S)
CREATE_FUNCTION = re.compile(rf"^create\s+(?:or\s+replace\s+)?function\s+({QNAME})\s*(.*)$", re.S)
INSERT_BUCKET = re.compile(
    r"^insert\s+into\s+storage\s*\.\s*buckets\s*\(([^)]*)\)\s*values\s*(.*)$", re.S)
DROP_OBJECT = re.compile(rf"^drop\s+(table|view|function)\s+(?:if\s+exists\s+)?({QNAME})")
CONSTRAINT_START = re.compile(
    r"^(constraint|primary\s+key|unique|foreign\s+key|check|exclude|like)\b")
TABLE_KEY_CONSTRAINT = re.compile(
    rf"^(?:constraint\s+{IDENT}\s+)?(?:primary\s+key|unique)\s*\(([^)]*)\)")
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
        re.search(r"\bgenerated\b.*\bidentity\b", rest))
    return Column(_strip_quotes(match.group(1)), col_type, unique, autoinc)


def _policy_clauses(rest: str) -> dict[str, object]:
    out: dict[str, object] = {"permissive": True, "command": "all", "roles": ("public",),
                              "roles_explicit": False, "using": None, "with_check": None}
    match = re.match(r"^as\s+(permissive|restrictive)\s*", rest)
    if match:
        out["permissive"] = match.group(1) == "permissive"
        rest = rest[match.end():]
    match = re.match(r"^for\s+(all|select|insert|update|delete)\s*", rest)
    if match:
        out["command"] = match.group(1)
        rest = rest[match.end():]
    match = re.match(r"^to\s+", rest)
    if match:
        starts = (find_top_level(rest, r"using\b"), find_top_level(rest, r"with\s+check\b"))
        ends = [i for i in starts if i != -1]
        end = min(ends) if ends else len(rest)
        roles = [_strip_quotes(r.strip()) for r in split_top_level(rest[match.end():end])]
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
        for handler in (self._create_table, self._alter_table, self._create_policy,
                        self._alter_policy, self._drop_policy, self._create_view,
                        self._alter_view, self._create_function, self._insert_bucket,
                        self._drop_object):
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
            row = dict(zip(columns, (v.strip().strip("'") for v in split_top_level(inner)),
                           strict=False))
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
            name=row["policyname"], table=key, command=row.get("cmd", "ALL").lower(),
            roles=roles or ("public",), roles_explicit=bool(roles) and roles != ("public",),
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
            fields.append(PrismaField(
                name=match.group(1), type=match.group(2), optional=bool(match.group(4)),
                is_list=bool(match.group(3)), attributes=attributes,
                column=column.group(1) if column else match.group(1), line=number,
            ))
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
    write(tmp_path, "prisma/schema.prisma", """
model User {
  id    Int    @id @default(autoincrement())
  email String @unique
  @@map("users")
}
""")
    write(tmp_path, "prisma/migrations/1_init/migration.sql",
          'create table "users" (id serial primary key, email text);')
    write(tmp_path, "supabase/migrations/1.sql", "create table public.documents (id uuid, user_id uuid);")
    write(tmp_path, "billing/models.py", """
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
""")
    write(tmp_path, "svc/db.py", """
from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

class Account(Base):
    __tablename__ = "accounts"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"))
""")
    write(tmp_path, "src/db/schema.ts", """
import { pgTable, serial, text, uuid } from "drizzle-orm/pg-core"

export const profiles = pgTable("profiles", {
  id: serial("id").primaryKey(),
  fullName: text("full_name").notNull(),
  email: text().unique(),
  orgId: uuid("org_id"),
})
""")
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
        ("id", True, True), ("email", True, False),
    ]
    invoice = models["Invoice"]
    assert invoice.field_names() == ["id", "amount", "number", "owner"]
    assert invoice.fields[0].autoincrement is True
    assert invoice.fields[2].unique is True
    assert models["Note"].field_names() == ["uid"]
    account = models["Account"]
    assert [(f.name, f.type, f.unique, f.autoincrement) for f in account.fields] == [
        ("id", "Integer", True, True), ("email", "String", True, False), ("org_id", "Mapped[int]", False, False),
    ]
    profiles = models["profiles"]
    assert [(f.name, f.type, f.unique, f.autoincrement) for f in profiles.fields] == [
        ("id", "serial", True, True), ("full_name", "text", False, False),
        ("email", "text", True, False), ("org_id", "uuid", False, False),
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
        fields.append(Field(stmt.targets[0].id, kind, Location(entry_rel, stmt.lineno), unique,
                            kind in DJANGO_AUTO))
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
                    pyast.constant(pyast.kwarg(value, "autoincrement")) is True)
                fields.append(Field(target.id, col_type, Location(entry.rel, stmt.lineno),
                                    unique, auto))
            models.append(DataModel(cls.name, table, "sqlalchemy",
                                    Location(entry.rel, cls.lineno), tuple(fields)))
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
                        word in chain for word in (".autoincrement(", "AsIdentity("))
                    fields.append(Field(column or key, col_type,
                                        Location(entry.rel, jsts.line(tree, value)), unique, auto))
                models.append(DataModel(table, table, "drizzle",
                                        Location(entry.rel, jsts.line(tree, call)), tuple(fields)))
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
    write(tmp_path, "app/api/users/[id]/route.ts",
          "export async function GET() {}\nexport const DELETE = async () => {}\n"
          "export function helper() {}\n")
    write(tmp_path, "app/(marketing)/api/signup/route.ts", "export async function POST(req) {}\n")
    write(tmp_path, "src/app/route.ts", "export function GET() {}\n")
    write(tmp_path, "pages/api/reset/index.js",
          "export default async function handler(req, res) {\n"
          "  if (req.method === 'POST') { return res.json({}) }\n}\n")
    write(tmp_path, "pages/api/ping.ts", "export default function ping(req, res) {}\n")
    write(tmp_path, "app/actions.ts",
          '"use server"\nexport async function createInvoice(data) {}\n'
          "export default async function signupAction() {}\n")
    write(tmp_path, "lib/not-actions.ts", "export async function nope() {}\n")
    write(tmp_path, "server.js",
          "const app = express()\n"
          "app.get('/health', (req, res) => res.send('ok'))\n"
          "function loginHandler(req, res) {}\n"
          "router.post('/login', loginHandler)\n"
          "axios.get('/x', cb)\n"
          "client.get('/y', (r) => r)\n"
          "app.all('/any', async (req, res) => {})\n")
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
    assert sorted((r.method, r.path) for r in routes) == [("ANY", "/api/ping"), ("POST", "/api/reset")]


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
    r"(?:app|router|server|fastify|routes|\w+Router|\w+router)\.(get|post|put|patch|delete|all)")
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
                    routes.append(Route(name, path, entry.rel, jsts.line(tree, fn), "next-app",
                                        handler=fn, tree=tree))
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
                routes.append(Route(method, path, entry.rel, jsts.line(tree, handler),
                                    "next-pages", handler=handler, tree=tree))
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
                routes.append(Route("ACTION", f"action:{name}", entry.rel, jsts.line(tree, fn),
                                    "next-action", handler=fn, tree=tree))
            default = exported.get("default")
            if default is not None and default.start_byte not in seen:
                routes.append(Route("ACTION", "action:default", entry.rel,
                                    jsts.line(tree, default), "next-action", handler=default,
                                    tree=tree))
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
                routes.append(Route("ANY" if method == "ALL" else method, path, entry.rel,
                                    jsts.line(tree, call), framework, handler=handler, tree=tree))
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
    write(tmp_path, "api/main.py",
          "from fastapi import APIRouter\nrouter = APIRouter()\n\n"
          "@router.get(\"/items/{item_id}\")\nasync def read_item(item_id: int):\n    return {}\n\n"
          "@router.api_route(\"/multi\", methods=[\"GET\", \"POST\"])\ndef multi():\n    pass\n")
    write(tmp_path, "web/app.py",
          "from flask import Flask\napp = Flask(__name__)\n\n"
          "@app.route(\"/contact\", methods=[\"GET\", \"POST\"])\ndef contact():\n    pass\n\n"
          "@app.route(\"/about\")\ndef about():\n    pass\n")
    write(tmp_path, "shop/urls.py",
          "from django.urls import path, include\nfrom . import views\n\n"
          "urlpatterns = [\n"
          "    path(\"invoices/<int:pk>/\", views.invoice_detail),\n"
          "    path(\"orders/\", views.OrderView.as_view()),\n"
          "    path(\"api/\", include(\"accounts.urls\")),\n"
          "    path(\"register/\", views.missing_view),\n"
          "]\n")
    write(tmp_path, "shop/views.py",
          "def invoice_detail(request, pk):\n    pass\n\n\nclass OrderView(View):\n    pass\n")
    write(tmp_path, "accounts/urls.py",
          "from rest_framework import routers\nfrom .views import AccountViewSet\n"
          "router = routers.DefaultRouter()\nrouter.register(r\"accounts\", AccountViewSet)\n")
    write(tmp_path, "accounts/views.py", "class AccountViewSet(ModelViewSet):\n    pass\n")
    write(tmp_path, "app/api/signup/route.ts", "export async function POST() {}\n")
    return RepoIndex(tmp_path)


def test_decorator_routes(tmp_path):
    got = sorted((r.method, r.path, r.file, r.line, r.framework) for r in decorator_routes(repo(tmp_path)))
    assert got == [
        ("GET", "/about", "web/app.py", 9, "flask"),
        ("GET", "/contact", "web/app.py", 5, "flask"),
        ("GET", "/items/{item_id}", "api/main.py", 5, "fastapi"),
        ("GET", "/multi", "api/main.py", 9, "fastapi"),
        ("POST", "/contact", "web/app.py", 5, "flask"),
        ("POST", "/multi", "api/main.py", 9, "fastapi"),
    ]


def test_django_routes_resolve_views(tmp_path):
    got = sorted((r.path, r.file, r.line, r.framework, type(r.handler).__name__)
                 for r in django_routes(repo(tmp_path)))
    assert got == [
        ("/accounts", "accounts/views.py", 1, "drf", "ClassDef"),
        ("/invoices/<int:pk>", "shop/views.py", 1, "django", "FunctionDef"),
        ("/orders", "shop/views.py", 5, "django", "ClassDef"),
        ("/register", "shop/urls.py", 8, "django", "NoneType"),
    ]


def test_extract_routes_sets_public_form_flag(tmp_path):
    routes = extract_routes(repo(tmp_path))
    public = sorted((r.method, r.path) for r in routes if r.is_public_form)
    assert public == [("ANY", "/register"), ("GET", "/contact"), ("POST", "/api/signup"), ("POST", "/contact")]
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
                    routes.append(Route(method, path, entry.rel, fn.lineno, framework,
                                        handler=fn, tree=tree))
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
            routes.append(Route("ANY", _url_path(route), rel or entry.rel,
                                handler.lineno if handler else call.lineno, "django",
                                handler=handler, tree=view_tree))
        for call in pyast.calls(tree, REGISTER_CALL):
            prefix = pyast.constant(call.args[0], None) if len(call.args) >= 2 else None
            if not isinstance(prefix, str):
                continue
            handler, rel, view_tree = _find_view(index, entry.rel, _view_name(call.args[1]))
            routes.append(Route("ANY", _url_path(prefix), rel or entry.rel,
                                handler.lineno if handler else call.lineno, "drf",
                                handler=handler, tree=view_tree))
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
    subprocess.run(["git", "-C", str(root), "-c", "user.name=dpr", "-c", "user.email=dpr@example.invalid",
                    *args], check=True, capture_output=True)


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
    write(tmp_path, "package.json", '{"dependencies": {"next": "14"}, "devDependencies": {"vitest": "1"}}')
    write(tmp_path, "web/broken/package.json", "{not json")
    write(tmp_path, "pyproject.toml",
          '[project]\ndependencies = ["Django>=5", "psycopg[binary]"]\n'
          '[dependency-groups]\ndev = ["pytest"]\n'
          '[tool.poetry.dependencies]\nsentry_sdk = "^2"\n')
    write(tmp_path, "requirements-dev.txt", "# tools\nslowapi==0.1 ; python_version > '3'\n-r base.txt\n")
    write(tmp_path, "src/a.ts",
          "import { createClient } from '@supabase/supabase-js'\n"
          "import './styles.css'\nconst x = require(\"stripe\")\nimport 'server-only'\n")
    write(tmp_path, "svc/b.py", "import os\nfrom openai import OpenAI\n")
    packages, sites = collect_packages(RepoIndex(tmp_path))
    for name in ["next", "vitest", "django", "psycopg", "pytest", "sentry-sdk", "slowapi",
                 "@supabase/supabase-js", "stripe", "server-only", "openai", "os"]:
        assert name in packages, name
    assert [str(loc) for loc in sites["stripe"]] == ["src/a.ts:3"]
    assert [str(loc) for loc in sites["openai"]] == ["svc/b.py:2"]
    assert normalise("Flask_Login") == "flask-login"


def test_collect_env_vars_names_only(tmp_path):
    write(tmp_path, ".env.local", "NEXT_PUBLIC_SUPABASE_URL=https://x\nSECRET_VALUE_HOLDER=do-not-read\n")
    write(tmp_path, "lib/a.ts",
          "const u = process.env.NEXT_PUBLIC_SUPABASE_URL\nconst k = process.env['STRIPE_SECRET_KEY']\n"
          "const v = import.meta.env.VITE_API\n")
    write(tmp_path, "src/routes/+page.svelte",
          "<script>\nimport { PUBLIC_MAP_TOKEN } from '$env/static/public'\n</script>\n")
    write(tmp_path, "svc/settings.py",
          "import os\nA = os.environ['DATABASE_URL']\nB = os.environ.get('DEBUG')\n"
          "C = os.getenv('REDIS_URL')\nD = env.bool('USE_TLS')\n")
    env = {e.name: e for e in collect_env_vars(RepoIndex(tmp_path))}
    assert sorted(env) == ["DATABASE_URL", "DEBUG", "NEXT_PUBLIC_SUPABASE_URL", "PUBLIC_MAP_TOKEN",
                           "REDIS_URL", "SECRET_VALUE_HOLDER", "STRIPE_SECRET_KEY", "USE_TLS", "VITE_API"]
    assert [str(loc) for loc in env["NEXT_PUBLIC_SUPABASE_URL"].locations] == [".env.local:1", "lib/a.ts:1"]
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
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout,
                                check=False)
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
    re.MULTILINE)
PY_IMPORT = re.compile(r"^\s*(?:from\s+([A-Za-z_]\w*)|import\s+([A-Za-z_]\w*))", re.MULTILINE)
JS_ENV = re.compile(
    r"(?:process\.env|import\.meta\.env)\.([A-Z][A-Z0-9_]*)"
    r"|process\.env\[\s*['\"]([A-Z][A-Z0-9_]*)['\"]\s*\]")
PY_ENV = re.compile(
    r"os\.environ\[\s*['\"]([A-Z][A-Z0-9_]*)['\"]\s*\]"
    r"|os\.environ\.get\(\s*['\"]([A-Z][A-Z0-9_]*)['\"]"
    r"|os\.getenv\(\s*['\"]([A-Z][A-Z0-9_]*)['\"]"
    r"|\benv(?:\.\w+)?\(\s*['\"]([A-Z][A-Z0-9_]*)['\"]")
SVELTE_ENV = re.compile(
    r"import\s*\{([^}]*)\}\s*from\s*['\"]\$env/(?:static|dynamic)/(?:public|private)['\"]")


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
            sites[name].append(Location(entry.rel, line_of(text, match.start(1) if match.group(1)
                                                           else match.start(2))))
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
                Location(entry.rel, line_of(text, match.start())))
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
    write(tmp_path, "package.json",
          '{"dependencies": {"next": "14", "@supabase/supabase-js": "2", "@prisma/client": "5",'
          ' "@sentry/nextjs": "8", "openai": "4", "@upstash/ratelimit": "1"},'
          ' "devDependencies": {"vitest": "1"}}')
    write(tmp_path, "next.config.js",
          "module.exports = { async headers() { return [{ source: '/(.*)', headers: "
          "[{ key: 'X-Frame-Options', value: 'DENY' }] }] } }\n")
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
    write(tmp_path, "shop/settings.py", "SECURE_HSTS_SECONDS = 3600\nfrom django.contrib.auth import x\n")
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
        if (any(normalise(p) in packages for p in spec.get("packages", []))
                or any(index.named(pattern) for pattern in spec.get("files", []))
                or (spec.get("text") and _code_matches(index, spec["text"]))):
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
        locations = sorted({loc for n in names for loc in sites.get(n, [])},
                           key=lambda loc: (loc.file, loc.line))[:20]
        found.append(SdkUse(sdk["name"], sdk["category"], sdk["recipient"], sdk["paid"],
                            tuple(locations)))
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
        "frontend_key_type", "rls_via_dashboard", "tables_not_in_migrations", "buckets_public",
    ]
    assert [q.id for q in questions_for(["leaks"])] == ["hosting_env_not_in_repo", "log_tool_access_retention"]


def test_options_from_detection():
    [db_region] = [q for q in load_questions() if q.id == "db_region"]
    assert options(db_region, Detection(hosting=["vercel"])) == ["vercel", "Not sure"]


def test_resolve_from_dict():
    qs = questions_for(["rls"])
    results, warnings = resolve(qs, Detection(), {
        "frontend_key_type": "Anon or publishable key only",
        "rls_via_dashboard": "Not sure",
        "nonsense": 1,
    })
    by_id = {r.question.id: r for r in results}
    assert [r.question.id for r in results] == [q.id for q in qs]
    assert (by_id["frontend_key_type"].open, by_id["frontend_key_type"].source) == (False, "answers")
    assert (by_id["rls_via_dashboard"].open, by_id["rls_via_dashboard"].answer) == (True, "Not sure")
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
    q = Question(id="x", reviews=("rls",), text="Host?", type="text", why="w", who="w",
                 answered_by="hosting")
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
    assert ask_on_terminal(q, ["Yes"], input_fn=lambda _: "only avatars", output=printed.append) == "only avatars"
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
            id=q["id"], reviews=tuple(q["reviews"]), text=q["text"], type=q["type"],
            why=q["why"], who=q["who"], options_from=q.get("options_from"),
            static_options=tuple(q.get("static_options", [])),
            honest_out=tuple(q.get("honest_out", ["Not sure"])),
            answered_by=q.get("answered_by"), lawyer=bool(q.get("lawyer", False)),
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


def resolve(questions: list[Question], detection: Detection,
            answers: str | Path | dict | None = None, interactive: bool = False,
            ask: Ask | None = None) -> tuple[list[QuestionResult], list[str]]:
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
        "# Honest answers such as \"Not sure\" are fine. They are listed as open questions.",
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


def ask_on_terminal(question: Question, options: list[str],
                    input_fn: Callable[[str], str] = input,
                    output: Callable[[str], None] = print) -> str | None:
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
    "inventory": "INV", "rls": "RLS", "auth": "CASE", "baseline": "FIX",
    "owasp": "FINDING", "leaks": "LEAK", "abuse": "GUARD",
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

KEY_RULES = ("LEAK-PUBLIC-SECRET", "LEAK-HARDCODED-KEY", "LEAK-KEY-IN-BUILD",
             "LEAK-ENV-TRACKED", "LEAK-ENV-IN-HISTORY")


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
        for phrase in ("compliant with", "complies with", "satisfies article",
                       "satisfies section", "lawful basis is"):
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
    write(tmp_path, ".env.example",
          "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=\nNEXT_PUBLIC_SUPABASE_ANON_KEY=\nSUPABASE_SERVICE_ROLE_KEY=\n")
    write(tmp_path, "lib/a.ts", "const k = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY\n")
    [f] = findings_for(tmp_path, "leaks", "LEAK-PUBLIC-SECRET")
    assert [str(loc) for loc in f.locations] == [".env.example:1", "lib/a.ts:1"]
    assert (f.tag, f.severity.value) == (Tag.CONFIRMED, "critical")
    assert f.fix.startswith(ROTATE)
    assert "rename NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY to SUPABASE_SERVICE_ROLE_KEY" in f.fix
    assert f.snippet is None


def test_hardcoded_key_live_and_test(tmp_path):
    write(tmp_path, "lib/stripe.ts", f'import Stripe from "stripe"\nexport const s = new Stripe("{LIVE}")\n')
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
    write(tmp_path, "next.config.js", "module.exports = {\n  productionBrowserSourceMaps: true,\n}\n")
    write(tmp_path, ".next/static/chunks/main.js.map", "{}")
    found = findings_for(tmp_path, "leaks", "LEAK-SOURCEMAP")
    assert sorted(str(f.locations[0]) for f in found) == [
        ".next/static/chunks/main.js.map:1", "next.config.js:2",
    ]


def test_sentry_pii(tmp_path):
    write(tmp_path, "sentry.client.config.ts",
          'import * as Sentry from "@sentry/nextjs"\nSentry.init({\n  dsn: "x",\n  sendDefaultPii: true,\n})\n')
    write(tmp_path, "sentry.server.config.ts",
          'import * as Sentry from "@sentry/nextjs"\nSentry.init({ dsn: "x" })\n')
    write(tmp_path, "sentry.edge.config.ts",
          'import * as Sentry from "@sentry/nextjs"\n'
          'Sentry.init({ dsn: "x", beforeSend(event) { return event } })\n')
    write(tmp_path, "app/settings.py",
          "import sentry_sdk\nsentry_sdk.init(\n    dsn='x',\n    send_default_pii=True,\n)\n")
    found = sorted((f.locations[0].file, f.locations[0].line) for f in
                   findings_for(tmp_path, "leaks", "LEAK-SENTRY-PII"))
    assert found == [
        ("app/settings.py", 4), ("sentry.client.config.ts", 4), ("sentry.server.config.ts", 2),
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
            yield make_finding("LEAK-PUBLIC-SECRET", tag=Tag.CONFIRMED, locations=env.locations,
                               name=env.name, prefix=prefix, renamed=env.name[len(prefix):])


@rule("LEAK-HARDCODED-KEY", review="leaks", severity="critical", exploitability="high")
def hardcoded_key(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.files:
        text = ctx.index.text(entry.rel)
        for hit in find_keys(text):
            yield make_finding(
                "LEAK-HARDCODED-KEY", tag=Tag.CONFIRMED, locations=[Location(entry.rel, hit.line)],
                severity=None if hit.live else "high", snippet=snippet(text, hit.line),
                kind=hit.kind)


@rule("LEAK-KEY-IN-BUILD", review="leaks", severity="critical", exploitability="high")
def key_in_build(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.build_files:
        text = entry.path.read_text(encoding="utf-8", errors="replace")
        for hit in find_keys(text):
            yield make_finding(
                "LEAK-KEY-IN-BUILD", tag=Tag.CONFIRMED, locations=[Location(entry.rel, hit.line)],
                severity=None if hit.live else "high", kind=hit.kind)


@rule("LEAK-SOURCEMAP", review="leaks", severity="medium", exploitability="medium")
def sourcemaps(ctx: Context) -> Iterator[Finding]:
    maps = [f for f in ctx.index.build_files if f.name.endswith(".map")]
    if maps:
        yield make_finding(
            "LEAK-SOURCEMAP", tag=Tag.CONFIRMED, locations=[Location(f.rel, 1) for f in maps[:5]],
            what=f"{len(maps)} source map file(s) are in the build output.")
    for entry in ctx.index.named("next.config.*", "vite.config.*"):
        text = ctx.index.text(entry.rel)
        pattern = NEXT_SOURCEMAPS if entry.name.startswith("next.") else VITE_SOURCEMAPS
        for match in pattern.finditer(text):
            line = line_of(text, match.start())
            yield make_finding(
                "LEAK-SOURCEMAP", tag=Tag.CONFIRMED, locations=[Location(entry.rel, line)],
                snippet=snippet(text, line),
                what=f"{entry.name} turns on source maps for the production build.")


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
                yield make_finding("LEAK-SENTRY-PII", tag=Tag.CONFIRMED,
                                   locations=[Location(entry.rel, line)],
                                   snippet=snippet(text, line),
                                   what=_sentry_detail(sends_pii, scrubs))


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
            yield make_finding("LEAK-SENTRY-PII", tag=Tag.CONFIRMED,
                               locations=[Location(entry.rel, line)],
                               snippet=snippet(text, line), what=_sentry_detail(sends_pii, scrubs))


@rule("LEAK-SENTRY-PII", review="leaks", severity="medium", exploitability="low")
def sentry_pii(ctx: Context) -> Iterator[Finding]:
    yield from _js_sentry(ctx)
    yield from _py_sentry(ctx)


def run(ctx: Context) -> ReviewSection:
    note = ("No secret value is printed in this report. Findings name the variable or key type "
            "and where it is. A key that reached a browser or git history must be rotated.")
    return ReviewSection("leaks", [Part("text", "What this review never prints", body=note),
                                   Part("findings", "Leaks")])
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
    subprocess.run(["git", "-C", str(root), "-c", "user.name=dpr", "-c", "user.email=dpr@example.invalid",
                    *args], check=True, capture_output=True)


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
    assert locs(findings_for(tmp_path / "web", "leaks", "LEAK-ENV-IN-HISTORY")) == [".env.staging:1"]


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
    write(tmp_path, "app/api/users/[id]/route.ts",
          "export async function GET(req, { params }) {\n"
          "  const user = await prisma.user.findUnique({ where: { id: params.id } })\n"
          "  return NextResponse.json(user)\n}\n")
    write(tmp_path, "app/api/invoices/[id]/route.ts",
          "export async function GET(req, { params }) {\n"
          "  return NextResponse.json(await prisma.invoice.findFirst({ where: { id: params.id } }))\n}\n")
    write(tmp_path, "app/api/safe/route.ts",
          "export async function GET() {\n"
          "  const user = await prisma.user.findUnique({ where: { id: 1 }, select: { id: true } })\n"
          "  return NextResponse.json(user)\n}\n")
    write(tmp_path, "app/api/profile/route.ts",
          "export async function GET() {\n"
          "  const { data } = await supabase.from('profiles').select('*').single()\n"
          "  return Response.json(data)\n}\n")
    write(tmp_path, "app/actions.ts",
          '"use server"\nexport async function me() {\n  return prisma.user.findFirst({ where: { id: 1 } })\n}\n')
    found = {str(f.locations[0]): f for f in findings_for(tmp_path, "leaks", "LEAK-BROAD-RESPONSE")}
    assert sorted(found) == [
        "app/actions.ts:3", "app/api/invoices/[id]/route.ts:2",
        "app/api/profile/route.ts:3", "app/api/users/[id]/route.ts:3",
    ]
    assert found["app/api/users/[id]/route.ts:3"].severity.value == "high"
    assert found["app/api/invoices/[id]/route.ts:2"].severity.value == "medium"
    assert found["app/api/profile/route.ts:3"].tag.value == "INFERRED"


def test_broad_response_python(tmp_path):
    write(tmp_path, "shop/serializers.py",
          "from rest_framework import serializers\n\n"
          "class UserSerializer(serializers.ModelSerializer):\n"
          "    class Meta:\n        model = User\n        fields = \"__all__\"\n")
    write(tmp_path, "shop/urls.py", "from django.urls import path\nfrom . import views\n"
          "urlpatterns = [path('me/', views.me)]\n")
    write(tmp_path, "shop/views.py",
          "from django.forms.models import model_to_dict\n\n"
          "def me(request):\n    return JsonResponse(model_to_dict(request.user))\n")
    assert locs(findings_for(tmp_path, "leaks", "LEAK-BROAD-RESPONSE")) == [
        "shop/serializers.py:6", "shop/views.py:4",
    ]


def test_ssr_props(tmp_path):
    write(tmp_path, "pages/account.tsx",
          "export async function getServerSideProps() {\n"
          "  const user = await prisma.user.findUnique({ where: { id: 1 } })\n"
          "  return { props: { user } }\n}\n"
          "export default function Page() { return null }\n")
    assert locs(findings_for(tmp_path, "leaks", "LEAK-SSR-PROPS")) == ["pages/account.tsx:3"]


def test_logged_pii(tmp_path):
    write(tmp_path, "app/api/signup/route.ts",
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
          "}\n")
    write(tmp_path, "svc/views.py",
          "import logging, traceback\nlogger = logging.getLogger(__name__)\n\n"
          "def create(request):\n"
          "    logger.error(f'bad input {request.data}')\n"
          "    try:\n        Invoice.objects.create(**request.data)\n"
          "    except Exception as e:\n        print(e)\n        traceback.print_exc()\n"
          "    try:\n        parse()\n    except ValueError as e:\n        print(e)\n")
    assert locs(findings_for(tmp_path, "leaks", "LEAK-LOGGED-PII")) == [
        "app/api/signup/route.ts:11", "app/api/signup/route.ts:6", "app/api/signup/route.ts:7",
        "svc/views.py:10", "svc/views.py:5", "svc/views.py:9",
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
    r"(?:prisma|db|tx)\.(\w+)\.(findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow|findMany)")
SUPABASE_ALL = re.compile(r"\.select\(\s*(?:['\"`]\*['\"`])?\s*\)")
SUPABASE_TABLE = re.compile(r"\.from\(\s*['\"`](\w+)['\"`]\s*\)")
SELECT_STAR = re.compile(r"select\s+\*", re.IGNORECASE)
JS_ROUTE_FRAMEWORKS = ("next-app", "next-pages", "next-action", "express", "fastify")
PY_ROUTE_FRAMEWORKS = ("django", "drf", "fastapi", "flask")
LOG_CALL = re.compile(
    r"console\.(?:log|error|warn|info|debug)|(?:logger|log)\.(?:info|error|warn|debug|log|fatal)")
PY_LOG_CALL = re.compile(
    r"print|logging\.(?:debug|info|warning|error|exception|critical)"
    r"|(?:logger|log|LOGGER)\.(?:debug|info|warning|error|exception|critical)")
SENSITIVE_ROOTS = frozenset({"req", "request", "body", "user", "token", "payload", "headers",
                             "session", "password"})
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
            yield make_finding("LEAK-ENV-TRACKED", tag=Tag.CONFIRMED,
                               locations=[Location(path, 1)], path=path)


@rule("LEAK-ENV-IN-HISTORY", review="leaks", severity="high", exploitability="medium")
def env_in_history(ctx: Context) -> Iterator[Finding]:
    root = ctx.index.root
    output = run_git(root, "log", "--all", "--diff-filter=A", "--name-only", "--format=commit %h",
                     "--", ":(glob)**/.env", ":(glob)**/.env.*")
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
        path = path[len(prefix):]
        if path and _is_real_env(path) and path not in tracked:
            first_seen.setdefault(path, commit)
    for path, sha in first_seen.items():
        yield make_finding("LEAK-ENV-IN-HISTORY", tag=Tag.CONFIRMED,
                           locations=[Location(path, 1)], path=path, commit=sha)


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


def _broad(ctx: Context, rel: str, line: int, source: str, name: str | None,
           rule_id: str = "LEAK-BROAD-RESPONSE") -> Finding:
    what = (f"This response sends every field of the {name or 'queried'} record, "
            "not only the ones the client needs.")
    return make_finding(rule_id, tag=Tag.INFERRED, locations=[Location(rel, line)],
                        severity=_severity(ctx, name), snippet=snippet(ctx.index.text(rel), line),
                        source=source, what=what)


def _js_responses(ctx: Context) -> Iterator[Finding]:
    for route in ctx.detection.routes:
        handler = route.handler
        if route.framework not in JS_ROUTE_FRAMEWORKS or handler is None:
            continue
        if handler.type not in jsts.FUNCTION_TYPES:
            continue
        candidates = [jsts.arguments(c)[0] for c in jsts.calls(route.tree, RESPONSE_CALL, handler)
                      if jsts.arguments(c)]
        if route.framework == "next-action":
            candidates += [r.named_children[0] for r in jsts.walk(handler, {"return_statement"})
                           if r.named_children]
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
                "model_to_dict", "vars")
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
                            yield _broad(ctx, entry.rel, jsts.line(tree, ret), source, model,
                                         rule_id="LEAK-SSR-PROPS")


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
        return any(_js_sensitive(s.named_children[0]) for s in arg.named_children
                   if s.type == "template_substitution" and s.named_children)
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
        return any(_py_sensitive(v.value, tree, line) for v in node.values
                   if isinstance(v, ast.FormattedValue))
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
    return make_finding("LEAK-LOGGED-PII", tag=Tag.INFERRED, locations=[Location(rel, line)],
                        snippet=snippet(ctx.index.text(rel), line), what=what)


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
    write(tmp_path, "lib/q.ts",
          "export const q = () => supabase.from('invoices').select('id')\n"
          "export const b = () => supabase.storage.createBucket('uploads', { public: true })\n")
    return tmp_path


def lines(found):
    return sorted((f.locations[0].file, f.locations[0].line) for f in found)


def test_table_off(tmp_path):
    [f] = findings_for(app(tmp_path), "rls", "RLS-TABLE-OFF")
    assert (str(f.locations[0]), f.severity.value, f.tag.value) == (
        "supabase/migrations/001_init.sql:1", "critical", "CONFIRMED")
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
        "Review 2 (rls): not applicable, no SQL tables, Supabase client or database dump found"]


def test_section_parts_and_breakage_note(tmp_path):
    index = RepoIndex(app(tmp_path))
    ctx = rules.Context(index=index, detection=detect(index))
    section = reviews.available()["rls"].run(ctx)
    assert [p.title for p in section.parts] == [
        "Table protection status", "Policy defects", "Missing policies (runnable SQL)",
        "How to confirm from outside the app", "Confirm in the database",
    ]
    table = section.parts[0]
    assert [r[0] for r in table.rows] == ["public.documents", "public.invoices", "public.lookup", "public.members"]
    invoices = next(r for r in table.rows if r[0] == "public.invoices")
    assert invoices[1:5] == ("no", "0", "yes, every row", "exposed")
    missing = section.parts[2].body
    assert "public.invoices" in missing and "public.members" in missing
    assert "`lib/q.ts:1`" in missing
    assert "pg_policies" in section.parts[4].body


def test_db_dump_is_source_of_truth(tmp_path):
    root = app(tmp_path)
    dump = write(tmp_path, "dump.csv",
                 "schemaname,tablename,rowsecurity\npublic,invoices,t\n\n"
                 "schemaname,tablename,policyname,permissive,roles,cmd,qual,with_check\n"
                 "public,invoices,inv_own,PERMISSIVE,{authenticated},SELECT,(auth.uid() = user_id),\n")
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
    return ".".join(p if re.fullmatch(r"[a-z_][a-z0-9_]*", p) else f'"{p}"'
                    for p in key.split(".", 1))


def sql_block(sql: str) -> str:
    return f"```sql\n{sql}\n```"


NO_PREDICATE = "-- No owner or tenant column was found. Choose the predicate for this table first."


def policies_sql(state: SchemaState, table: TableDef) -> str:
    name, target = table.name, qualified(table.key)
    lines = [f"alter table {target} enable row level security;"]
    pred = predicate(state, table)
    if pred is None:
        return "\n".join([*lines, NO_PREDICATE])
    return "\n".join([
        *lines, "",
        f'create policy "{name}_select_own" on {target}\n  for select using ({pred});', "",
        f'create policy "{name}_insert_own" on {target}\n  for insert with check ({pred});', "",
        f'create policy "{name}_update_own" on {target}\n'
        f"  for update using ({pred}) with check ({pred});", "",
        f'create policy "{name}_delete_own" on {target}\n  for delete using ({pred});',
    ])


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
    reach = ("A public Supabase key is configured, so anyone holding it can read the table."
             if exposed else "No public key was found, which reduces how reachable it is.")
    for table in public_tables(ctx):
        if not table.rls:
            yield make_finding(
                "RLS-TABLE-OFF", tag=Tag.CONFIRMED, locations=[table_location(table)],
                severity="critical" if exposed else "high",
                fix=sql_block(policies_sql(state, table)), verify=confirm_commands(table.name),
                table=table.key, reach=reach)


@rule("RLS-NO-POLICIES", review="rls", severity="low", exploitability="low")
def no_policies(ctx: Context) -> Iterator[Finding]:
    state = state_for(ctx)
    for table in public_tables(ctx):
        if table.rls and not state.policies_for(table.key):
            yield make_finding("RLS-NO-POLICIES", tag=Tag.CONFIRMED,
                               locations=[table_location(table)],
                               fix=sql_block(policies_sql(state, table)), table=table.key)


@rule("RLS-SELECT-ONLY", review="rls", severity="low", exploitability="low")
def select_only(ctx: Context) -> Iterator[Finding]:
    state = state_for(ctx)
    for table in public_tables(ctx):
        policies = state.policies_for(table.key)
        if table.rls and policies and all(p.command == "select" for p in policies):
            yield make_finding("RLS-SELECT-ONLY", tag=Tag.CONFIRMED,
                               locations=[policies[0].location], table=table.key)


@rule("RLS-VIEW-BYPASS", review="rls", severity="high", exploitability="high")
def view_bypass(ctx: Context) -> Iterator[Finding]:
    if not client_facing(ctx):
        return
    protected_tables = _rls_tables(ctx)
    for key, view in sorted(state_for(ctx).views.items()):
        protected = [s for s in view.sources if s in protected_tables]
        if key.startswith("public.") and not view.security_invoker and protected:
            fix = sql_block(f"alter view {qualified(key)} set (security_invoker = true);")
            yield make_finding("RLS-VIEW-BYPASS", tag=Tag.CONFIRMED, locations=[view.location],
                               fix=fix, view=key, tables=", ".join(protected))


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
        yield make_finding("RLS-DEFINER-FUNCTION", tag=Tag.CONFIRMED, locations=[fn.location],
                           severity="high" if protected else "medium", function=key, what=what)


@rule("RLS-PUBLIC-BUCKET", review="rls", severity="medium", exploitability="medium")
def public_bucket(ctx: Context) -> Iterator[Finding]:
    for bucket in sorted(state_for(ctx).buckets.values(), key=lambda b: b.id):
        if bucket.public:
            yield make_finding("RLS-PUBLIC-BUCKET", tag=Tag.CONFIRMED,
                               locations=[bucket.location], bucket=bucket.id)
    for entry in ctx.index.js_files:
        if "createBucket" not in ctx.index.text(entry.rel):
            continue
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for call in jsts.calls(tree, r"(?:\w+\.)*createBucket"):
                args = jsts.arguments(call)
                public = jsts.object_pairs(args[1]).get("public") if len(args) > 1 else None
                if public is not None and jsts.node_text(public) == "true":
                    yield make_finding(
                        "RLS-PUBLIC-BUCKET", tag=Tag.CONFIRMED,
                        locations=[Location(entry.rel, jsts.line(tree, call))],
                        bucket=jsts.string_value(args[0]) or "(dynamic name)")


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
        reach = ("yes, every row" if ctx.detection.public_supabase_key
                 else "yes, if a public key reaches the browser")
        verdict = "exposed"
    elif count == 0:
        reach, verdict = "no, all client access denied", "locked, probably read with a service key"
    else:
        reach, verdict = "only rows the policies allow", "check policy defects"
    return (table.key, "yes" if table.rls else "no", str(count), reach, verdict,
            str(table_location(table)))


def run(ctx: Context) -> ReviewSection | None:
    state = state_for(ctx)
    if not state.tables and not client_facing(ctx):
        ctx.not_covered.append(
            "Review 2 (rls): not applicable, no SQL tables, Supabase client or database dump found")
        return None
    if not client_facing(ctx):
        return ReviewSection("rls", [Part("text", "Relevance", body=SERVER_ONLY)])
    tables = public_tables(ctx)
    parts = [
        Part("table", "Table protection status",
             columns=("Table", "RLS enabled", "Policies", "Reachable by anon key", "Verdict",
                      "Evidence"),
             rows=tuple(_status_row(ctx, t) for t in tables)),
        Part("findings", "Policy defects"),
    ]
    gaps = [t for t in tables if not t.rls or not state.policies_for(t.key)]
    if gaps:
        body = "\n\n".join(sql_block(policies_sql(state, t)) for t in gaps)
        breakage = _breakage(ctx, gaps)
        if breakage:
            body += ("\n\nAdding these policies can make these queries return nothing for rows "
                     "the caller does not own:\n" + "\n".join(f"- `{loc}`" for loc in breakage))
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
    assert 'drop policy "documents_read" on public.documents;' in by_line(root, "RLS-POLICY-TRUE")[8].fix


def test_weak_with_check_severity(tmp_path):
    found = by_line(app(tmp_path), "RLS-WEAK-WITH-CHECK")
    assert {line: f.severity.value for line, f in found.items()} == {3: "low", 11: "high", 12: "high"}


def test_wrong_role_client_owner_tenant_unbound(tmp_path):
    root = app(tmp_path)
    assert sorted(by_line(root, "RLS-WRONG-ROLE")) == [10]
    assert sorted(by_line(root, "RLS-CLIENT-OWNER")) == [4]
    unbound = by_line(root, "RLS-TENANT-UNBOUND")
    assert sorted(unbound) == [15]
    assert unbound[15].tag.value == "INFERRED" and unbound[15].proof_needed


def test_dump_only_table_is_checked(tmp_path):
    root = app(tmp_path)
    dump = write(tmp_path, "pol.csv",
                 "schemaname,tablename,policyname,permissive,roles,cmd,qual,with_check\n"
                 "public,secrets,secrets_read,PERMISSIVE,{authenticated},SELECT,(auth.role() = 'authenticated'::text),\n")
    found = findings_for(root, "rls", "RLS-AUTHENTICATED-NOT-OWNER", db_dump=str(dump))
    assert sorted((f.locations[0].file.endswith("pol.csv"), f.locations[0].line) for f in found) == [
        (False, 9), (True, 2),
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
    ordered = sorted(state.policies.values(),
                     key=lambda p: (p.location.file, p.location.line, p.name))
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
            yield make_finding("RLS-POLICY-TRUE", tag=Tag.CONFIRMED, locations=[policy.location],
                               fix=_fix(state, policy), policy=policy.name, table=table.key)


@rule("RLS-AUTHENTICATED-NOT-OWNER", review="rls", severity="high", exploitability="high")
def authenticated_not_owner(ctx: Context) -> Iterator[Finding]:
    for state, table, policy in _policies(ctx):
        text = predicate_text(policy)
        if not text or AUTH_REF.search(text) or not has_owner_or_unknown(table):
            continue
        signed_in_only = (policy.roles_explicit and set(policy.roles) == {"authenticated"}
                          and "true" not in (policy.using, policy.with_check))
        if AUTH_ROLE.search(text) or signed_in_only:
            yield make_finding("RLS-AUTHENTICATED-NOT-OWNER", tag=Tag.CONFIRMED,
                               locations=[policy.location], fix=_fix(state, policy),
                               policy=policy.name, table=table.key)


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
            p.command in ("select", "all") and p.using
            and (UID_REF.search(p.using) or re.search(rf"\b{re.escape(owner)}\b", p.using))
            for p in policies)
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
                what = (f"The {policy.command} policy {policy.name} lets a caller change {owner} "
                        "to another user. ")
                what += ("A select policy scoped to the owner blocks this in practice."
                         if select_scoped else "No select policy scoped to the owner blocks it.")
            yield make_finding("RLS-WEAK-WITH-CHECK", tag=Tag.CONFIRMED,
                               locations=[policy.location], severity=severity,
                               fix=_fix(state, policy), policy=policy.name, table=table.key,
                               owner=owner, what=what)


@rule("RLS-WRONG-ROLE", review="rls", severity="high", exploitability="high")
def wrong_role(ctx: Context) -> Iterator[Finding]:
    for state, table, policy in _policies(ctx):
        if owner_column(table) is None or policy.command not in WRITE_COMMANDS:
            continue
        open_roles = {"anon", "public"} & set(policy.roles)
        if policy.roles_explicit and open_roles and not AUTH_REF.search(predicate_text(policy)):
            yield make_finding("RLS-WRONG-ROLE", tag=Tag.CONFIRMED, locations=[policy.location],
                               fix=_fix(state, policy), policy=policy.name, table=table.key,
                               roles=", ".join(sorted(open_roles)), command=policy.command)


@rule("RLS-CLIENT-OWNER", review="rls", severity="high", exploitability="high")
def client_owner(ctx: Context) -> Iterator[Finding]:
    for state, table, policy in _policies(ctx):
        if CLIENT_CLAIM.search(predicate_text(policy)):
            yield make_finding("RLS-CLIENT-OWNER", tag=Tag.CONFIRMED, locations=[policy.location],
                               fix=_fix(state, policy), policy=policy.name, table=table.key)


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
        yield make_finding("RLS-TENANT-UNBOUND", tag=Tag.INFERRED, locations=[policy.location],
                           fix=_fix(state, policy), policy=policy.name, table=table.key,
                           tenant=tenant)
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
    write(tmp_path, "package.json", '{"dependencies": {"next": "14", "@supabase/supabase-js": "2"}}')
    write(tmp_path, ".env.example", "NEXT_PUBLIC_SUPABASE_ANON_KEY=\nNEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=\n")
    write(tmp_path, "supabase/migrations/1.sql", "create table public.notes (id int, user_id uuid);")
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
        "inventory": "not available in this version", "rls": "runs", "auth": "not available in this version",
        "baseline": "not available in this version", "owasp": "not available in this version",
        "leaks": "runs", "abuse": "not available in this version",
    }
    assert [s for s, _ in report.meta.applicability] == [
        "inventory", "rls", "auth", "baseline", "owasp", "leaks", "abuse"]
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
    assert {q.question.id for q in report.questions} == {"hosting_env_not_in_repo", "log_tool_access_retention"}
    assert not any(f.review == "rls" for f in report.findings)


def test_not_applicable_reason(tmp_path):
    write(tmp_path, "a.py", "x = 1\n")
    report = review(tmp_path, reviews=[2])
    assert report.sections == {}
    assert dict(report.meta.applicability)["rls"] == "not applicable, no SQL tables, Supabase client or database dump found"


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
    ("url", "baseline", "Live header read skipped: it belongs to review 4 (baseline), "
                        "which is not available in this version"),
    ("with_audit", "owasp", "Dependency audit skipped: it belongs to review 5 (owasp), "
                            "which is not available in this version"),
)


def discover(path: str | os.PathLike[str]) -> tuple[RepoIndex, Detection]:
    index = RepoIndex(path)
    index.sanity_check()
    return index, detect(index)


def _validate(url: str | None, owns_host: bool, semgrep: str, db_dump: str | None) -> None:
    if url and not owns_host:
        raise ScanError(
            "--url needs --i-own-this-host: dpr only reads headers from a host you control")
    if semgrep not in ("auto", "off") and not Path(semgrep).is_dir():
        raise ScanError(f"semgrep rules folder not found: {semgrep}")
    if db_dump and not Path(db_dump).is_file():
        raise ScanError(f"database dump not found: {db_dump}")


def _reason(slug: str, selected: list[str], modules: dict, sections: dict,
            notes: list[str]) -> str:
    if slug in sections:
        return "runs"
    if slug not in selected:
        return "not selected"
    if slug not in modules:
        return "not available in this version"
    prefix = f"Review {number(slug)} ({slug}): "
    return next((n[len(prefix):] for n in notes if n.startswith(prefix)), "not applicable")


def review(path: str | os.PathLike[str] = ".", reviews: Iterable[str | int] = ("all",),
           answers: str | Path | dict | None = None, interactive: bool = False,
           url: str | None = None, owns_host: bool = False, login_path: str | None = None,
           with_audit: bool = False, semgrep: str = "auto", db_dump: str | None = None,
           today: datetime.date | None = None) -> Report:
    _validate(url, owns_host, semgrep, db_dump)
    selected = resolve_reviews(reviews)
    index, detection = discover(path)
    options = Options(url=url, owns_host=owns_host, login_path=login_path,
                      with_audit=with_audit, semgrep=semgrep, db_dump=db_dump)
    ask = ask_on_terminal if interactive and sys.stdin.isatty() else None
    results, warnings = resolve(questions_for(selected), detection, answers, interactive, ask)
    ctx = Context(index=index, detection=detection, options=options,
                  answers={r.question.id: r for r in results})
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
        (slug, _reason(slug, selected, modules, sections, ctx.not_covered)) for slug in REVIEWS)
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
    return Report(meta=meta, detection=detection, findings=rank(dedupe(findings)),
                  sections=sections, questions=results, not_covered=not_covered)
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
    base = dict(rule_id=rule_id, review=review, title=title, tag="CONFIRMED", severity=sev,
                exploitability="high", effort_minutes=5, locations=(Location("a.ts", 3),),
                detail="Detail text.", fix="Fix text.")
    base.update(extra)
    return Finding(**base)


def report():
    q_open = Question(id="q1", reviews=("rls",), text="Are buckets public?", type="choice",
                      why="Dashboards.", who="Admin | owner")
    q_done = Question(id="q2", reviews=("rls",), text="Which key ships?", type="choice",
                      why="Env.", who="Ops")
    return Report(
        meta=ReportMeta(project="shop", scope=".", revision="abc123", date="2026-09-16",
                        reviews_run=("rls", "leaks"), method="Static analysis of the repository",
                        applicability=(("inventory", "not available in this version"), ("rls", "runs"),
                                       ("leaks", "runs"))),
        detection=Detection(frameworks=["next"], databases=["supabase"], languages={"javascript/typescript": 4}),
        findings=[
            finding("RLS-TABLE-OFF", "rls", "critical", "RLS off on public.notes",
                    fix="```sql\nalter table public.notes enable row level security;\n```"),
            finding("LEAK-LOGGED-PII", "leaks", "high", "Log call", tag="INFERRED", proof_needed="Check it.",
                    snippet="console.error(body)"),
            finding("LEAK-PUBLIC-SECRET", "leaks", "low", "Public secret", verify="Search the bundle."),
        ],
        sections={
            "leaks": ReviewSection("leaks", [Part("findings", "Leaks")]),
            "rls": ReviewSection("rls", [
                Part("table", "Table protection status", columns=("Table", "Verdict"),
                     rows=(("public.notes", "exposed | bad"),)),
                Part("findings", "Policy defects"),
                Part("text", "Confirm in the database", body="Run the queries."),
            ]),
        },
        questions=[QuestionResult(q_open, None, "none", True), QuestionResult(q_done, "Anon only", "answers", False)],
        not_covered=["big.js: larger than 1 MB"],
    )


def test_header_summary_and_top_fixes():
    text = render_markdown(report())
    assert text.startswith("# Data Protection Review: shop\n\nDate: 2026-09-16\nScope: . @ abc123\n")
    assert "Reviews run: rls, leaks" in text
    assert "| Critical | 1 |" in text and "| High | 1 |" in text and "| Open questions (UNKNOWN) | 1 |" in text
    assert "1. RLS off on public.notes (`a.ts:3`, about 5 min)" in text
    assert "not legal advice" in text


def test_sections_in_number_order_with_tables_and_blocks():
    text = render_markdown(report())
    assert text.index("## 2. Database lock check") < text.index("## 6. Leak hunt")
    assert "| public.notes | exposed \\| bad |" in text
    assert "#### RLS 1: RLS off on public.notes" in text
    leaks = text[text.index("## 6. Leak hunt"):]
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
BANNED_PHRASES = ("compliant with", "complies with", "satisfies article", "satisfies section",
                  "lawful basis is")
SEVERITIES = ("critical", "high", "medium", "low")
SOURCE_LABELS = {"answers": "from the answers file", "interactive": "answered in the terminal",
                 "detection": "detected in the repository"}
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
    for heading, value in (("Proof needed", f.proof_needed), ("Attack", f.attack),
                           ("Blast radius", f.blast)):
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
    summary = _table(("Severity", "Count"), [
        *[(s.capitalize(), str(counts[s])) for s in SEVERITIES],
        ("Open questions (UNKNOWN)", str(len(open_questions))),
    ])
    if report.findings:
        top = "Top three fixes by risk removed per minute spent:\n\n" + "\n".join(
            f"{i}. {f.title} (`{f.locations[0] if f.locations else 'no file'}`, "
            f"about {f.effort_minutes} min)"
            for i, f in enumerate(report.findings[:3], start=1))
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
        "applicability": "Reviews:\n\n" + "\n".join(
            f"- Review {number(slug)}, {TITLES[slug]}: {reason}"
            for slug, reason in report.meta.applicability),
        "sections": sections,
        "answered": "\n".join(
            f"- {q.question.text} {q.answer} ({SOURCE_LABELS.get(q.source, q.source)})"
            for q in answered) or "None.",
        "still_open": _table(
            ("Question", "Why the repository cannot answer it", "Who can answer"),
            [(q.question.text, q.question.why, q.question.who) for q in open_questions]
        ) if open_questions else "None.",
        "not_covered": "\n".join(f"- {item}" for item in [*ALWAYS_NOT_COVERED,
                                                          *report.not_covered]),
    }


def render_markdown(report: Report) -> str:
    env = Environment(loader=PackageLoader("dpr", "report/templates"), autoescape=False,
                      trim_blocks=True, lstrip_blocks=True, keep_trailing_newline=True)
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
    write(tmp_path, "supabase/migrations/1.sql", "create table public.notes (id int, user_id uuid);")
    write(tmp_path, "app/api/notes/route.ts", "export async function GET() {}\n")
    report = dpr.review(tmp_path)
    data = json.loads(dpr.render_json(report))
    assert list(data)[:2] == ["schema_version", "meta"]
    assert data["schema_version"] == 1
    assert set(data) == {"schema_version", "meta", "detection", "findings", "sections", "questions",
                         "not_covered"}
    assert "schema" not in data["detection"] and "packages" not in data["detection"]
    [route] = data["detection"]["routes"]
    assert set(route) == {"method", "path", "file", "line", "framework", "is_public_form"}
    first = data["findings"][0]
    assert first["tag"] in ("CONFIRMED", "INFERRED", "UNVERIFIED")
    assert isinstance(first["locations"][0], dict) and {"file", "line"} <= set(first["locations"][0])
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
    write(root, ".env.example", "NEXT_PUBLIC_SUPABASE_ANON_KEY=\nNEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=\n")
    write(root, "supabase/migrations/1.sql", "create table public.notes (id int, user_id uuid);")
    write(root, "app/page.tsx", "export default function Page() { return null }\n")
    return root


def git(root, *args):
    subprocess.run(["git", "-C", str(root), "-c", "user.name=dpr", "-c", "user.email=dpr@example.invalid",
                    *args], check=True, capture_output=True)


def test_scan_writes_reports_and_summary(tmp_path, capsys):
    root = app(tmp_path)
    assert main(["scan", str(root)]) == 0
    out_dir = root / "data-protection-review"
    [md] = list(out_dir.glob("REPORT-*.md"))
    [js] = list(out_dir.glob("report-*.json"))
    assert md.read_text().startswith("# Data Protection Review: app")
    assert json.loads(js.read_text())["schema_version"] == 1
    lines = capsys.readouterr().out.strip().splitlines()
    assert lines[0].startswith("dpr: 2 findings (critical 2, high 0, medium 0, low 0), 22 open questions")
    assert lines[1] == "Top fixes:"
    assert any(line.startswith("Wrote ") and line.endswith(".md") for line in lines)
    assert len(lines) <= 15


def test_fail_on(tmp_path):
    root = app(tmp_path)
    assert main(["scan", str(root), "--fail-on", "critical", "--format", "json"]) == 1
    assert main(["scan", str(root), "--fail-on", "none", "--format", "json"]) == 0
    assert main(["scan", str(root), "--reviews", "leaks", "--fail-on", "high", "--format", "md"]) == 1


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
    scan.add_argument("--reviews", nargs="+", default=["all"], metavar="REVIEW",
                      help="all, 1 to 7, or " + ", ".join(REVIEWS))
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
    return (f'Tip: add "{rel_dir}/" to .gitignore. '
            "The report maps where the data and the weaknesses are.")


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
        lines += [f"  {i}. {f.title} ({f.locations[0] if f.locations else 'no file'})"
                  for i, f in enumerate(report.findings[:3], start=1)]
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
    report = review(args.path, reviews=reviews, answers=args.answers,
                    interactive=args.interactive, url=args.url, owns_host=args.owns_host,
                    login_path=args.login_path, with_audit=args.with_audit,
                    semgrep=args.semgrep, db_dump=args.db_dump)
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
        ["git", "-C", str(root), "-c", "user.name=dpr", "-c", "user.email=dpr@example.invalid",
         "-c", "commit.gpgsign=false", *args],
        check=True, capture_output=True)


def _bad_extras(root: Path) -> None:
    (root / "lib/stripe.ts").write_text(
        'import Stripe from "stripe"\n\nexport const stripe = new Stripe("' + LIVE_STRIPE + '")\n')
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
        'import Stripe from "stripe"\n\nexport const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)\n')
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
    return {(f.rule_id, f.locations[0].file, f.locations[0].line, f.tag.value) for f in report.findings}


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
    banned = set(yaml.safe_load((FIXTURES / "next-supabase-good" / "expected.yaml").read_text())["must_not_report"])
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
    before = subprocess.run(["git", "-C", str(bad), "status", "--porcelain", "--ignored"],
                            capture_output=True, text=True, check=True).stdout
    listing = sorted(p.relative_to(bad).as_posix() for p in bad.rglob("*") if ".git/" not in p.as_posix())
    review(bad)
    after = subprocess.run(["git", "-C", str(bad), "status", "--porcelain", "--ignored"],
                           capture_output=True, text=True, check=True).stdout
    assert after == before
    assert sorted(p.relative_to(bad).as_posix() for p in bad.rglob("*") if ".git/" not in p.as_posix()) == listing
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

