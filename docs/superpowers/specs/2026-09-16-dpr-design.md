# dpr: deterministic data protection review

Date: 2026-09-16
Status: draft for review
Source behaviour: the data-protection-review skill in `Active Projects/data-protection-review/`

## 1. Goal

A Python package, `dpr`, that runs the same seven reviews as the data-protection-review skill against a code repository, with no LLM. It must be usable two ways: imported as a module (`import dpr`) and run as a CLI (`dpr scan`). It is for private use on repositories the owner controls.

Success means: on the fixture apps, every planted defect is reported with the correct rule id and evidence tag, the clean fixtures report none of them, and no secret value ever appears in any output.

## 2. Scope

### In scope for v1

- Languages: JavaScript, TypeScript (including JSX/TSX, and the `<script>` blocks of `.vue` and `.svelte` files), Python.
- Frameworks recognised: Next.js (app and pages router), Express, Fastify, Django, Django REST Framework, FastAPI, Flask.
- Data layers recognised: Supabase, Postgres SQL migrations, Prisma, Drizzle, Django ORM, SQLAlchemy.
- All seven reviews: inventory, rls, auth, baseline, owasp, leaks, abuse.
- Outputs: Markdown report, JSON, SARIF 2.1.0.
- Optional adapters: Semgrep, `npm audit`, `pip-audit`, live header read.

### Out of scope for v1

- Ruby, Go, PHP, Java. The rule interface must allow adding them later without redesign.
- Firebase security rules (`firestore.rules`, `storage.rules`). Listed under "What this review did not cover" when found.
- Any small language model. Findings keep snippet and location so a later model can re-grade INFERRED findings.
- Generating executable auth tests.
- Publishing to PyPI. Install is from the local path with `uv`.
- HTML report.
- Any exploitation, credential testing, fuzzing or path enumeration. Never in scope.

## 3. Decisions

| Decision | Choice | Reason |
|---|---|---|
| Matching depth | Regex for simple patterns, real parsers for structure | Without an LLM, accuracy is the product. Parsers let findings reach CONFIRMED. |
| JS/TS parser | `tree-sitter` + `tree-sitter-javascript` + `tree-sitter-typescript` | Prebuilt wheels with the grammars inside, no compiler, no runtime download. `tree-sitter-language-pack` 1.x was rejected: it downloads grammars into a user cache at first use, which breaks the no-network rule. |
| Python parser | stdlib `ast` | No dependency, exact. |
| SQL and Prisma | Small own parsers | Only a narrow set of statements matters (section 7). |
| OWASP breadth | Optional Semgrep adapter | Free rule packs give injection, XSS, crypto and config coverage. Rules license allows internal use, which fits private use. |
| First consumer | CLI and CI | Core returns plain objects, so later import by another app needs no change. |
| Unanswerable facts | Answers file, optional prompts | CI never blocks. Missing answers become UNKNOWN. |
| OWASP numbering | OWASP Top 10 2021 | Same numbering as the skill and Semgrep rule metadata. |
| Python | 3.12, managed by `uv` | System Python is 3.9. |
| Name | `dpr` | Short. Can be renamed before the first release tag. |

### Deliberate deviations from the skill text

1. **"Policy on select only leaves insert, update and delete wide open."** In Postgres, once RLS is enabled, a command with no matching policy is denied for roles without `BYPASSRLS`. So `dpr` does not report this as open. It reports `RLS-SELECT-ONLY` as a low informational finding: client writes are denied, so if the app writes to that table it is probably using a service key, which is then checked by the leaks review.
2. **"USING without WITH CHECK on insert/update lets the caller write rows owned by someone else."** Tested on PostgreSQL 14.17: an UPDATE policy with only `USING` reuses it as the check and blocks moving a row to another owner, and an INSERT policy with no `WITH CHECK` blocks the insert. The real defect is a `WITH CHECK` that is present but does not check ownership, such as `WITH CHECK (true)`. For UPDATE that is only exploitable when the table's select policies do not restrict ownership either, because Postgres also checks the new row against select policies when the update has a filter. `dpr` reports this as `RLS-WEAK-WITH-CHECK` (section 10.2).
3. **Report title** uses a colon instead of a dash: `# Data Protection Review: <project>`.
4. **SARIF.** GitHub shows SARIF inline only for public repositories or with paid GitHub Code Security. The CI example therefore uploads the Markdown report as a workflow artifact. SARIF output is still produced.
5. **Tag case.** Evidence tags are uppercase strings (CONFIRMED, INFERRED, UNVERIFIED, UNKNOWN) in JSON and SARIF output, matching section 6.2; section 11.2's lowercase rule applies to severity and exploitability only.

### Milestone 2 refinements to this spec

Found while planning and reviewing reviews 4, 5 and 7. The tables in section 10 already include them.

6. **Calibration.** CONFIRMED only when a parser reads the fact at the cited location. A finding that rests on the absence of evidence is INFERRED whenever the app has a global mechanism the classifier cannot read.
7. **Header checks per surface.** "Not set in any header config" would let a static site that sets `X-Frame-Options` hide an API that sets nothing. Each surface (static host config, Next.js, Express, FastAPI, Django) is judged on its own, and one finding per header lists every surface that lacks it. Vercel and Netlify configs count HSTS as set, because both platforms send it by default.
8. **OWASP categories on baseline and abuse rules** (A01, A02, A04, A05, A07), so SARIF properties and a later Semgrep dedupe can use them. Review 5's "Categories reviewed" part counts only its own rules and cross-references the others.
9. **Route access.** Auth words in dependency, decorator, wrapper and middleware names match whole snake or camel case words (`get_author` is not auth). Database session dependencies (`get_db`, `get_session`, parameters typed `Session` or `AsyncSession`) are not auth. FastAPI reads `APIRouter(dependencies=...)` and `include_router(..., dependencies=...)` up the include chain. Express counts `.use` middleware only when its mount path covers the route, ignores known non-auth middleware (`session()`, `passport.initialize()`, `express.json()`, routers) and reads middleware placed in front of a router where another file mounts it. Mounts, `include_router` calls and `.use` middleware in test files never count. A router is authenticated through its mounts only when every mount is guarded; when mounts disagree the route is public with a "mixed" basis and the guard as evidence. A Next.js matcher is read as a path pattern, so a negative lookahead excludes its listed prefixes. Django `LoginRequiredMiddleware` in any settings module makes plain Django views authenticated unless marked `login_not_required`; DRF views (`APIView`, `@api_view`, viewsets) are exempt from it, as DRF itself exempts them. DRF permissions are read from the syntax tree of any module holding `INSTALLED_APPS` or `REST_FRAMEWORK` (comments never count; test, local and development settings modules are used only when no other settings module exists, and production modules that disagree give a "mixed" basis): `IsAuthenticated` requires sign-in, `IsAdminUser` requires an admin, and `IsAuthenticatedOrReadOnly` leaves `GET`, `HEAD` and `OPTIONS` public, so a view that serves both reads and writes gets a "mixed" basis. Each public answer records whether it rests on an explicit marker, on absence, or on a mixed answer.
10. **Paid routes** follow helpers through the calling file's own definitions and imports, up to two calls deep, not only within one file. SDK names are read per file, including a client imported from another repository file (`from app.clients import client`, `import { openai } from "@/lib/openai"`). A method call is followed only when its receiver is an imported module, or an instance built from a class the file defines or imports, where the instance is assigned at module level (`ai_service = AIService()`, also when imported from its module) or in the calling function's own body before the call; assignments inside other functions and parameters (including `Depends(...)` defaults) are never used, and method calls on other objects are never followed. A helper matched by name alone (an import that cannot be read to its definition) makes `ABUSE-PAID-UNAUTH` INFERRED.
11. **`ABUSE-INMEMORY-LIMITER` also applies to multi-process deploys**, not only serverless hosting: two gunicorn workers keep two counters just as two functions do. The worker count or the serverless host's config file (for example `vercel.json`) is cited as a second location.
12. **`OWASP-A01-UNSCOPED-QUERY`**: a later comparison or non-logging call that uses both the caller and the loaded record counts as an ownership check and clears the finding; a later call that receives only the caller makes it INFERRED. Only models that belong to someone are reported (user-like models, owner or tenant columns, or a parent key to an owned model), so reference data is skipped, and so is a read lookup (`findUnique`, `findFirst`, `findMany`, `findOne`, `select`, `filter`, `get`) whose own filter has a top-level visibility key (`published`, `is_public`, `isPublic`, `visible`, `visibility`) set to a literal that means public (`True`, `true`, `1`, `"public"`, `"published"`), when the handler does not write to the loaded record afterwards. A value from the request, any other literal (`"team"`, `"members"`), a key inside `include`, `select` or a joined model, writes (`update`, `delete`, `upsert`) and a later write to the record (attribute assignment, `save`, `update`, `commit` or `delete` involving it) do not skip the lookup. On a public route the finding is INFERRED: the record type may be meant to be public. Form and body fields are not record identifiers. `OWASP-A01-GUESSABLE-ID` is reported only for owned models.
13. **`ABUSE-FORM-NO-CHALLENGE`** needs the route to be public and not a `GET`; `is_public_form` alone also marks signed-in upload routes. One finding per file lists every route.
14. **`ABUSE-ERROR-LEAK`** covers catch-all exceptions (`Exception`, `BaseException`, bare `except`); messages of narrow exceptions such as `ValueError` are usually written for users.
15. **`OWASP-A02-SECRET-IN-URL`** does not report `token=` in one-time links (reset, verify, confirm, invite, magic, activate, unsubscribe): that is the standard delivery for single-use tokens.
16. **`OWASP-A03-RAW-SQL`** skips Python files under Alembic and `migrations/` folders (JS and TS migration files are still read), and is CONFIRMED only when a request value, or a name assigned from one, is inside the SQL string's interpolations. A request value passed as a bound parameter does not count.
17. **`BASE-WEAK-HASH`** does not report a fast hash of a token, reset link, one-time code, nonce or API key, or of a value from `randomBytes` or `secrets.token_*`: storing a SHA-256 of a high-entropy random value is the recommended pattern. A password argument is still reported.
18. **`BASE-CSP-WEAK`** does not report `'unsafe-inline'` next to a nonce or hash source and `'strict-dynamic'`, because browsers that support nonces ignore it there.
19. **Route paths include router prefixes** for FastAPI and Flask, so tables read `/auth/register`. Review modules may define a `finish(ctx, section, findings)` hook to summarise their own findings.
20. **Snippets mask credential shapes** as well as key patterns: URL passwords with or without a user name, password flags on command lines, secret query parameter values (also a quoted value or a value concatenated as a separate literal) and literals assigned to password, secret, token or API key names, including adjacent, concatenated, escaped and triple-quoted literals, each masked on the whole line before the line is cut. The patterns use bounded repetition, so redaction stays linear on long minified lines. Credential rules mask their own Python literal by its source range, so it is hidden however it is spelled.
21. **tree-sitter 0.26 `Point.row`** corrupts memory past line 256. Helpers index points (`start_point[0]`) rather than read `.row` or `.column`.
22. **Rules added beyond the original tables**, from gaps found against a private comparison run: `BASE-LITERAL-PASSWORD-HASH`, `BASE-SEED-ON-START`, `BASE-SHORT-PASSWORD-MIN`, `BASE-SAMESITE-NONE-NO-CSRF`, `BASE-DB-NETWORK-OPEN`, `BASE-DB-ADMIN-LOGIN`, `BASE-HTTPS-NOT-ENFORCED`, `OWASP-A01-EMAIL-OWNERSHIP`, `OWASP-A01-PATH-TRAVERSAL`, `OWASP-A03-HTML-EMAIL`, `OWASP-A05-XML-PARSER`, `OWASP-A08-UNPINNED-DEPS`, `OWASP-A08-UNPINNED-INSTALL`, `ABUSE-LIMITER-NOT-APPLIED`, `ABUSE-LIMITER-PROXY-IP`, `ABUSE-UPLOAD-UNBOUNDED`, `LEAK-PUBLIC-GATE-KEY` and `LEAK-DEFAULT-CREDENTIAL`. Their rows are in sections 10.1 and 10.4 to 10.6.

### v0.2 refinements to this spec

Found by comparing v0.1.0 with a manual audit of a large Django repository, where about 95% of the findings were noise. The tables in section 10 already include them.

23. **Scan scope follows git.** In a git repository the index holds tracked files only (`git ls-files`). `--include-untracked` (`dpr.review(include_untracked=True)`) adds untracked files that git does not ignore (`git ls-files --others --exclude-standard`); ignored files are never read. A repository that tracks no file under the scanned folder yet is scanned as if the flag were set. When untracked files were left out, `not_covered` gives their count and three examples. Outside a git repository, or when git is unavailable, every file under the folder is walked as before and `not_covered` says so. Skipped directories and size limits are unchanged. Build output folders (section 7.1) are read whatever git says, because they are generated and usually ignored.
24. **"Committed" means tracked.** `INV-PII-FILE-IN-REPO` says a file is committed only when git tracks it (high). An untracked file scanned on request is "in the working folder, not committed" (medium, with a fix that moves the data out of the folder instead of rewriting history), and outside git the finding says whether it is committed is not known. `LEAK-COMMITTED-DATA-FILE` counts tracked files only, including the email check in tests and documentation. Any finding whose every location is an untracked file scanned on request ends its detail with "not tracked by git: it is in this working folder only". `LEAK-ENV-TRACKED` and `LEAK-ENV-IN-HISTORY` already read git directly and are unchanged.
25. **Vendored code.** A JS or CSS file is a copied library when its name matches `vendored_libs.yaml` (jQuery, Bootstrap, Select2, DataTables, PDF.js, Moment.js, Lodash and about 40 more; the version and `.min` are removed first), it is minified (`.min.js`, `.min.css`, or at least 4 KB with lines over 300 characters on average), or its header is a library banner (`/*!` at the start, `@license`, `@preserve`, a webpack bootstrap). A whole folder is vendored when it is named after a known library and holds no `.py`, `.ts`, `.tsx`, `.jsx`, `.vue` or `.svelte` file, is a child of a third-party folder (`third-party`, `third_party`, `vendors`, `bower_components` and similar), or holds its own `LICENSE` or `COPYING` file with no project manifest (`package.json`, `pyproject.toml`, `setup.py`, `requirements.txt`, `manage.py` and similar) anywhere below it, such as a Django app copied from another project. Collected static output (`staticfiles`, or a `static` folder that holds Django admin's collected `admin/js/core.js`) is vendored too, but only the libraries inside it are named. Sink rules skip vendored files: `OWASP-A03-XSS-SINK`, `OWASP-A03-COMMAND`, `OWASP-A03-RAW-SQL`, `OWASP-A02-SECRET-IN-URL`, `OWASP-A02-WEAK-RANDOM-TOKEN`, `OWASP-A08-UNSAFE-DESERIALISE`, `OWASP-A08-NO-SRI`, `LEAK-LOGGED-PII`, and `LEAK-SOURCEMAP` for maps under a vendored folder. Key patterns (`LEAK-HARDCODED-KEY`, `LEAK-KEY-IN-BUILD`) and route, settings and access rules still read them. Each library is reported once as `OWASP-A06-VENDORED-LIB` (section 10.5), keyed by name and version, or by folder; the register groups them into one issue per app root.

## 4. Non-negotiable rules, enforced in code

| Skill rule | Enforcement |
|---|---|
| Inventory, not legal advice | Report renderer test fails if output matches `compliant with`, `complies with`, `satisfies Article`, `satisfies Section`, `lawful basis is`. Templates contain the fixed disclaimer. |
| Evidence tag on every finding | `Finding.tag` is required. `Finding.__post_init__` raises `ValueError` if tag is CONFIRMED and `locations` is empty. |
| Never upgrade a tag | Tags are set once at creation. `Finding` is a frozen dataclass. Dedupe chooses between existing findings and never changes a tag. |
| Static analysis by default | The only network calls are: live header read (needs `--url` and `--i-own-this-host`), Semgrep's own download of registry rules when Semgrep is installed and no local rules folder is given (`--semgrep DIR` avoids it), and audits (needs `--with-audit`). A test patches `socket.socket.connect` and asserts the `dpr` process opens no connection in a run with `semgrep="off"`, no `url`, and no audits. |
| Never print a secret value | Matchers replace the matched secret span with `<redacted:KIND>` before building any object. `Finding` has no raw-match field. Every snippet also masks credential shapes on the whole line before cutting it (refinement 20 in section 3). Tests assemble fake keys and a corpus of credential shapes at runtime, run all formats and CLI output, and assert none of the values appear. Semgrep results from secret rules have `extra.lines` dropped. |
| Report is sensitive | `dpr.review()` writes nothing. Only the CLI writes, to `<PATH>/data-protection-review/` by default. The CLI prints a gitignore hint if that folder is not ignored. It never edits `.gitignore` and never runs `git add` or `git commit`. |
| Rank by risk removed per minute | Section 6.3. |

## 5. Architecture

### 5.1 Public API

```python
import dpr

report = dpr.review(
    path="/path/to/repo",
    reviews=("all",),              # or ("leaks", "rls") or (2, 5)
    answers="dpr-answers.yaml",    # path, dict, or None
    url=None,                      # live header read
    owns_host=False,               # must be True when url is set
    login_path=None,               # default: detected from routes, else /login
    with_audit=False,
    semgrep="auto",                # "auto" | "off" | path to local rules dir
    db_dump=None,                  # path to pasted pg_tables / pg_policies output
    include_untracked=False,       # in git, also scan untracked files git does not ignore
)

report.findings        # list[Finding], ranked
report.detection       # Detection
report.sections        # dict[str, ReviewSection], keyed by review slug
report.questions       # list[QuestionResult], answered and open
report.not_covered     # list[str]
report.meta            # project name, scope, git sha or "uncommitted working tree", date, reviews run, method

dpr.render_markdown(report) -> str
dpr.render_json(report) -> str
dpr.render_sarif(report) -> str
```

`dpr.review()` has no side effects on disk.

### 5.2 Run pipeline

1. **Walk.** Build a `RepoIndex` of files once (section 7.1).
2. **Discover.** Produce `Detection` (section 8).
3. **Select reviews.** Resolve numbers and slugs. Drop reviews that do not apply and record why in `not_covered`. `rls` applies only when SQL table definitions, a Supabase client, or a `--db-dump` exist.
4. **Questions.** Merge the question ids of the selected reviews, drop those answered by detection, fill from the answers source, mark the rest UNKNOWN (section 9).
5. **Run reviews.** Each review is `run(index, detection, answers) -> ReviewResult(findings, section)`. Reviews read other reviews' results only through `Detection` and a shared read-only `Facts` store filled in a fixed order: leaks, rls, baseline, auth, owasp, abuse, inventory. Inventory runs last because it consumes logged-PII and SDK facts.
6. **Adapters.** Semgrep and audits run inside the owasp review. Live headers run inside the baseline review.
7. **Dedupe and rank** (section 6.3, 6.4).
8. **Return** `Report`.

### 5.3 Package layout

```
app-prep/
  pyproject.toml
  uv.lock
  src/dpr/
    __init__.py            review, render_markdown, render_json, render_sarif
    api.py                 review() pipeline
    cli.py                 argparse entry point: scan, questions
    model.py               Finding, Location, Tag, Severity, Exploitability, Report, ReviewSection
    rank.py                scoring and dedupe
    rules.py               rule decorator and registry
    walk.py                RepoIndex
    parsing/
      jsts.py              tree-sitter wrapper, query helpers
      pyast.py             ast helpers
      sql.py               statement splitter and schema state
      prisma.py            schema.prisma parser
      schemas.py           model extraction: Prisma, SQL, Django, SQLAlchemy, Drizzle
      routes.py            route extraction per framework
    discovery/
      detect.py            Detection builder
    reviews/
      inventory.py
      rls.py
      auth.py
      baseline.py
      owasp.py
      leaks.py
      abuse.py
    adapters/
      semgrep.py
      audits.py
      headers.py
    questions/
      catalogue.py
      prompt.py
    report/
      markdown.py
      templates/report.md.j2
      json_out.py
      sarif.py
    data/
      pii_terms.yaml       personal data terms by category
      secrets.yaml         key patterns and secret-name words
      sdks.yaml            SDK names, category, data recipient, paid
      costs.yaml           default limits per paid category
      weights.yaml         severity, exploitability weights, A01 boost
      questions.yaml       question catalogue
      rule_text.yaml       attack, blast, fix, verify templates per rule id
  tests/
  docs/superpowers/specs/
  tasks/
  .github/workflows/ci.yml
```

No module over about 400 lines. A review that grows past that splits into a package (`reviews/owasp/a01.py` and so on).

### 5.4 Dependencies

Runtime: `tree-sitter`, `tree-sitter-javascript`, `tree-sitter-typescript`, `pyyaml`, `jinja2`. Everything else is stdlib, including `urllib` for header reads and `argparse` for the CLI.

Dev: `pytest`, `pytest-cov`, `ruff`.

Optional, not declared as dependencies: `semgrep`, `npm`, `pip-audit`, `git`. Each is looked up with `shutil.which` and recorded as not run when missing.

## 6. Data model

### 6.1 Finding

```python
@dataclass(frozen=True)
class Location:
    file: str          # repo-relative, forward slashes
    line: int          # 1-based
    end_line: int | None = None

@dataclass(frozen=True)
class Finding:
    rule_id: str               # e.g. "LEAK-PUBLIC-SECRET"
    review: str                # slug
    title: str
    tag: Tag                   # CONFIRMED | INFERRED | UNVERIFIED | UNKNOWN
    severity: Severity         # critical | high | medium | low
    exploitability: Exploitability  # high | medium | low
    effort_minutes: int
    locations: tuple[Location, ...]
    snippet: str | None        # redacted source excerpt, max 5 lines
    detail: str                # what was found, one short paragraph
    proof_needed: str | None   # required when tag is INFERRED
    attack: str | None
    blast: str | None
    fix: str                   # exact change, diff, or SQL
    verify: str | None         # command the user runs
    owasp: str | None          # "A01" .. "A10"
    source: str = "dpr"        # "dpr" | "semgrep:<rule id>" | "npm-audit" | "pip-audit"
    refs: tuple[str, ...] = () # related rule ids for cross-references
```

Validation in `__post_init__`: CONFIRMED requires at least one location. INFERRED requires `proof_needed`.

### 6.2 Tags

| Tag | Set when |
|---|---|
| CONFIRMED | A parser or exact read proves it at a cited location. |
| INFERRED | A regex or heuristic matched, or a parser matched but a helper call or later check could change the answer. `proof_needed` says what would settle it. |
| UNVERIFIED | Needs a runtime or dashboard check. |
| UNKNOWN | A question with no answer. |

### 6.3 Ranking

`score = severity_weight * exploitability_weight * boost / max(effort_minutes, 1)`

Default `weights.yaml`:

```yaml
severity: {critical: 100, high: 40, medium: 10, low: 3}
exploitability: {high: 3, medium: 2, low: 1}
tag_factor: {CONFIRMED: 1.0, INFERRED: 0.6, UNVERIFIED: 0.4}
boost: {A01: 1.5}
leaks_order: [LEAK-PUBLIC-SECRET, LEAK-HARDCODED-KEY, LEAK-KEY-IN-BUILD, LEAK-ENV-TRACKED, LEAK-ENV-IN-HISTORY, LEAK-BROAD-RESPONSE, LEAK-SSR-PROPS, LEAK-LOGGED-PII]
```

`tag_factor` multiplies the score. UNKNOWN items are questions, not findings, and are not ranked. Within the leaks review section, findings are ordered by `leaks_order` first, then score. The report summary's "top three fixes" is the top three by score across all reviews.

### 6.4 Dedupe

Two passes:

1. Within `dpr` rules: key `(rule_id, first location file, first location line)`. Duplicates come from a rule matching the same line twice; keep the first.
2. Between Semgrep and `dpr`: a Semgrep finding is dropped when a `dpr` finding has the same `owasp` category and the same first location file and line. The `dpr` finding gains the Semgrep rule id in `refs`.

Dedupe chooses which existing finding survives. It never edits a tag.

### 6.5 Report sections

Each review returns a `ReviewSection` holding the tables and text blocks its part of the report template needs (for example the RLS table protection status rows, or the inventory data map rows). Section shapes are defined per review in section 10.

## 7. Walking and parsing

### 7.1 RepoIndex

- Skipped directories: `node_modules`, `.git`, `.next`, `dist`, `build`, `out`, `vendor`, `.venv`, `venv`, `__pycache__`, `.turbo`, `coverage`, `.pytest_cache`, `.mypy_cache`, `data-protection-review`, `site-packages`, and any directory that holds a `pyvenv.cfg` file (a virtualenv under any name, such as `.env/` or `env/`).
- Build output directories (`dist`, `build`, `out`, `.next/static`) are indexed separately as `build_files` and read only by the leaks review.
- In a git repository only tracked files are indexed, plus untracked files that git does not ignore with `--include-untracked`; outside git every file is walked (refinement 23 in section 3). Build output directories are read whatever git says.
- Symlinks are not followed.
- Binary files (null byte in the first 8 KB) are skipped.
- Source files over 1 MB are skipped and listed in `not_covered`. Build files up to 10 MB are scanned with key regexes only.
- Text read as UTF-8 with `errors="replace"`; a leading byte order mark is dropped (`utf-8-sig`).
- Parsed trees are cached per file for the run.

**Sanity check.** If a `package.json`, `pyproject.toml` or `requirements*.txt` is present and no supported source file was indexed at all (no JS/TS/Vue/Svelte file and no `.py` file), raise `ScanError`. A Python repository with a tooling-only `package.json`, or a JS repository with a docs `requirements.txt`, scans normally. This is the silent empty-scan failure the skill hit.

### 7.2 JS/TS

tree-sitter grammars `javascript`, `typescript`, `tsx`. `.vue` and `.svelte` files: extract each `<script>` block, parse it as `ts` when `lang="ts"` else `javascript`, and add the block's start line offset to every location.

Helpers: find call expressions by callee path (`prisma.*.findUnique`), read object literal keys and values, resolve a local `const` to its initialiser within the same function, list exported function names, find string literals matching a pattern.

### 7.3 Python

stdlib `ast`. Files that fail to parse are listed in `not_covered`. Helpers mirror 7.2: calls by dotted name, keyword arguments, class bases, decorators, assignments in module scope.

### 7.4 SQL

A statement splitter that respects single quotes (with backslash escapes inside `E'...'` strings), double-quoted identifiers, dollar quoting (`$$` and `$tag$`), `--` and `/* */` comments. Recognised statements:

- `CREATE TABLE` (columns and types, schema, primary key)
- `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` and `DISABLE`
- `CREATE POLICY`, `ALTER POLICY`, `DROP POLICY` (name, table, permissive, command, roles, `USING`, `WITH CHECK`)
- `CREATE VIEW` / `CREATE OR REPLACE VIEW` (options including `security_invoker`, source tables)
- `CREATE FUNCTION` / `CREATE OR REPLACE FUNCTION` (`SECURITY DEFINER`, `SET search_path`, tables referenced in body)
- `INSERT INTO storage.buckets` (id, `public`)
- `GRANT ... TO anon | authenticated | public`
- `DROP TABLE`

Migration files are applied in filename order to a `SchemaState`. Sources: `supabase/migrations/*.sql`, `migrations/**/*.sql`, `prisma/migrations/*/migration.sql`, `db/**/*.sql`, `schema.sql`.

Predicates (`USING`, `WITH CHECK`) are kept as normalised text (lowercased outside string literals, whitespace collapsed) and inspected with targeted patterns, not a full expression parser.

### 7.5 Prisma

Line parser for `model` blocks: field name, type, optional/list markers, attributes (`@id`, `@unique`, `@default(autoincrement())`, `@relation(... onDelete: Cascade)`, `@map`), and block attributes (`@@map`, `@@unique`).

### 7.6 Schema extraction

`schemas.py` returns a common `Model(name, table, source, fields[Field(name, type, unique, location)])` from Prisma, SQL `SchemaState`, Django (`models.Model` subclasses), SQLAlchemy (classes with `__tablename__`, `Column` or `mapped_column`), and Drizzle (`pgTable`, `mysqlTable`, `sqliteTable` calls).

### 7.7 Routes

`routes.py` returns `Route(method, path, file, line, framework, is_public_form, wrappers, handler_node)`:

All Next.js paths below are also matched under `src/`.

- Next.js app router: `app/**/route.{js,ts}` exported `GET`, `POST`, `PUT`, `PATCH`, `DELETE`. Path from folders, `[id]` kept as `:id`, route groups `(name)` removed.
- Next.js server actions: functions in files starting with `"use server"`. Method recorded as `ACTION`.
- Next.js pages router: `pages/api/**`. Method `ANY` unless the handler branches on `req.method`.
- Express and Fastify: `app.<method>(` and `router.<method>(` calls.
- Django: `path()` and `re_path()` in `urls.py`, resolved to the view function or class in the same app where possible. DRF `router.register`.
- FastAPI: `@app.<method>` and `@router.<method>` decorators.
- Flask: `@app.route` and `@bp.route` with `methods=`.

Handlers passed through a wrapper call, such as `export const POST = withAuth(async () => ...)` or `router.get('/x', auth, asyncHandler(async (req, res) => ...))`, are unwrapped to the last function argument, and `export { handler as GET, handler as POST }` is followed to `handler`. A wrapper call with no function argument is kept as the handler. `wrappers` lists the wrapper callees, outermost first, and for Express and Fastify it starts with the middleware names between the path and the handler (Fastify `onRequest`, `preParsing`, `preValidation` and `preHandler` options included).

`is_public_form` is true when the path or handler name contains `signup`, `sign-up`, `register`, `login`, `signin`, `reset`, `forgot`, `contact`, `waitlist`, `newsletter`, `feedback`, `invite`, `upload`.

## 8. Discovery

`Detection` fields:

| Field | Source |
|---|---|
| `languages` | file counts per language |
| `frameworks` | dependency names in `package.json`, `pyproject.toml`, `requirements*.txt`, plus file signals (`next.config.*`, `manage.py`) |
| `databases`, `orms` | dependencies and schema files |
| `auth_providers` | dependencies and imports: Supabase auth, Clerk, Auth0, NextAuth / Auth.js, Firebase auth, Passport, Lucia, Better Auth, Django auth, FastAPI security utilities; hashing libraries |
| `env_vars` | names from every `.env*` file in the repo root and app folders, and code references (`process.env.X`, `import.meta.env.X`, `os.environ["X"]`, `os.getenv("X")`, `env("X")` from django-environ). Env files are read line by line and only the text before `=` is kept; the rest of the line is discarded before any object is built, and the safety test covers this. Each name has `public: bool` from prefixes `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `PUBLIC_`, `NUXT_PUBLIC_`, `EXPO_PUBLIC_`, `GATSBY_`, and the files and lines it appears in. |
| `public_supabase_key` | true when a public-prefixed env name contains `SUPABASE` |
| `sdks` | `sdks.yaml` matched against dependencies and imports, with call-site locations |
| `routes` | section 7.7 |
| `models` | section 7.6 |
| `hosting` | `vercel.json`, `netlify.toml`, `fly.toml`, `render.yaml`, `railway.json`, `app.yaml`, `Procfile`, `Dockerfile`, `docker-compose.yml`, `serverless.yml`, `*.tf` |
| `ci` | `.github/workflows/*` |
| `logging` | logger libraries and Sentry init locations |
| `header_config` | files that set security headers |
| `rate_limiters` | limiter libraries and call sites |
| `test_frameworks` | jest, vitest, playwright, pytest, django test runner |
| `git` | is repo, HEAD sha or `uncommitted working tree`, via `git` subprocess when present |
| `serverless` | true when hosting is Vercel, Netlify, or `serverless.yml` / Lambda handlers exist |

The detection table in the report shows: language and framework, database and ORM, auth provider, hosting, API route count, third-party SDK count, RLS or policy files present, rate limiting present, security headers configured. It then lists which reviews apply and which do not, with the reason.

## 9. Questions and answers

`questions.yaml` entries:

```yaml
- id: db_region
  reviews: [inventory]
  text: Which region are the database, object storage and backups provisioned in?
  type: choice            # choice | multi | text
  options_from: hosting   # detection field used to build options
  static_options: []
  honest_out: ["Not sure"]
  answered_by: null       # detection key that answers it, if any
  lawyer: true            # also listed for the data protection lawyer
```

v1 catalogue (merged and deduped from the skill's "Cannot be determined from code" lists):

| id | Reviews |
|---|---|
| `user_countries` | inventory |
| `company_country` | inventory |
| `db_region` | inventory |
| `retention_policy` | inventory |
| `prod_access` | inventory |
| `dpas_in_place` | inventory |
| `data_outside_repo` | inventory |
| `frontend_key_type` | rls |
| `rls_via_dashboard` | rls |
| `tables_not_in_migrations` | rls |
| `buckets_public` | rls |
| `provider_email_templates` | auth |
| `provider_session_lifetimes` | auth |
| `edge_protection` (CDN or WAF headers, rate limits, blocking) | auth, baseline, owasp, abuse |
| `provider_hash_params` | baseline |
| `tls_termination` | baseline |
| `prod_config_matches_repo` | owasp |
| `hosting_env_not_in_repo` | leaks |
| `log_tool_access_retention` | leaks |
| `traffic_peak` | abuse |
| `spend_caps` | abuse |
| `alert_channel` | abuse |

Answers source, in order: the `answers` dict or YAML file (keys are question ids, unknown keys produce a warning), then `--interactive` prompts on a TTY for up to 8 remaining questions in catalogue order, then UNKNOWN. A value of `"Not sure"` or `"No formal policy"` is recorded as UNKNOWN with that wording kept.

`dpr questions PATH` runs discovery only and writes `dpr-answers.yaml` with the open questions for that repo as commented entries, options included.

Lawyer questions: the 11 from the skill's inventory reference, each mapped to the question ids or detection fields that answer it. Rendered in the three groups of the report template: answered by this review, still open (with why the repo cannot answer and who can), and for the data protection lawyer.

## 10. Reviews

Each subsection lists rule ids with default tag, severity and exploitability. Effort minutes and fix text come from `rule_text.yaml`.

### 10.1 Leaks (`leaks`, review 6)

| Rule | Detects | Tag | Sev | Expl |
|---|---|---|---|---|
| `LEAK-PUBLIC-SECRET` | Public-prefixed env name containing a secret word from `secrets.yaml` (`SERVICE_ROLE`, `SECRET`, `PRIVATE`, `ADMIN`, `WEBHOOK_SECRET`, `DATABASE_URL`, `DB_URL`, `SMTP`, `PASSWORD`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `AWS_SECRET`, `ACCESS_KEY`) at a code reference or example env file line | CONFIRMED | critical | high |
| `LEAK-HARDCODED-KEY` | Key pattern in indexed source: `sk_live_`, `rk_live_`, `sk_test_`, `sb_secret_`, `xox[baprs]-`, `AKIA[0-9A-Z]{16}`, `ghp_`, `gho_`, `github_pat_`, `AIza[0-9A-Za-z_-]{35}`, JWTs whose decoded payload has `role: service_role` | CONFIRMED | critical (test keys: high) | high |
| `LEAK-KEY-IN-BUILD` | Same patterns in `build_files` | CONFIRMED | critical | high |
| `LEAK-ENV-TRACKED` | `git ls-files` lists `.env*` other than `.example`, `.sample`, `.template`. The file's variable names are read (never values) | CONFIRMED | critical when a name is not public-prefixed or looks secret, or the file cannot be read (for example tracked but deleted from the working tree); low when every name is public-prefixed and not secret-like, with the note that frameworks such as Next.js commit these on purpose | high |
| `LEAK-ENV-IN-HISTORY` | `git log --all --diff-filter=A --name-only` shows such a file was ever added | CONFIRMED | high | medium |
| `LEAK-SOURCEMAP` | `*.map` in build output (not under a vendored library folder), `productionBrowserSourceMaps: true`, Vite `build.sourcemap: true` | CONFIRMED | medium | medium |
| `LEAK-BROAD-RESPONSE` | Route returns a whole record: `NextResponse.json(x)` / `res.json(x)` where `x` comes from an ORM call without `select`; DRF serializer `fields = "__all__"`; `select *` or Supabase `.select('*')` in a route | INFERRED | high if the model has a sensitive column (`password`, `hash`, `token`, `secret`, `stripe_customer_id`, `role`), else medium | medium |
| `LEAK-SSR-PROPS` | `getServerSideProps` / loader returning an ORM result without `select` | INFERRED | medium | medium |
| `LEAK-LOGGED-PII` | `console.log/error`, `logger.*`, `print`, `logging.*` with an argument named or rooted in `req`, `request`, `body`, `user`, `token`, `payload`, `headers`, `err` / `e` of a DB call; `traceback.print_exc()` | INFERRED | medium | low |
| `LEAK-SENTRY-PII` | `sendDefaultPii: true`, `send_default_pii=True`, or Sentry init without `beforeSend` / `before_send` | CONFIRMED | medium | low |
| `LEAK-PUBLIC-GATE-KEY` | Public-prefixed env name that reads as an access gate (`BYPASS`, `UNLOCK`, `OVERRIDE`, `MASTER_KEY`, `ACCESS_CODE`, `INVITE_CODE`, `MAINTENANCE_KEY` and similar), citing any committed value's location | CONFIRMED | low | medium |
| `LEAK-DEFAULT-CREDENTIAL` | Committed default credentials in compose files, scripts and docs: literal secret-named compose values, shell defaults such as `${DB_PASSWORD:-value}`, connection URLs with an inline password, password flags on command lines. Reports locations only, never the value | CONFIRMED | low | low |

Every key finding's fix text starts with "Rotate the key now. It already reached a browser or history; removing it from the next build does not undo that." The key value is never included; the finding names the variable or key kind and the location.

Section shape: leak blocks in the skill's output format.

### 10.2 RLS (`rls`, review 2)

Input: `SchemaState` from migrations and, when given, `--db-dump`.

| Rule | Detects | Tag | Sev | Expl |
|---|---|---|---|---|
| `RLS-TABLE-OFF` | Table in `public` schema never enabled, or disabled last | CONFIRMED | critical when `public_supabase_key` is true, else high with a reduced-relevance note | high |
| `RLS-NO-POLICIES` | Enabled, zero policies | CONFIRMED | low | low |
| `RLS-SELECT-ONLY` | Select policies only (deviation 1 in section 3) | CONFIRMED | low | low |
| `RLS-POLICY-TRUE` | `USING (true)` on a table with an owner or tenant column | CONFIRMED | high | high |
| `RLS-AUTHENTICATED-NOT-OWNER` | Predicate only checks `auth.role() = 'authenticated'`, or `TO authenticated` with a predicate that never references `auth.uid()` or `auth.jwt()`. Like `RLS-POLICY-TRUE`, only on tables with an owner or tenant column, or with unknown columns (dump only) | CONFIRMED, or INFERRED when the predicate calls a helper function | high | high |
| `RLS-WEAK-WITH-CHECK` | `INSERT`, `UPDATE` or `ALL` policy on a table with an owner column whose `WITH CHECK` is present and references neither the owner column, `auth.uid()` nor `auth.jwt()` (deviation 2 in section 3) | CONFIRMED, or INFERRED when the `WITH CHECK` calls a helper function | high for `INSERT`; for `UPDATE` and `ALL`, low when the table has select policies and every select policy on the table references the owner column or `auth.uid()`, else high | high |
| `RLS-WRONG-ROLE` | Write policy granted `TO public` or `TO anon` on a table with an owner column | CONFIRMED, or INFERRED when the predicate calls a helper function | high | high |
| `RLS-CLIENT-OWNER` | Predicate reads `user_metadata` from `auth.jwt()`, or `current_setting('request.headers'` | CONFIRMED | high | high |
| `RLS-TENANT-UNBOUND` | Predicate has a subquery over a membership-like table (`member`, `membership`, `org_users`, `team_users`) filtered by `auth.uid()` but never references the policy table's tenant column (`org_id`, `organization_id`, `tenant_id`, `workspace_id`, `team_id`) | INFERRED (the membership match is a heuristic); when the predicate calls a helper function, `proof_needed` asks to read that function | high | high |
| `RLS-VIEW-BYPASS` | View in `public` over an RLS table without `security_invoker = true` | CONFIRMED | high | high |
| `RLS-DEFINER-FUNCTION` | `SECURITY DEFINER` function in `public`; severity high if its body reads an RLS table, plus a note when `search_path` is not set | CONFIRMED | medium or high | medium |
| `RLS-PUBLIC-BUCKET` | `storage.buckets` row with `public = true`, or `createBucket(..., { public: true })` | CONFIRMED | medium | medium |

Policy checks that look for a policy granting too much (`RLS-POLICY-TRUE`, `RLS-AUTHENTICATED-NOT-OWNER`, `RLS-WEAK-WITH-CHECK`, `RLS-WRONG-ROLE`, `RLS-TENANT-UNBOUND`) ignore restrictive policies, which cannot grant access, and policies granted only to `service_role`, `postgres` or `supabase_admin`, which clients do not use. The select policies counted for `RLS-WEAK-WITH-CHECK` severity are the permissive `SELECT` and `ALL` policies left after the same filter. A helper function is any function call in the predicate other than `auth.uid()`, `auth.jwt()` and `auth.role()`; its `proof_needed` is "Read the called function to confirm it checks the row owner or tenant." `ALTER TABLE ... RENAME TO` moves the table, its policies and its RLS flag to the new name.

Owner column detection: `user_id`, `owner_id`, `created_by`, `author_id`, `profile_id` (first match wins). Tenant column: list above.

Generated SQL per gap: `alter table ... enable row level security;` plus select, insert, update, delete policies using `auth.uid() = <owner column>`, or `<tenant column> in (select <tenant column> from <membership table> where user_id = auth.uid())` when a tenant column and membership table exist. When no owner or tenant column exists, the fix says so and gives the enable statement only, with a comment to choose the predicate.

Breakage note: routes from detection that query the table through the Supabase client are listed as "queries that may start returning nothing after this change".

Section shape: table `table | RLS enabled | policy count | reachable by anon key | verdict | evidence`, policy defects, missing policies (SQL), the two `pg_tables` / `pg_policies` queries when migrations are absent or incomplete, and outside confirmation commands (`curl` against `/rest/v1/<table>` with `$ANON_KEY`, pass and fail described). `dpr` never runs these commands.

When the data layer is Prisma or another server-only ORM and no public client key is detected, the section states reduced relevance and emits no RLS findings.

`--db-dump` accepts psql aligned output or CSV of the two queries. Findings from it use `Location(file="<dump file>", line=<row line>)`.

### 10.3 Auth failure path test plan (`auth`, review 3)

The ten cases from the skill are fixed templates with Expected text. Each case has detector functions that set "This app".

| Case | Detectors | Possible result |
|---|---|---|
| 1 Wrong password five times | limiter on the login route; lockout fields (`failed_attempts`, `locked_until`); `django-axes` | INFERRED |
| 2 Reset for unregistered email | string literal matching `no (account\|user) (found\|exists\|with)`, `not registered`, `does(n't\| not) exist` in reset handlers or UI | CONFIRMED fail when found, else UNVERIFIED |
| 3 Verification link twice | token model has `used_at` / `consumed` / `verified_at`, or token deleted in the verify handler | INFERRED |
| 4 Signup with existing email | string literal matching `already (registered\|exists\|in use\|taken)` | CONFIRMED fail when found, else UNVERIFIED |
| 5 Session left open | cookie `maxAge` / `expires`; JWT `expiresIn`; NextAuth `session.maxAge`; Django `SESSION_COOKIE_AGE`; cookie flags | CONFIRMED values |
| 6 Expired reset link | server-side expiry comparison in the reset handler | INFERRED |
| 7 Reset token for someone else | reset handler reads both `email` and `token` from the body and updates by `email` | INFERRED fail |
| 8 Concurrent signup | unique constraint on the email field | CONFIRMED pass or fail |
| 9 Email change | handler writes `email` directly with no verification token step | INFERRED fail |
| 10 Logout and back button | logout only clears client storage; `Cache-Control: no-store` on authenticated responses | INFERRED |

When a managed provider handles a case, "This app" says so and the result is UNVERIFIED with the provider named.

Failed cases also become findings `AUTH-CASE-<n>` so they rank with everything else. Case 2 and 4 findings carry `refs` to the baseline enumeration note instead of duplicating it.

Section shape: one block per case (`CASE n`, Expected, This app, Risk, Test), failing cases first by exploitability.

### 10.4 Baseline (`baseline`, review 4)

| Rule | Detects | Tag | Sev | Expl |
|---|---|---|---|---|
| `BASE-COOKIE-HTTPONLY` / `-SECURE` / `-SAMESITE` | Parsed cookie set calls: Next `cookies().set`, `res.cookie`, `Set-Cookie` literals, `response.set_cookie`, Django `SESSION_COOKIE_*` / `CSRF_COOKIE_*` | CONFIRMED | high for session-like names (`sid`, `session`, `token`, `auth`, `jwt`), else low | medium |
| `BASE-HEADER-MISSING-<NAME>` | HSTS, CSP, X-Content-Type-Options, frame protection, Referrer-Policy, Permissions-Policy not set on a header surface; each static host config and app is judged on its own (refinement 7 in section 3) | UNVERIFIED, CONFIRMED with `--url` | HSTS high, CSP medium, others low | low |
| `BASE-CSP-WEAK` | `unsafe-inline` in `script-src` (not when a nonce or hash source and `'strict-dynamic'` are present), or `default-src *` | CONFIRMED | medium | medium |
| `BASE-VERSION-DISCLOSURE` | Next `poweredByHeader` not false; Express without `app.disable('x-powered-by')` or helmet; live `Server` / `X-Powered-By` with a version | INFERRED, CONFIRMED with `--url` | low | low |
| `BASE-WEAK-HASH` | `md5`, `sha1`, `sha256` via `hashlib` or `crypto.createHash` inside a function or on a variable whose name contains `password`, except a hash of a token, reset link, one-time code, nonce, API key or `randomBytes` / `secrets.token_*` value when no password is hashed; Django `PASSWORD_HASHERS` first entry MD5 or SHA1 | INFERRED, CONFIRMED for Django setting | critical | medium |
| `BASE-NO-HTTPS-REDIRECT` | `--url` http root does not redirect to https | CONFIRMED | high | medium |
| `BASE-DEBUG-ON` | Django `DEBUG = True` as a literal in a settings module; `FastAPI(debug=True)`, `Flask(debug=True)` or `run(debug=True)`; a settings class whose `debug` defaults to `True` | INFERRED | high | medium |
| `BASE-MIXED-CONTENT` | `http://` asset URLs in `src`/`href` (excluding localhost, XML namespaces) | INFERRED | low | low |
| `BASE-CACHE-AUTH` | login page response without `Cache-Control: no-store` (live only) | CONFIRMED | low | low |
| `BASE-LITERAL-PASSWORD-HASH` | Password hashing calls (`get_password_hash`, `hash_password`, `make_password`, `bcrypt.hash`, a password context's `hash`) whose argument resolves to text written in the repository; copies of the same text elsewhere are found by SHA-256 digest and cited, never printed | CONFIRMED; INFERRED when the text is only an environment variable fallback | critical; high for a fallback | high |
| `BASE-SEED-ON-START` | A start command (shell start script, Procfile, Dockerfile `CMD`, platform start command, `package.json` start scripts) runs a seed step | INFERRED | critical when the seed file hashes committed passwords, else high | high |
| `BASE-SHORT-PASSWORD-MIN` | A password length check or schema minimum below 8 characters | CONFIRMED | low | low |
| `BASE-SAMESITE-NONE-NO-CSRF` | `SameSite=None` in configuration or code with no CSRF package, Django, or `csrf` reference anywhere in the code | INFERRED | low | medium |
| `BASE-DB-NETWORK-OPEN` | Terraform exposing a database: Azure firewall rules `0.0.0.0` to `0.0.0.0` (medium) or to `255.255.255.255` (high); security group ingress, `aws_security_group_rule` or `aws_vpc_security_group_ingress_rule` opening a database port to `0.0.0.0/0` or `::/0` (high); `publicly_accessible = true` (medium); Cloud SQL authorized network `0.0.0.0/0` (high). Commented-out values never count | CONFIRMED | medium or high | medium |
| `BASE-DB-ADMIN-LOGIN` | A Terraform connection string built from an admin or master login variable | INFERRED | medium | medium |
| `BASE-HTTPS-NOT-ENFORCED` | Azure web or function app without `https_only = true`, CloudFront `allow-all` viewers, HTTP load balancer listener without a redirect | CONFIRMED | low | low |

Password storage delegated to a managed provider is a section note, not a finding. Account enumeration is a section note referencing `AUTH-CASE-2` and `AUTH-CASE-4`.

Live header read (`adapters/headers.py`): only when `url` is set and `owns_host` is true, else `ScanError`. Exactly three `HEAD` requests: `https` root following redirects, `https` login path following redirects, `http` root without following redirects. 10 second timeout each. Failures become UNVERIFIED with the reason.

Section shape: fix blocks in the skill's format (`FIX n`, Where, Now, Change, Verify), ordered by score.

### 10.5 OWASP (`owasp`, review 5)

Own rules:

| Rule | Detects | Tag | Sev | Expl |
|---|---|---|---|---|
| `OWASP-A01-UNSCOPED-QUERY` | In a route handler, an identifier from the request (`params.id`, `req.params.*`, `searchParams.get`, FastAPI path parameter, Django view kwarg) reaches an ORM lookup (Prisma `findUnique/findFirst/update/delete`, Django `get/filter/get_object_or_404`, SQLAlchemy `session.get` / `filter`, Supabase `.eq`) whose filter has no session subject (`session.user.id`, `auth()`, `getServerSession`, `request.user`, `current_user`, `auth.uid`) | CONFIRMED when the filter literal is fully visible and the function has no later comparison against the session subject; INFERRED when a later call receives only the caller, the model is unknown, or the route is public (refinement 12 in section 3) | high | high |
| `OWASP-A01-UNGUARDED-METHOD` | Same route file: one exported method calls an auth check, another write method does not | CONFIRMED; INFERRED when the unguarded method is public only by absence and the app has a global auth mechanism the classifier cannot read | high | high |
| `OWASP-A01-MASS-ASSIGNMENT` | Request body passed whole into ORM create or update (`data: body`, `...body`, `**request.data`, `**payload.dict()`) | CONFIRMED when the model has `role`, `is_admin`, `org_id`, `plan`, `is_staff`; else INFERRED | high | high |
| `OWASP-A01-GUESSABLE-ID` | Model with autoincrement integer id used in a route path parameter | CONFIRMED | medium | medium |
| `OWASP-A01-CLIENT-ONLY-GUARD` | UI conditional on `isAdmin` / `role === 'admin'` while the matching admin API route has no role check | INFERRED | medium | medium |
| `OWASP-A02-WEAK-RANDOM-TOKEN` | `Math.random()` or `random.random/choice` assigned to a name containing `token`, `secret`, `code`, `otp`, `reset`, `nonce` | INFERRED | high | medium |
| `OWASP-A02-SECRET-IN-URL` | URL string built with `token=`, `password=`, `apikey=` query parameters | INFERRED | medium | low |
| `OWASP-A03-RAW-SQL` | `$queryRawUnsafe`, `$executeRawUnsafe`, string concatenation or f-string into `execute`, `.raw()`, `text()`; Python files under `alembic/` or `migrations/` are skipped | CONFIRMED when a request value, or a name assigned from one in the same function, is inside the string's interpolations; else INFERRED | high | high |
| `OWASP-A03-XSS-SINK` | `dangerouslySetInnerHTML` with a non-literal, `v-html`, `innerHTML =`, `{@html}` | INFERRED | high | medium |
| `OWASP-A03-COMMAND` | `child_process.exec` / `execSync` with a non-literal; `subprocess` with `shell=True` and a non-literal; `eval`, `new Function` | INFERRED | high | high |
| `OWASP-A04-CLIENT-PRICE` | Request body fields `price`, `amount`, `total`, `plan`, `isPaid`, `discount` passed to Stripe or an ORM write | INFERRED | high | high |
| `OWASP-A08-NO-SRI` | `<script src="https://...">` without `integrity` in HTML or JSX | CONFIRMED | low | low |
| `OWASP-A08-UNSAFE-DESERIALISE` | `pickle.loads`, `yaml.load` without a safe loader, `node-serialize` | INFERRED | high | medium |
| `OWASP-A08-CI-UNTRUSTED` | GitHub workflow on `pull_request_target` that checks out the PR head ref | CONFIRMED | high | medium |
| `OWASP-A09-NO-AUTH-FAIL-LOG` | Login handler failure branch has no logger call | INFERRED | low | low |
| `OWASP-A10-SSRF` | `fetch`, `axios`, `requests`, `httpx`, `urllib` called with a URL from the request in the same function with no host allowlist comparison | INFERRED | high | high |
| `OWASP-A01-EMAIL-OWNERSHIP` | A non-user model matched to the caller by comparing its email with the signed-in user's email | INFERRED | high | medium |
| `OWASP-A01-PATH-TRAVERSAL` | A request value (FastAPI parameter, Flask or Django path parameter, `request.files` / `request.form`, Express `req.body` / `req.params`, `originalname`) reaches a file write path, directly or through a helper, without `secure_filename`, `basename` or a resolved-path check. Parameters typed `int`, `float`, `bool`, `UUID`, `Decimal`, `date`, `datetime`, an `Enum` or a `Literal`, and `<int:>` / `<uuid:>` path converters, are not sources | CONFIRMED; INFERRED when the helper is one of several with the same name | high | medium |
| `OWASP-A03-HTML-EMAIL` | HTML f-strings in email code that insert values without `html.escape` | INFERRED | low | low |
| `OWASP-A05-XML-PARSER` | XML or spreadsheet parsing when the project does not declare `defusedxml` | INFERRED | low | low |
| `OWASP-A08-UNPINNED-DEPS` | `requirements*.txt` with at least half its entries unpinned and no lock file or hashes beside it; `package.json` with dependencies and no lock file in its folder or above | CONFIRMED | low | low |
| `OWASP-A08-UNPINNED-INSTALL` | `pip install` of unpinned packages in start scripts or CI, unpinned `npx` of scoped packages, `npm install` (not `npm ci`) in CI | CONFIRMED | low | low |
| `OWASP-A06-VENDORED-LIB` | A third-party library copied into the repository (refinement 25 in section 3), once per library: name, version when a file name, banner, `package.json`, `bower.json` or `__version__` shows it, and up to 10 file locations. Fix: manage it as a dependency and keep it updated | CONFIRMED when the name comes from the library list or a banner; INFERRED when only the file's shape, a third-party folder or a licence file marks it | low | low |

Sink rules (`OWASP-A03-XSS-SINK`, `OWASP-A03-COMMAND`, `OWASP-A03-RAW-SQL`, `OWASP-A02-SECRET-IN-URL`, `OWASP-A02-WEAK-RANDOM-TOKEN`, `OWASP-A08-UNSAFE-DESERIALISE`, `OWASP-A08-NO-SRI`) skip vendored files.

Shared findings: A05 debug and error exposure use `BASE-DEBUG-ON` and `ABUSE-ERROR-LEAK`; CORS uses the abuse rules; A07 references the auth review. These are cross-references, not duplicates.

Route classification table: every route marked public, authenticated, authenticated and ownership-checked, or admin, from the presence of auth calls, ownership predicates and role checks (refinement 9 in section 3). Used by A01 rules and printed in the section.

**Semgrep adapter.** When `semgrep` is `"auto"` and the binary exists, or a local rules path is given: `semgrep scan --json --metrics=off --timeout 30 --config p/owasp-top-ten --config p/javascript --config p/typescript --config p/python` (or `--config <local dir>`), scoped to the repo with the same skipped directories, overall timeout 300 seconds. Each result becomes a `Finding` with `source="semgrep:<check_id>"`, tag INFERRED, `owasp` parsed from `extra.metadata.owasp`, severity from `extra.severity` (`ERROR` high, `WARNING` medium, `INFO` low). Results without an OWASP mapping are kept under `A05`. The `lines` field is dropped for rules whose id or metadata mentions secrets. Semgrep's rules are downloaded from the Semgrep registry unless a local path is given; code is scanned locally.

**Audits.** With `with_audit`: `npm audit --omit=dev --json` when `package-lock.json` exists, `pip-audit -f json` against requirements or the project. Advisories become `OWASP-A06-VULN-DEP` findings, tag INFERRED, `proof_needed` "call path from the app to the vulnerable function was not traced". Without the flag, A06 lists only `OWASP-A06-VENDORED-LIB` findings and notes that the audit adapters did not run.

Section shape: finding blocks in the skill's format (`FINDING n`, Where, Attack, Blast, Fix) ordered by score, the route classification table, then categories reviewed with no finding.

### 10.6 Abuse and bill guard (`abuse`, review 7)

`costs.yaml` maps SDK categories (llm, email, sms, storage, image, browser, maps, payments) to a cost note and starting limits (`per_user`, `per_ip`, `window`) taken from the skill's example table.

| Rule | Detects | Tag | Sev | Expl |
|---|---|---|---|---|
| `ABUSE-PAID-UNAUTH` | Route whose handler, or a helper it reaches through its file's definitions or imports (up to two calls deep), calls a paid SDK, with no auth guard found for the route (refinements 9 and 10 in section 3) | CONFIRMED; INFERRED when the helper was matched by name only, or the route is public only by absence and the app has a global auth mechanism the classifier cannot read | critical | high |
| `ABUSE-PAID-UNLIMITED` | Paid route with no limiter reference in the handler file or matching middleware | INFERRED | high | high |
| `ABUSE-INMEMORY-LIMITER` | When more than one process or instance serves requests (a worker count above one, or serverless hosting): `express-rate-limit` or `express-slow-down` imported and called without `store`; a slowapi or Flask-Limiter `Limiter` whose storage is `memory://`, falls back to memory, or is not passed; a module-level `Map` counter. The worker count or the host's config file is the second location | CONFIRMED for `express-rate-limit` or `express-slow-down` without `store` and a literal `memory://`; INFERRED for a memory fallback, a counter `Map`, or storage that app config or the environment can set (`RATELIMIT_STORAGE_URI`), including settings that disagree; settings in test files never count | medium | medium |
| `ABUSE-FORM-NO-CHALLENGE` | `is_public_form` route with no Turnstile, hCaptcha or reCAPTCHA verification and no honeypot field | INFERRED | medium | medium |
| `ABUSE-CORS-WILDCARD` | `origin: '*'`, `Access-Control-Allow-Origin: *` on routes with auth, `CORS_ALLOW_ALL_ORIGINS = True`, FastAPI `allow_origins=["*"]` | CONFIRMED | high | medium |
| `ABUSE-CORS-REFLECT` | `origin: true`, `callback(null, true)` without an allowlist check, or `Access-Control-Allow-Origin` set from the request `Origin`; critical when credentials are allowed | CONFIRMED | high or critical | high |
| `ABUSE-CORS-LOOSE-REGEX` | Origin regex without `^` and `$` anchors | CONFIRMED | medium | medium |
| `ABUSE-ERROR-LEAK` | Response body built from `err.message`, `err.stack`, `str(e)`, `repr(e)`, `traceback.format_exc()` | CONFIRMED | medium | medium |
| `ABUSE-NO-KILL-SWITCH` | Paid SDK call sites with no env flag check nearby (`*_ENABLED`, `DISABLE_*`, feature flag call) | INFERRED | low | low |
| `ABUSE-LIMITER-NOT-APPLIED` | slowapi `Limiter(default_limits=...)` while `SlowAPIMiddleware` is never added | CONFIRMED | medium | medium |
| `ABUSE-LIMITER-PROXY-IP` | Limiter keyed on `get_remote_address`, or `express-rate-limit` without `keyGenerator`, on a hosted app with no forwarded-address trust configured anywhere | INFERRED | medium | medium |
| `ABUSE-UPLOAD-UNBOUNDED` | A route reads a whole `UploadFile` or `request.files` upload into memory with no size limit, or checks the size only after reading | CONFIRMED | low | medium |

Section shape: cost surface table (route, calls, cost note, auth, limited), limits table with numbers from `costs.yaml` marked "starting default, not measured traffic", an implementation snippet chosen by stack (Upstash rate limit for Next.js on Vercel, `express-rate-limit` with a Redis store for Express, `slowapi` for FastAPI, `django-ratelimit` for Django), CORS and error message rewrites, and alerts and kill switch text: rate-of-spend alert (hourly paid calls over 3 times the 7-day hourly average), provider-side hard caps, signup rate anomaly, error spike on paid routes, and a named env flag per paid route.

### 10.7 Inventory (`inventory`, review 1)

Field sources: models (7.6), validation schemas in signup, register and onboarding files (zod `z.object`, yup, Joi, pydantic `BaseModel`, DRF serializers, Django forms), and runtime-captured data (`x-forwarded-for`, `req.ip`, `request.client.host`, `REMOTE_ADDR`, `user-agent`, geolocation headers).

Matching: names split on camelCase and underscores into tokens, matched against `pii_terms.yaml` categories: identifiers, account, financial, technical, behavioural, content, inferred, special category, children, and South African identifiers (`id_number`, `sa_id`, `identity_number`, `passport_number`, `tax_number`).

| Rule | Detects | Tag | Sev | Expl |
|---|---|---|---|---|
| `INV-SPECIAL-CATEGORY` | Field in the special category list | CONFIRMED | high | low |
| `INV-CHILDREN-SIGNAL` | `age`, `date_of_birth` with minimum under 18, `parent`, `guardian`, `school`, `grade` fields | INFERRED | high | low |
| `INV-CATCHALL-JSON` | `json`/`jsonb` column or Prisma `Json` named `metadata`, `properties`, `custom_fields`, `extra`, `payload`, `raw`, `attributes`, `data` | CONFIRMED | medium | low |
| `INV-UNUSED-FIELD` | Personal data field whose name appears only in schema, migrations and at most one write | INFERRED | low | low |
| `INV-NO-DELETION-PATH` | Table with personal data and no delete path: no cascade, no scheduled job deleting it (`vercel.json` crons, Celery beat, GitHub `schedule`, `cron` libraries), no TTL | INFERRED | medium | low |
| `INV-SDK-RECEIVES-PII` | Call to a data-recipient SDK whose argument object has personal data keys (CONFIRMED) or is a whole user object (INFERRED) | CONFIRMED or INFERRED | medium | low |
| `INV-PII-FILE-IN-REPO` | `.csv` / `.json` whose header row or top-level keys match personal data terms. Called committed only when git tracks it (refinement 24 in section 3) | CONFIRMED | high; medium for an untracked file scanned with `--include-untracked` | medium |

Section shape: the data map table (`Field | What it is | Where collected | Where it lives | Third parties with a copy | Retention | Who internally can read it | Evidence`), one flow line per collection point (`signup form (file) -> users table -> Stripe customers.create -> Sentry on error`, tagged INFERRED because flows are joined by shared model and file references, not traced), "collected with no clear reason", "not covered by this repo", and the lawyer questions (section 9). Retention is "retained indefinitely, no deletion path found" or UNKNOWN; a period is never invented. Who can read: admin routes and roles found, remainder UNKNOWN.

## 11. Output

### 11.1 Markdown

Jinja2 template mirroring the skill's `report-template.md` section for section, with only the sections for reviews that ran, in review number order (1 to 7) regardless of run order. Header: project name, date, scope and git sha, reviews run, method (static analysis, plus header checks against the named URL with the owner's confirmation, plus Semgrep and audits when they ran). Fixed disclaimer paragraph. Summary counts by severity plus open question count. Top three fixes. Evidence tag legend. Detection table. Per-review sections. Open questions in three groups. What this review did not cover: systems outside the repo, production config differences, runtime behaviour, skipped files, rules that errored, adapters not run, Firebase rules if present.

### 11.2 JSON

`{"schema_version": 1, "meta": ..., "detection": ..., "findings": [...], "sections": ..., "questions": ..., "not_covered": [...]}`. Enums as lowercase strings (evidence tags stay uppercase, deviation 5 in section 3), locations as objects.

### 11.3 SARIF 2.1.0

One run, tool name `dpr`, one rule per `rule_id` (Semgrep rule ids kept). Level: critical and high `error`, medium `warning`, low `note`. Properties: `tag`, `severity`, `exploitability`, `owasp`, `review`. Questions are not included.

### 11.4 Files written by the CLI

`<out>/REPORT-YYYY-MM-DD.md`, `<out>/report-YYYY-MM-DD.json`, `<out>/report-YYYY-MM-DD.sarif`, for the requested formats. Default `out` is `<PATH>/data-protection-review/`. A same-day rerun overwrites. After writing, the CLI prints at most 15 lines: counts by severity, top three fixes, open UNKNOWN count, file paths, and the gitignore hint when applicable.

## 12. CLI

```
dpr scan [PATH]
    --reviews all | 1..7 | inventory rls auth baseline owasp leaks abuse   (default all)
    --answers FILE
    --interactive
    --url URL --i-own-this-host [--login-path PATH]
    --with-audit
    --semgrep auto|off|DIR        (default auto)
    --db-dump FILE
    --format md,json,sarif        (default md,json)
    --out DIR
    --fail-on critical|high|medium|none   (default none)
    --include-untracked           in git, also scan untracked files git does not ignore

dpr questions [PATH] [--out FILE]  (default FILE: <PATH>/dpr-answers.yaml)
```

Exit codes: `0` completed and nothing at or above `--fail-on`; `1` a finding at or above `--fail-on`; `2` `ScanError`, invalid arguments, or any other unexpected error (one line `dpr: error: <Type>: <message>` on stderr; with `DPR_STRICT=1` the exception is re-raised).

## 13. Error handling

| Situation | Behaviour |
|---|---|
| Path missing, sanity check fails, `--url` without `--i-own-this-host`, invalid answers YAML | `ScanError`, exit 2, one-line message |
| Unknown key in answers | Warning printed, key ignored |
| File fails to parse | Listed in `not_covered`, run continues |
| File cannot be read, or is not a regular file | Unreadable files are listed in `not_covered`; pipes, sockets and devices are skipped; run continues |
| Rule raises | Caught per rule, `rule <id> failed: <ExceptionType>` in `not_covered`, run continues. With env `DPR_STRICT=1` the exception is re-raised (set in tests). |
| A review module's `run()` raises | Caught per review, `review <slug> failed: <ExceptionType>` in `not_covered`, that review's section and rules are skipped, run continues. With env `DPR_STRICT=1` the exception is re-raised. |
| Optional tool missing | Listed as not run with the reason |
| Adapter timeout | Semgrep 300 s, audits 120 s, header request 10 s; listed as incomplete |
| Not a git repo | Git-based rules skipped and listed; meta shows `uncommitted working tree` |

## 14. Testing

- **Unit tests** per parser: SQL splitter (dollar quoting, comments, nested quotes), policy extraction, Prisma, schema extraction per ORM, route extraction per framework, Vue/Svelte script offsets.
- **Rule tests**: each rule has at least one positive and one negative snippet test.
- **Fixture apps** in `tests/fixtures/`:
  - `next-supabase-bad`: public-prefixed service role key reference; hardcoded live Stripe-shaped key; migrations with a table without RLS, a `using (true)` policy, an update policy with `with check (true)`, a view without `security_invoker`; invoice route with an unscoped `findUnique`; generate route calling OpenAI with no auth and no limiter; signup route logging the body, returning "already registered", and setting a cookie without `httpOnly`; `productionBrowserSourceMaps: true`; Sentry `sendDefaultPii: true`; reflected CORS with credentials; `dangerouslySetInnerHTML` with user content; tracked `.env`; `metadata jsonb` column; `medical_conditions` column.
  - `next-supabase-good`: the same app with each defect fixed and security headers configured.
  - `django-bad`: `DEBUG = True`, MD5 first in `PASSWORD_HASHERS`, `get_object_or_404(Invoice, pk=pk)` without a user filter, `CORS_ALLOW_ALL_ORIGINS = True`, `SESSION_COOKIE_SECURE = False`, `requests.get(request.GET["url"])`, f-string SQL with a request value, `traceback.format_exc()` in a response, serializer `fields = "__all__"`, `send_default_pii=True`.
  - `fastapi-good`: response models, `get_current_user` scoping, `slowapi` limiter, CORS allowlist, bcrypt hashing.
  - Each fixture has `expected.yaml`: bad fixtures list `{rule_id, file, line, tag}` that must be reported; good fixtures list `must_not_report` rule ids.
- **Secrets never committed.** Key-shaped strings are assembled at test runtime and written into a temporary copy of the fixture, and git-based fixtures (`.env` tracked, history) are created with `git init` in `tmp_path`. No key-shaped string is committed, so push protection is never triggered.
- **Safety tests**: planted key strings absent from Markdown, JSON and SARIF; no legal verdict phrases; CONFIRMED always has a location; no network connection in a default run.
- **Snapshot test** of the full Markdown report for `next-supabase-bad`, with date and sha normalised.
- **Semgrep tests**: adapter mapping tested with saved Semgrep JSON. One integration test marked `semgrep` runs the real binary and is skipped when it is missing.
- **Smoke runs** (manual, recorded in `tasks/todo.md`): `dpr scan` on `Active Projects/RocoVit` and `Active Projects/DataPulse` with `--out` pointing to a scratch folder. Nothing is written into those repositories. Results reviewed for false alarms, which become new negative rule tests.
- **Test report**: `pytest` summary and `pytest-cov` coverage printed and shared before any push.

## 15. CI

`.github/workflows/ci.yml`, triggered on push to `feature/**`, `bugfix/**`, `develop`, `main`, and on pull requests:

- Job `test`: `uv sync`, `ruff check`, `ruff format --check`, `pytest -m "not semgrep"` with coverage on Python 3.12.
- Job `semgrep`: install `semgrep`, run `pytest -m semgrep`.

`docs/ci-example.yml`: a workflow for other repos that installs `dpr` from its git URL, runs `dpr scan --format md,sarif --fail-on critical`, and uploads the report folder as an artifact with `retention-days: 7`.

## 16. Milestones

Each milestone ends with all tests green locally and in CI.

1. **Core, leaks, RLS.** Project scaffold, `model`, `rank`, `rules`, `walk` with sanity check, JS/TS and Python parsers, SQL and Prisma parsers, schema and route extraction, discovery, questions catalogue and answers loading, Markdown and JSON output, CLI `scan` and `questions`, leaks review, RLS review, safety tests, `next-supabase-bad` and `next-supabase-good` fixtures for those rules.
2. **Baseline, abuse, own OWASP rules.** Live header adapter, baseline review, abuse review, OWASP own rules and route classification, SARIF output, `django-bad` and `fastapi-good` fixtures.
3. **Semgrep, audits, inventory, auth.** Semgrep adapter, audit adapters, inventory review, auth test plan review, full snapshot test, CI workflow including the Semgrep job, CI example, smoke runs, project contributor notes.

## 17. Repository and workflow

- Gitflow: `main`, `develop`, work on `feature/dpr-scanner` branched from `develop`. Merges go through pull requests. No direct commits to `develop` or `main`.
- No remote is added and nothing is pushed until the owner asks.
- Commit messages contain no AI attribution.
- Plan and progress tracked in `tasks/todo.md`.
