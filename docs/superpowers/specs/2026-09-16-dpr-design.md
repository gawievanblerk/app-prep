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
| JS/TS parser | `tree-sitter` + `tree-sitter-language-pack` | Prebuilt wheels, no compiler, one API for js, ts, tsx. |
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
2. **Report title** uses a colon instead of a dash: `# Data Protection Review: <project>`.
3. **SARIF.** GitHub shows SARIF inline only for public repositories or with paid GitHub Code Security. The CI example therefore uploads the Markdown report as a workflow artifact. SARIF output is still produced.

## 4. Non-negotiable rules, enforced in code

| Skill rule | Enforcement |
|---|---|
| Inventory, not legal advice | Report renderer test fails if output matches `compliant with`, `complies with`, `satisfies Article`, `satisfies Section`, `lawful basis is`. Templates contain the fixed disclaimer. |
| Evidence tag on every finding | `Finding.tag` is required. `Finding.__post_init__` raises `ValueError` if tag is CONFIRMED and `locations` is empty. |
| Never upgrade a tag | Tags are set once at creation. `Finding` is a frozen dataclass. Dedupe chooses between existing findings and never changes a tag. |
| Static analysis by default | The only network calls are: live header read (needs `--url` and `--i-own-this-host`), Semgrep's own download of registry rules when Semgrep is installed and no local rules folder is given (`--semgrep DIR` avoids it), and audits (needs `--with-audit`). A test patches `socket.socket.connect` and asserts the `dpr` process opens no connection in a run with `semgrep="off"`, no `url`, and no audits. |
| Never print a secret value | Matchers replace the matched secret span with `<redacted:KIND>` before building any object. `Finding` has no raw-match field. A test assembles fake keys at runtime, runs all formats, and asserts none of the key strings appear. Semgrep results from secret rules have `extra.lines` dropped. |
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

Runtime: `tree-sitter`, `tree-sitter-language-pack`, `pyyaml`, `jinja2`. Everything else is stdlib, including `urllib` for header reads and `argparse` for the CLI.

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

- Skipped directories: `node_modules`, `.git`, `.next`, `dist`, `build`, `out`, `vendor`, `.venv`, `venv`, `__pycache__`, `.turbo`, `coverage`, `.pytest_cache`, `.mypy_cache`, `data-protection-review`.
- Build output directories (`dist`, `build`, `out`, `.next/static`) are indexed separately as `build_files` and read only by the leaks review.
- Symlinks are not followed.
- Binary files (null byte in the first 8 KB) are skipped.
- Source files over 1 MB are skipped and listed in `not_covered`. Build files up to 10 MB are scanned with key regexes only.
- Text read as UTF-8 with `errors="replace"`.
- Parsed trees are cached per file for the run.

**Sanity check.** If a `package.json` is present and zero JS/TS/Vue/Svelte files were indexed, or a `pyproject.toml` / `requirements*.txt` is present and zero `.py` files were indexed, raise `ScanError`. This is the silent empty-scan failure the skill hit.

### 7.2 JS/TS

tree-sitter grammars `javascript`, `typescript`, `tsx`. `.vue` and `.svelte` files: extract each `<script>` block, parse it as `ts` when `lang="ts"` else `javascript`, and add the block's start line offset to every location.

Helpers: find call expressions by callee path (`prisma.*.findUnique`), read object literal keys and values, resolve a local `const` to its initialiser within the same function, list exported function names, find string literals matching a pattern.

### 7.3 Python

stdlib `ast`. Files that fail to parse are listed in `not_covered`. Helpers mirror 7.2: calls by dotted name, keyword arguments, class bases, decorators, assignments in module scope.

### 7.4 SQL

A statement splitter that respects single quotes, double-quoted identifiers, dollar quoting (`$$` and `$tag$`), `--` and `/* */` comments. Recognised statements:

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

`routes.py` returns `Route(method, path, file, line, framework, handler_node, is_public_form)`:

All Next.js paths below are also matched under `src/`.

- Next.js app router: `app/**/route.{js,ts}` exported `GET`, `POST`, `PUT`, `PATCH`, `DELETE`. Path from folders, `[id]` kept as `:id`, route groups `(name)` removed.
- Next.js server actions: functions in files starting with `"use server"`. Method recorded as `ACTION`.
- Next.js pages router: `pages/api/**`. Method `ANY` unless the handler branches on `req.method`.
- Express and Fastify: `app.<method>(` and `router.<method>(` calls.
- Django: `path()` and `re_path()` in `urls.py`, resolved to the view function or class in the same app where possible. DRF `router.register`.
- FastAPI: `@app.<method>` and `@router.<method>` decorators.
- Flask: `@app.route` and `@bp.route` with `methods=`.

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
| `LEAK-ENV-TRACKED` | `git ls-files` lists `.env*` other than `.example`, `.sample`, `.template` | CONFIRMED | critical | high |
| `LEAK-ENV-IN-HISTORY` | `git log --all --diff-filter=A --name-only` shows such a file was ever added | CONFIRMED | high | medium |
| `LEAK-SOURCEMAP` | `*.map` in build output, `productionBrowserSourceMaps: true`, Vite `build.sourcemap: true` | CONFIRMED | medium | medium |
| `LEAK-BROAD-RESPONSE` | Route returns a whole record: `NextResponse.json(x)` / `res.json(x)` where `x` comes from an ORM call without `select`; DRF serializer `fields = "__all__"`; `select *` or Supabase `.select('*')` in a route | INFERRED | high if the model has a sensitive column (`password`, `hash`, `token`, `secret`, `stripe_customer_id`, `role`), else medium | medium |
| `LEAK-SSR-PROPS` | `getServerSideProps` / loader returning an ORM result without `select` | INFERRED | medium | medium |
| `LEAK-LOGGED-PII` | `console.log/error`, `logger.*`, `print`, `logging.*` with an argument named or rooted in `req`, `request`, `body`, `user`, `token`, `payload`, `headers`, `err` / `e` of a DB call; `traceback.print_exc()` | INFERRED | medium | low |
| `LEAK-SENTRY-PII` | `sendDefaultPii: true`, `send_default_pii=True`, or Sentry init without `beforeSend` / `before_send` | CONFIRMED | medium | low |

Every key finding's fix text starts with "Rotate the key now. It already reached a browser or history; removing it from the next build does not undo that." The key value is never included; the finding names the variable or key kind and the location.

Section shape: leak blocks in the skill's output format.

### 10.2 RLS (`rls`, review 2)

Input: `SchemaState` from migrations and, when given, `--db-dump`.

| Rule | Detects | Tag | Sev | Expl |
|---|---|---|---|---|
| `RLS-TABLE-OFF` | Table in `public` schema never enabled, or disabled last | CONFIRMED | critical when `public_supabase_key` is true, else high with a reduced-relevance note | high |
| `RLS-NO-POLICIES` | Enabled, zero policies | CONFIRMED | low | low |
| `RLS-SELECT-ONLY` | Select policies only (deviation 1 in section 3) | CONFIRMED | low | low |
| `RLS-POLICY-TRUE` | `USING (true)` or `WITH CHECK (true)` on a table with an owner or tenant column | CONFIRMED | high | high |
| `RLS-AUTHENTICATED-NOT-OWNER` | Predicate only checks `auth.role() = 'authenticated'`, or `TO authenticated` with a predicate that never references `auth.uid()` or `auth.jwt()` | CONFIRMED | high | high |
| `RLS-MISSING-WITH-CHECK` | `INSERT`, `UPDATE` or `ALL` policy without `WITH CHECK` | CONFIRMED | high | high |
| `RLS-WRONG-ROLE` | Write policy granted `TO public` or `TO anon` on a table with an owner column | CONFIRMED | high | high |
| `RLS-CLIENT-OWNER` | Predicate reads `user_metadata` from `auth.jwt()`, or `current_setting('request.headers'` | CONFIRMED | high | high |
| `RLS-TENANT-UNBOUND` | Predicate has a subquery over a membership-like table (`member`, `membership`, `org_users`, `team_users`) filtered by `auth.uid()` but never references the policy table's tenant column (`org_id`, `organization_id`, `tenant_id`, `workspace_id`, `team_id`) | INFERRED | high | high |
| `RLS-VIEW-BYPASS` | View in `public` over an RLS table without `security_invoker = true` | CONFIRMED | high | high |
| `RLS-DEFINER-FUNCTION` | `SECURITY DEFINER` function in `public`; severity high if its body reads an RLS table, plus a note when `search_path` is not set | CONFIRMED | medium or high | medium |
| `RLS-PUBLIC-BUCKET` | `storage.buckets` row with `public = true`, or `createBucket(..., { public: true })` | CONFIRMED | medium | medium |

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
| `BASE-HEADER-MISSING-<NAME>` | HSTS, CSP, X-Content-Type-Options, frame protection, Referrer-Policy, Permissions-Policy not set in any header config | UNVERIFIED, CONFIRMED with `--url` | HSTS high, CSP medium, others low | low |
| `BASE-CSP-WEAK` | `unsafe-inline` in `script-src`, or `default-src *` | CONFIRMED | medium | medium |
| `BASE-VERSION-DISCLOSURE` | Next `poweredByHeader` not false; Express without `app.disable('x-powered-by')` or helmet; live `Server` / `X-Powered-By` with a version | INFERRED, CONFIRMED with `--url` | low | low |
| `BASE-WEAK-HASH` | `md5`, `sha1`, `sha256` via `hashlib` or `crypto.createHash` inside a function or on a variable whose name contains `password`; Django `PASSWORD_HASHERS` first entry MD5 or SHA1 | INFERRED, CONFIRMED for Django setting | critical | medium |
| `BASE-NO-HTTPS-REDIRECT` | `--url` http root does not redirect to https | CONFIRMED | high | medium |
| `BASE-DEBUG-ON` | Django `DEBUG = True` as a literal in a settings module | INFERRED | high | medium |
| `BASE-MIXED-CONTENT` | `http://` asset URLs in `src`/`href` (excluding localhost, XML namespaces) | INFERRED | low | low |
| `BASE-CACHE-AUTH` | login page response without `Cache-Control: no-store` (live only) | CONFIRMED | low | low |

Password storage delegated to a managed provider is a section note, not a finding. Account enumeration is a section note referencing `AUTH-CASE-2` and `AUTH-CASE-4`.

Live header read (`adapters/headers.py`): only when `url` is set and `owns_host` is true, else `ScanError`. Exactly three `HEAD` requests: `https` root following redirects, `https` login path following redirects, `http` root without following redirects. 10 second timeout each. Failures become UNVERIFIED with the reason.

Section shape: fix blocks in the skill's format (`FIX n`, Where, Now, Change, Verify), ordered by score.

### 10.5 OWASP (`owasp`, review 5)

Own rules:

| Rule | Detects | Tag | Sev | Expl |
|---|---|---|---|---|
| `OWASP-A01-UNSCOPED-QUERY` | In a route handler, an identifier from the request (`params.id`, `req.params.*`, `searchParams.get`, FastAPI path parameter, Django view kwarg) reaches an ORM lookup (Prisma `findUnique/findFirst/update/delete`, Django `get/filter/get_object_or_404`, SQLAlchemy `session.get` / `filter`, Supabase `.eq`) whose filter has no session subject (`session.user.id`, `auth()`, `getServerSession`, `request.user`, `current_user`, `auth.uid`) | CONFIRMED when the filter literal is fully visible and the function has no later comparison against the session subject; INFERRED when a later comparison or an unresolved helper call exists | high | high |
| `OWASP-A01-UNGUARDED-METHOD` | Same route file: one exported method calls an auth check, another write method does not | CONFIRMED | high | high |
| `OWASP-A01-MASS-ASSIGNMENT` | Request body passed whole into ORM create or update (`data: body`, `...body`, `**request.data`, `**payload.dict()`) | CONFIRMED when the model has `role`, `is_admin`, `org_id`, `plan`, `is_staff`; else INFERRED | high | high |
| `OWASP-A01-GUESSABLE-ID` | Model with autoincrement integer id used in a route path parameter | CONFIRMED | medium | medium |
| `OWASP-A01-CLIENT-ONLY-GUARD` | UI conditional on `isAdmin` / `role === 'admin'` while the matching admin API route has no role check | INFERRED | medium | medium |
| `OWASP-A02-WEAK-RANDOM-TOKEN` | `Math.random()` or `random.random/choice` assigned to a name containing `token`, `secret`, `code`, `otp`, `reset`, `nonce` | INFERRED | high | medium |
| `OWASP-A02-SECRET-IN-URL` | URL string built with `token=`, `password=`, `apikey=` query parameters | INFERRED | medium | low |
| `OWASP-A03-RAW-SQL` | `$queryRawUnsafe`, `$executeRawUnsafe`, string concatenation or f-string into `execute`, `.raw()`, `text()` | CONFIRMED when a request value is in the string within the same function, else INFERRED | high | high |
| `OWASP-A03-XSS-SINK` | `dangerouslySetInnerHTML` with a non-literal, `v-html`, `innerHTML =`, `{@html}` | INFERRED | high | medium |
| `OWASP-A03-COMMAND` | `child_process.exec` / `execSync` with a non-literal; `subprocess` with `shell=True` and a non-literal; `eval`, `new Function` | INFERRED | high | high |
| `OWASP-A04-CLIENT-PRICE` | Request body fields `price`, `amount`, `total`, `plan`, `isPaid`, `discount` passed to Stripe or an ORM write | INFERRED | high | high |
| `OWASP-A08-NO-SRI` | `<script src="https://...">` without `integrity` in HTML or JSX | CONFIRMED | low | low |
| `OWASP-A08-UNSAFE-DESERIALISE` | `pickle.loads`, `yaml.load` without a safe loader, `node-serialize` | INFERRED | high | medium |
| `OWASP-A08-CI-UNTRUSTED` | GitHub workflow on `pull_request_target` that checks out the PR head ref | CONFIRMED | high | medium |
| `OWASP-A09-NO-AUTH-FAIL-LOG` | Login handler failure branch has no logger call | INFERRED | low | low |
| `OWASP-A10-SSRF` | `fetch`, `axios`, `requests`, `httpx`, `urllib` called with a URL from the request in the same function with no host allowlist comparison | INFERRED | high | high |

Shared findings: A05 debug and error exposure use `BASE-DEBUG-ON` and `ABUSE-ERROR-LEAK`; CORS uses the abuse rules; A07 references the auth review. These are cross-references, not duplicates.

Route classification table: every route marked public, authenticated, authenticated and ownership-checked, or admin, from the presence of auth calls, ownership predicates and role checks. Used by A01 rules and printed in the section.

**Semgrep adapter.** When `semgrep` is `"auto"` and the binary exists, or a local rules path is given: `semgrep scan --json --metrics=off --timeout 30 --config p/owasp-top-ten --config p/javascript --config p/typescript --config p/python` (or `--config <local dir>`), scoped to the repo with the same skipped directories, overall timeout 300 seconds. Each result becomes a `Finding` with `source="semgrep:<check_id>"`, tag INFERRED, `owasp` parsed from `extra.metadata.owasp`, severity from `extra.severity` (`ERROR` high, `WARNING` medium, `INFO` low). Results without an OWASP mapping are kept under `A05`. The `lines` field is dropped for rules whose id or metadata mentions secrets. Semgrep's rules are downloaded from the Semgrep registry unless a local path is given; code is scanned locally.

**Audits.** With `with_audit`: `npm audit --omit=dev --json` when `package-lock.json` exists, `pip-audit -f json` against requirements or the project. Advisories become `OWASP-A06-VULN-DEP` findings, tag INFERRED, `proof_needed` "call path from the app to the vulnerable function was not traced". Without the flag, A06 is listed as not run.

Section shape: finding blocks in the skill's format (`FINDING n`, Where, Attack, Blast, Fix) ordered by score, the route classification table, then categories reviewed with no finding.

### 10.6 Abuse and bill guard (`abuse`, review 7)

`costs.yaml` maps SDK categories (llm, email, sms, storage, image, browser, maps, payments) to a cost note and starting limits (`per_user`, `per_ip`, `window`) taken from the skill's example table.

| Rule | Detects | Tag | Sev | Expl |
|---|---|---|---|---|
| `ABUSE-PAID-UNAUTH` | Route whose handler (or a function it calls in the same file) calls a paid SDK, with no auth call in the handler and no middleware matcher covering the path | CONFIRMED | critical | high |
| `ABUSE-PAID-UNLIMITED` | Paid route with no limiter reference in the handler file or matching middleware | INFERRED | high | high |
| `ABUSE-INMEMORY-LIMITER` | `express-rate-limit` without `store`, or a module-level `Map` / dict counter, when `serverless` is true | CONFIRMED | medium | medium |
| `ABUSE-FORM-NO-CHALLENGE` | `is_public_form` route with no Turnstile, hCaptcha or reCAPTCHA verification and no honeypot field | INFERRED | medium | medium |
| `ABUSE-CORS-WILDCARD` | `origin: '*'`, `Access-Control-Allow-Origin: *` on routes with auth, `CORS_ALLOW_ALL_ORIGINS = True`, FastAPI `allow_origins=["*"]` | CONFIRMED | high | medium |
| `ABUSE-CORS-REFLECT` | `origin: true`, `callback(null, true)` without an allowlist check, or `Access-Control-Allow-Origin` set from the request `Origin`; critical when credentials are allowed | CONFIRMED | high or critical | high |
| `ABUSE-CORS-LOOSE-REGEX` | Origin regex without `^` and `$` anchors | CONFIRMED | medium | medium |
| `ABUSE-ERROR-LEAK` | Response body built from `err.message`, `err.stack`, `str(e)`, `repr(e)`, `traceback.format_exc()` | CONFIRMED | medium | medium |
| `ABUSE-NO-KILL-SWITCH` | Paid SDK call sites with no env flag check nearby (`*_ENABLED`, `DISABLE_*`, feature flag call) | INFERRED | low | low |

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
| `INV-PII-FILE-IN-REPO` | Committed `.csv` / `.json` / `.xlsx` whose header row or top-level keys match personal data terms | CONFIRMED | high | medium |

Section shape: the data map table (`Field | What it is | Where collected | Where it lives | Third parties with a copy | Retention | Who internally can read it | Evidence`), one flow line per collection point (`signup form (file) -> users table -> Stripe customers.create -> Sentry on error`, tagged INFERRED because flows are joined by shared model and file references, not traced), "collected with no clear reason", "not covered by this repo", and the lawyer questions (section 9). Retention is "retained indefinitely, no deletion path found" or UNKNOWN; a period is never invented. Who can read: admin routes and roles found, remainder UNKNOWN.

## 11. Output

### 11.1 Markdown

Jinja2 template mirroring the skill's `report-template.md` section for section, with only the sections for reviews that ran, in review number order (1 to 7) regardless of run order. Header: project name, date, scope and git sha, reviews run, method (static analysis, plus header checks against the named URL with the owner's confirmation, plus Semgrep and audits when they ran). Fixed disclaimer paragraph. Summary counts by severity plus open question count. Top three fixes. Evidence tag legend. Detection table. Per-review sections. Open questions in three groups. What this review did not cover: systems outside the repo, production config differences, runtime behaviour, skipped files, rules that errored, adapters not run, Firebase rules if present.

### 11.2 JSON

`{"schema_version": 1, "meta": ..., "detection": ..., "findings": [...], "sections": ..., "questions": ..., "not_covered": [...]}`. Enums as lowercase strings, locations as objects.

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

dpr questions [PATH] [--out FILE]  (default FILE: <PATH>/dpr-answers.yaml)
```

Exit codes: `0` completed and nothing at or above `--fail-on`; `1` a finding at or above `--fail-on`; `2` `ScanError` or invalid arguments.

## 13. Error handling

| Situation | Behaviour |
|---|---|
| Path missing, sanity check fails, `--url` without `--i-own-this-host`, invalid answers YAML | `ScanError`, exit 2, one-line message |
| Unknown key in answers | Warning printed, key ignored |
| File fails to parse | Listed in `not_covered`, run continues |
| Rule raises | Caught per rule, `rule <id> failed: <ExceptionType>` in `not_covered`, run continues. With env `DPR_STRICT=1` the exception is re-raised (set in tests). |
| Optional tool missing | Listed as not run with the reason |
| Adapter timeout | Semgrep 300 s, audits 120 s, header request 10 s; listed as incomplete |
| Not a git repo | Git-based rules skipped and listed; meta shows `uncommitted working tree` |

## 14. Testing

- **Unit tests** per parser: SQL splitter (dollar quoting, comments, nested quotes), policy extraction, Prisma, schema extraction per ORM, route extraction per framework, Vue/Svelte script offsets.
- **Rule tests**: each rule has at least one positive and one negative snippet test.
- **Fixture apps** in `tests/fixtures/`:
  - `next-supabase-bad`: public-prefixed service role key reference; hardcoded live Stripe-shaped key; migrations with a table without RLS, a `using (true)` policy, an update policy without `WITH CHECK`, a view without `security_invoker`; invoice route with an unscoped `findUnique`; generate route calling OpenAI with no auth and no limiter; signup route logging the body, returning "already registered", and setting a cookie without `httpOnly`; `productionBrowserSourceMaps: true`; Sentry `sendDefaultPii: true`; reflected CORS with credentials; `dangerouslySetInnerHTML` with user content; tracked `.env`; `metadata jsonb` column; `medical_conditions` column.
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
