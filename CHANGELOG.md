# Changelog

All notable changes to dpr are listed here. Versions follow semantic versioning.

## [0.2.1] - 2026-10-26

- The report header lists the standards tested: the OWASP Top 10 2021 when review 5 runs, and each standard in the readiness section.

## [0.2.0] - 2026-10-26

This release cuts false positives sharply, adds rule packs found missing in real scans, and adds a standards readiness section to the report.

### Accuracy

- In a git repository dpr scans tracked files only. `--include-untracked` adds untracked files that git does not ignore, and findings in them say the file is not in the repository.
- Vendored and minified third-party libraries are reported once per library as a dependency issue, instead of running code rules on them.
- False positives cut in many rules: path traversal, debug and weak hash settings in test modules, weak random tokens, raw SQL built from helpers and bound arguments, escaped Markup values, hardcoded keys in test scripts and example comments, container rules outside the shipped build stage, and unscoped lookups.
- LLM calls and rendered files no longer count as public-sensitive actions.
- FastAPI dependency gates on routers and apps, custom auth decorators and class-based view fields are read, so guarded routes are not reported as open.
- JS routes are traced into paid routes of another service in the same repository.
- Secret-looking path segments in route paths are masked in every output.
- Three bundled advisory entries were corrected against public sources.

### Rules added in this release

- A Django and deploy rule pack, secret fallbacks to committed values, Pickle sessions, settings that fail open, sensitive public routes, and personal data found by value in data files and code.


### Standards readiness

- A new report section maps every dpr rule to the controls of seven standards: OWASP ASVS 5.0, NIST SP 800-63B Rev. 4, ISO 27799:2016, IEC 81001-5-1:2021, the HIPAA Security and Privacy Rules, GDPR and POPIA. Each control shows Findings (with register ids), No findings in code, Partly checked, Not checked, or Evidence needed, plus the answers to related open questions. The health standards also say whether the data inventory found health fields.
- `--standards LIST` (and `standards=` in `dpr.review()`) picks the standards to report: `all` (default), `none`, or ids such as `hipaa,popia`.
- The JSON report has a `standards` list, and SARIF rules carry the controls they speak to as `tags`.

### New rules

- BASE-PASSWORD-COMPOSITION: password rules that demand set character types.
- BASE-PASSWORD-EXPIRY: passwords that expire on a schedule.
- BASE-STORAGE-UNENCRYPTED: Terraform databases, volumes, file systems and caches without encryption at rest.

## [0.1.0] - 2026-09-22

First release. dpr reviews a JS/TS or Python repository for data protection issues without an LLM and writes Markdown, JSON and SARIF reports. A default scan opens no network connection and never prints a secret or personal value.

### Reviews

- Review 1, data inventory: a personal data classifier, collection points (request schemas, body reads, runtime values), third parties that receive personal data, deletion paths, retention, unused personal fields, committed data files, a personal data map, data flows and answers to open questions.
- Review 2, database lock check: row level security policies from SQL migrations, Prisma and database dumps, and a reduced-relevance section for server-only databases with GRANT parsing and runnable SQL.
- Review 3, failure path test plan: account flow discovery and twelve cases for sign-in, signup, reset, verification, sessions, email change and second factors, each decided by a finding, a recorded pass or a live-test note.
- Review 4, security baseline: security headers by surface, cookies, debug flags, seed accounts, committed passwords, password hashing, database exposure, and checks that pass.
- Review 5, OWASP sweep: access control, injection, cryptography, integrity, logging and audit gaps.
- Review 6, leak hunt: keys and env files in the tree and git history, over-broad responses, personal data in logs, source maps and committed data files. A tracked env file is judged by its values as well as its names, so publishable keys and other public-by-design values do not read as leaked secrets.
- Review 7, abuse and bill guard: paid routes, rate limits, bulk fan-out, CORS and error messages, kill switches and a cost surface traced through services.

### Report

- A findings register that groups findings into distinct issues and drives the summary counts and the top three fixes.
- Detection of hosting, CI, SDKs, auth providers and app roots; findings in apps that nothing deploys are listed one severity step lower, and evidence never crosses app roots.
- Open questions filtered by what was detected, questions for the data protection lawyer, and a list of what the review did not cover.

### Known limits

- `--with-audit` (dependency audit) and `--semgrep` are accepted but not run yet.
- Live header checks read only a site the user owns (`--url` with `--i-own-this-host`).
