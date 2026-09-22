# Changelog

All notable changes to dpr are listed here. Versions follow semantic versioning.

## [0.1.0] - 2026-09-22

First release. dpr reviews a JS/TS or Python repository for data protection issues without an LLM and writes Markdown, JSON and SARIF reports. A default scan opens no network connection and never prints a secret or personal value.

### Reviews

- Review 1, data inventory: a personal data classifier, collection points (request schemas, body reads, runtime values), third parties that receive personal data, deletion paths, retention, unused personal fields, committed data files, a personal data map, data flows and answers to open questions.
- Review 2, database lock check: row level security policies from SQL migrations, Prisma and database dumps, and a reduced-relevance section for server-only databases with GRANT parsing and runnable SQL.
- Review 3, failure path test plan: account flow discovery and twelve cases for sign-in, signup, reset, verification, sessions, email change and second factors, each decided by a finding, a recorded pass or a live-test note.
- Review 4, security baseline: security headers by surface, cookies, debug flags, seed accounts, committed passwords, password hashing, database exposure, and checks that pass.
- Review 5, OWASP sweep: access control, injection, cryptography, integrity, logging and audit gaps.
- Review 6, leak hunt: keys and env files in the tree and git history, over-broad responses, personal data in logs, source maps and committed data files.
- Review 7, abuse and bill guard: paid routes, rate limits, bulk fan-out, CORS and error messages, kill switches and a cost surface traced through services.

### Report

- A findings register that groups findings into distinct issues and drives the summary counts and the top three fixes.
- Detection of hosting, CI, SDKs, auth providers and app roots; findings in apps that nothing deploys are listed one severity step lower, and evidence never crosses app roots.
- Open questions filtered by what was detected, questions for the data protection lawyer, and a list of what the review did not cover.

### Known limits

- `--with-audit` (dependency audit) and `--semgrep` are accepted but not run yet.
- Live header checks read only a site the user owns (`--url` with `--i-own-this-host`).
