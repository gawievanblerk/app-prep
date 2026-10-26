# Standards readiness

Goal: report readiness for OWASP ASVS 5.0, NIST SP 800-63B Rev. 4, ISO 27799:2016, IEC 81001-5-1:2021, HIPAA, GDPR and POPIA from the existing findings, without legal verdicts.

- [x] `src/dpr/data/standards.yaml`: controls per standard, each with rules, evidence and related questions
- [x] `src/dpr/report/standards.py`: per-control status (findings, clear, partial, not checked, evidence) and a health data signal
- [x] `Report.standards`, the Markdown section, JSON output and SARIF rule tags
- [x] `--standards LIST` on the CLI and `standards=` on `dpr.review()`
- [x] New rules: BASE-PASSWORD-COMPOSITION, BASE-PASSWORD-EXPIRY, BASE-STORAGE-UNENCRYPTED
- [x] Tests: mapping integrity (every rule mapped, every mapped rule registered, known question ids), status logic, report output, CLI, new rules
- [x] README and CHANGELOG

## Review

887 tests pass locally (was 860), ruff check and format clean. CI runs the whole test folder, so the new tests run there too. The express-prisma fixture gained one expected finding: its Terraform database sets no storage encryption.

Limits: clause labels are short names to check against the published standards. Breached-password screening, OAuth and OIDC settings and token signature checks are listed as evidence needed, not read from code.
