# dpr

Deterministic data protection review for JS/TS and Python repositories. No LLM.

```bash
uv sync
uv run dpr scan /path/to/repo
```

## Install a release

Releases are private GitHub releases of this repository. Each release attaches a wheel and a source archive. With access to the repository:

```bash
gh release download v0.2.0 --repo gawievanblerk/app-prep --pattern "*.whl" --dir /tmp/dpr
uv tool install /tmp/dpr/dpr-0.2.0-py3-none-any.whl
dpr --version
```

Or install straight from the tag: `uv tool install git+https://github.com/gawievanblerk/app-prep@v0.2.0`. The changes in each release are in `CHANGELOG.md`.

The report maps where personal data and weaknesses are. Keep it out of git.
This is an inventory of what the code shows, not legal advice.

## How to scan

`dpr` scans a folder on your machine. It reads the code and never changes it. A default scan opens no network connection.

### Scan a local repository

Run from anywhere, pointing `--project` at this repository:

```bash
uv run --project /path/to/app-prep dpr scan /path/to/repo --out ~/scans/repo-report
```

Or from inside this repository:

```bash
uv run dpr scan /path/to/repo --out ~/scans/repo-report
```

Use `--out` to keep the report outside the scanned repository. Without it, `dpr` writes a `data-protection-review/` folder inside the scanned repository, and prints a tip to add that folder to `.gitignore` when git does not already ignore it.

### Scan a GitHub pull request

`dpr` does not read GitHub links. Clone the repository, check out the pull request, then scan the folder:

```bash
mkdir -p ~/scans && cd ~/scans
gh repo clone owner/repo repo-pr
cd repo-pr && gh pr checkout <number> && cd ..
uv run --project /path/to/app-prep dpr scan repo-pr --out repo-pr-report
```

### Output

Each scan prints a short summary (finding counts, the top three fixes and the files written) and writes:

- `REPORT-<date>.md`: the report to read
- `report-<date>.json`: the same content for tools
- `report-<date>.sarif`: SARIF 2.1.0 for code scanning, when `--format` includes `sarif`

### Options

| Option | What it does |
|---|---|
| `--out DIR` | Folder for the report files |
| `--format md,json,sarif` | Output formats, comma separated (default `md,json`) |
| `--reviews ...` | Run only some reviews: `all`, numbers `1` to `7`, or names `inventory`, `rls`, `auth`, `baseline`, `owasp`, `leaks`, `abuse` (for example `--reviews leaks,owasp`) |
| `--fail-on LEVEL` | Exit with code 1 when a finding at LEVEL or above exists: `medium`, `high` or `critical` (default `none`) |
| `--include-untracked` | In a git repository dpr reads tracked files only. This also reads untracked files that git does not ignore. Findings in them say the file is not in the repository |
| `--answers FILE` | Answers to the open questions, in YAML (create a starter file with `dpr questions`) |
| `--interactive` | Ask the open questions in the terminal |
| `--url URL --i-own-this-host` | Also read the security headers of a site you own: three `HEAD` requests, nothing else. `--url` without `--i-own-this-host` is refused |
| `--login-path PATH` | The login page path for the live header read (default `/login` or a detected route) |
| `--standards LIST` | Standards readiness to report, comma separated: `all` (default), `none`, or `asvs`, `nist-800-63b`, `iso-27799`, `iec-81001-5-1`, `hipaa`, `gdpr`, `popia` |
| `--db-dump FILE` | Output of the database check queries printed in the report's review 2 section; the live policies then replace what the migrations say |

Exit codes: `0` scan done, `1` a finding at or above `--fail-on`, `2` bad arguments or a scan error.

Not available yet: `--with-audit` (the report notes "Dependency audit not run" under "What this review did not cover") and `--semgrep` (accepted and ignored).

### Answer the open questions

Some things cannot be read from code, such as where data is hosted. Write a starter answers file, fill it in, and pass it to the next scan:

```bash
uv run dpr questions /path/to/repo --out ~/scans/repo-answers.yaml
uv run dpr scan /path/to/repo --answers ~/scans/repo-answers.yaml --out ~/scans/repo-report
```

### Use in CI

```bash
uv run dpr scan . --format sarif --out dpr-report --fail-on high
```

### Use as a Python module

```python
from dpr import review, render_markdown

report = review("/path/to/repo", reviews=["leaks", "owasp"])
print(render_markdown(report))
```

`render_json` and `render_sarif` return the other formats.

### Standards readiness

The report has a readiness view for seven standards, placed before the open questions: OWASP ASVS 5.0, NIST SP 800-63B Rev. 4, ISO 27799:2016, IEC 81001-5-1:2021, the HIPAA Security and Privacy Rules, GDPR and POPIA. Each control is matched to the dpr rules that test it in code (`src/dpr/data/standards.yaml`) and gets one status:

- Findings: at least one of its rules fired. The register ids of those issues are listed.
- No findings in code: every rule ran and none fired. This is not proof that the control is in place.
- Partly checked or Not checked: some or all of the reviews that own its rules did not run.
- Evidence needed: only documents, settings outside the repository or people can show it, such as a risk analysis, a breach procedure or a lawful basis.

For ISO 27799, IEC 81001-5-1 and HIPAA the report also says whether the data inventory found health fields. This is readiness for an assessment, not a certification, an audit result or legal advice. Check the section labels against the published text of each standard.

### Evidence tags

Each finding carries a tag: `CONFIRMED` (read directly at the cited location), `INFERRED` (likely, with what would prove it), or `UNVERIFIED` (only a live test can prove it). Check `INFERRED` findings before acting on them.
