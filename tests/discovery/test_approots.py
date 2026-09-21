from dpr.api import review
from dpr.discovery.approots import lower_undeployed, root_of
from dpr.discovery.detect import detect
from dpr.model import AppRoot, Finding, Location
from dpr.walk import RepoIndex
from tests.reviews.helpers import write

PIPELINE = (
    "variables:\n  apiDir: '$(Build.SourcesDirectory)/apps/api-py'\n"
    "steps:\n  - script: cd apps/web && npm ci && npm run build\n"
)


def monorepo(tmp_path):
    write(tmp_path, "package.json", '{"workspaces": ["apps/*", "packages/*"]}')
    write(tmp_path, "azure-pipelines.yml", PIPELINE)
    write(tmp_path, "apps/api-py/requirements.txt", "fastapi\n")
    write(
        tmp_path,
        "apps/api-py/app/main.py",
        "from fastapi import FastAPI\napp = FastAPI()\n\n\n@app.get('/health')\ndef health():\n"
        "    return {}\n",
    )
    write(tmp_path, "apps/web/package.json", '{"dependencies": {"react": "18"}}')
    write(tmp_path, "apps/web/index.html", "<div id=root></div>\n")
    write(tmp_path, "apps/web/src/main.tsx", "export {}\n")
    write(tmp_path, "apps/api/package.json", '{"dependencies": {"express": "4"}}')
    write(
        tmp_path,
        "apps/api/src/index.ts",
        "import express from 'express'\nconst app = express()\n"
        "app.get('/health', (req, res) => res.json({}))\n",
    )
    write(tmp_path, "packages/shared/package.json", '{"name": "shared"}')
    write(tmp_path, "packages/shared/index.ts", "export const x = 1\n")
    return tmp_path


def test_roots_kinds_and_deployment(tmp_path):
    roots = {r.path: r for r in detect(RepoIndex(monorepo(tmp_path))).app_roots}
    assert set(roots) == {"", "apps/api", "apps/api-py", "apps/web", "packages/shared"}
    assert (roots["apps/api-py"].kind, roots["apps/api-py"].deployed) == ("server", True)
    assert roots["apps/api-py"].evidence == "named in azure-pipelines.yml"
    assert (roots["apps/web"].kind, roots["apps/web"].deployed) == ("web", True)
    assert (roots["apps/api"].kind, roots["apps/api"].deployed) == ("server", False)
    assert (roots["packages/shared"].kind, roots["packages/shared"].deployed) == ("library", None)
    assert roots[""].deployed is None


def test_own_start_script_counts_as_deployed(tmp_path):
    monorepo(tmp_path)
    write(tmp_path, "apps/api/startup.sh", "node dist/index.js\n")
    roots = {r.path: r for r in detect(RepoIndex(tmp_path)).app_roots}
    assert roots["apps/api"].deployed is True


def test_without_any_deploy_reference_nothing_is_marked_undeployed(tmp_path):
    monorepo(tmp_path)
    (tmp_path / "azure-pipelines.yml").unlink()
    roots = detect(RepoIndex(tmp_path)).app_roots
    assert all(r.deployed is None for r in roots)


def test_root_of_picks_the_deepest_root():
    roots = [AppRoot("", "library", None), AppRoot("apps/api", "server", False)]
    assert root_of(roots, "apps/api/src/a.ts").path == "apps/api"
    assert root_of(roots, "apps/api-py/a.py").path == ""
    assert root_of([AppRoot("apps/api", "server", False)], "docs/x.md") is None


def finding(severity, *files):
    return Finding(
        rule_id="R",
        review="owasp",
        title="t",
        tag="CONFIRMED",
        severity=severity,
        exploitability="high",
        effort_minutes=5,
        locations=tuple(Location(f, 1) for f in files),
        detail="Detail.",
        fix="Fix.",
    )


def test_lower_undeployed_only_when_every_location_is_undeployed():
    roots = [
        AppRoot("", "library", None),
        AppRoot("apps/api", "server", False),
        AppRoot("apps/web", "web", True),
    ]
    items = [
        finding("critical", "apps/api/a.ts", "apps/api/b.ts"),
        finding("high", "apps/api/a.ts", "apps/web/a.ts"),
        finding("low", "apps/api/a.ts"),
    ]
    lowered, mixed, low = lower_undeployed(items, roots)
    assert lowered.severity.value == "high" and lowered.tag.value == "CONFIRMED"
    assert lowered.detail.startswith("Detail. Every location is in apps/api, which no deploy")
    assert mixed == items[1]
    assert low == items[2]


def test_review_lowers_findings_in_an_undeployed_app(tmp_path):
    monorepo(tmp_path)
    write(
        tmp_path,
        "apps/api/src/run.ts",
        "import { exec } from 'child_process'\nexport function run(cmd: string) { exec(cmd) }\n",
    )
    report = review(tmp_path, reviews=["owasp"])
    [command] = [f for f in report.findings if f.rule_id == "OWASP-A03-COMMAND"]
    assert command.severity.value == "medium"
    assert (
        "App root apps/api is not named by any deploy or CI configuration; its findings are "
        "listed one severity step lower"
    ) in report.not_covered
