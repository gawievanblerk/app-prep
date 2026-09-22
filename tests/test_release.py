import re
import tomllib
from pathlib import Path

import yaml

import dpr

ROOT = Path(__file__).resolve().parent.parent


def _pyproject() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text())


def test_version_has_one_source():
    project = _pyproject()["project"]
    assert "version" not in project
    assert "version" in project["dynamic"]
    assert _pyproject()["tool"]["hatch"]["version"]["path"] == "src/dpr/__init__.py"
    assert re.fullmatch(r"\d+\.\d+\.\d+", dpr.__version__)


def test_package_is_marked_private_and_proprietary():
    project = _pyproject()["project"]
    assert "Private :: Do Not Upload" in project["classifiers"]
    assert project["license"] == "LicenseRef-Proprietary"
    assert project["license-files"] == ["LICENSE"]
    text = (ROOT / "LICENSE").read_text()
    assert "All rights reserved" in text
    assert "Proprietary" in text


def test_changelog_has_an_entry_for_this_version():
    text = (ROOT / "CHANGELOG.md").read_text()
    assert re.search(rf"^## \[?{re.escape(dpr.__version__)}\]? ", text, re.M)


def test_sdist_ships_only_the_package_tests_and_release_files():
    sdist = _pyproject()["tool"]["hatch"]["build"]["targets"]["sdist"]
    assert set(sdist["include"]) == {"src/dpr", "tests", "README.md", "CHANGELOG.md", "LICENSE"}


def test_release_workflow_builds_from_a_version_tag():
    workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    trigger = workflow.get("on") or workflow.get(True)
    assert trigger["push"]["tags"] == ["v*.*.*"]
    steps = "\n".join(
        str(step.get("run", "")) for job in workflow["jobs"].values() for step in job["steps"]
    )
    assert "uv build" in steps
    assert "GITHUB_REF_NAME" in steps
    assert "gh release create" in steps


def test_ci_runs_on_release_branches():
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    trigger = workflow.get("on") or workflow.get(True)
    assert "release/**" in trigger["push"]["branches"]
