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
