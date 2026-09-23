"""Exact dependency versions a repository pins, read from its manifests.

Only exact pins say which version is installed: `name==1.2.3` (or `===`) in requirements
files, `pyproject.toml` dependencies and Pipfile packages, an exact version in Poetry, and a
bare or `=` version in package.json (`"express": "4.19.2"`). Ranges such as `>=`, `~=`, `^` and
`~` are not read: the installed version is in a lock file dpr does not resolve.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass

from dpr.discovery.packages import normalise
from dpr.model import Location
from dpr.walk import RepoIndex

VERSION = r"\d+(?:\.\d+)*(?:[-.+]?[A-Za-z0-9]+(?:\.\d+)*)*"
PY_PIN = re.compile(
    rf"^\s*([A-Za-z0-9][\w.-]*)\s*(?:\[[^\]]*\])?\s*={{2,3}}\s*({VERSION})\s*(?:[;#].*)?$"
)
JS_PIN = re.compile(r"^\s*=?\s*v?(\d+\.\d+\.\d+(?:-[\w.]+)?)\s*$")
BARE = re.compile(r"^\s*(?:={2,3})?\s*(\d+(?:\.\d+)+)\s*$")


@dataclass(frozen=True)
class Pin:
    ecosystem: str  # "pypi" or "npm"
    name: str  # normalised: lower case, "_" as "-"
    version: str
    location: Location


def _line(text: str, needle: str) -> int:
    pos = text.find(needle)
    return text.count("\n", 0, pos) + 1 if pos >= 0 else 1


def _requirement(spec: str) -> tuple[str, str] | None:
    match = PY_PIN.match(spec)
    return (normalise(match.group(1)), match.group(2)) if match else None


def _requirements(rel: str, text: str) -> list[Pin]:
    found = []
    for number, row in enumerate(text.splitlines(), start=1):
        pinned = _requirement(row)
        if pinned:
            found.append(Pin("pypi", *pinned, Location(rel, number)))
    return found


def _exact(spec: object) -> str | None:
    if isinstance(spec, dict):
        spec = spec.get("version")
    match = BARE.match(str(spec or ""))
    return match.group(1) if match else None


def _pyproject(rel: str, text: str) -> list[Pin]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    found = []
    for spec in data.get("project", {}).get("dependencies", []):
        pinned = _requirement(str(spec))
        if pinned:
            found.append(Pin("pypi", *pinned, Location(rel, _line(text, str(spec)))))
    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name, spec in poetry.items():
        version = _exact(spec) if name.lower() != "python" else None
        if version:
            found.append(Pin("pypi", normalise(name), version, Location(rel, _line(text, name))))
    return found


def _pipfile(rel: str, text: str) -> list[Pin]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    found = []
    for section in ("packages", "dev-packages"):
        for name, spec in data.get(section, {}).items():
            version = _exact(spec) if str(spec).lstrip().startswith(("=", "{")) else None
            if version:
                location = Location(rel, _line(text, name))
                found.append(Pin("pypi", normalise(name), version, location))
    return found


def _package_json(rel: str, text: str) -> list[Pin]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    found = []
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            match = JS_PIN.match(str(spec))
            if match:
                location = Location(rel, _line(text, f'"{name}"'))
                found.append(Pin("npm", name.lower(), match.group(1), location))
    return found


def pinned_versions(index: RepoIndex) -> list[Pin]:
    found: list[Pin] = []
    for entry in index.named("requirements*.txt"):
        found += _requirements(entry.rel, index.text(entry.rel))
    readers = {"pyproject.toml": _pyproject, "Pipfile": _pipfile, "package.json": _package_json}
    for name, reader in readers.items():
        for entry in index.named(name):
            found += reader(entry.rel, index.text(entry.rel))
    return found
