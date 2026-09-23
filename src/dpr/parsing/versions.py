"""Framework, runtime and base image versions a repository declares, read from its files.

Only versions the files fix are read: `==`, `~=` and `===` pins in requirements files,
pyproject and Pipfile; a caret, tilde or plain major in package.json; Dockerfile `FROM`
images and `pythonX.Y` in its `RUN` lines; `.python-version`, `runtime.txt` and `.nvmrc`.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass

from dpr.model import Location
from dpr.walk import RepoIndex

PY_PIN = re.compile(r"^\s*(django)\s*(?:\[[^\]]*\])?\s*(?:==|~=|===)\s*(\d+)\.(\d+)", re.I | re.M)
PY_VERSION = re.compile(r"(?:^|[^\w.])(?:python-?)?(2|3)\.(\d{1,2})(?:\.\d+)?\b")
JS_MAJOR = re.compile(r"^\s*[\^~=v]?\s*(\d+)(?:\.(?:\d+|x|\*))*\s*$")
FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", re.I | re.M)
RUN_PYTHON = re.compile(r"\bpython(3\.\d{1,2})\b")
DEBIAN_NAMES = {"stretch": "9", "buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13"}
JS_PACKAGES = {"next": "next", "express": "express"}


@dataclass(frozen=True)
class Declared:
    component: str
    cycle: str
    location: Location


def _line(text: str, needle: str) -> int:
    pos = text.find(needle)
    return text.count("\n", 0, pos) + 1 if pos >= 0 else 1


def _requirements(rel: str, text: str) -> list[Declared]:
    return [
        Declared("django", f"{m.group(2)}.{m.group(3)}", Location(rel, _line(text, m.group(0))))
        for m in PY_PIN.finditer(text)
    ]


def _pin(spec: object) -> str | None:
    """major.minor of an exact Python version spec: "==3.2.9", "3.2.9", {version = "..."}."""
    if isinstance(spec, dict):
        spec = spec.get("version")
    match = re.fullmatch(r"\s*(?:==|~=|===)?\s*(\d+)\.(\d+)(?:\.\d+)?\s*", str(spec or ""))
    return f"{match.group(1)}.{match.group(2)}" if match else None


def _pyproject(rel: str, text: str) -> list[Declared]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    found = _requirements(rel, "\n".join(data.get("project", {}).get("dependencies", [])))
    found = [Declared(d.component, d.cycle, Location(rel, _line(text, "Django"))) for d in found]
    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name, spec in poetry.items():
        cycle = _pin(spec) if name.lower() == "django" else None
        if cycle:
            found.append(Declared("django", cycle, Location(rel, _line(text, name))))
    return found


def _pipfile(rel: str, text: str) -> list[Declared]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    found = []
    for name, spec in data.get("packages", {}).items():
        cycle = _pin(spec) if name.lower() == "django" else None
        if cycle:
            found.append(Declared("django", cycle, Location(rel, _line(text, name))))
    version = str(data.get("requires", {}).get("python_version", ""))
    match = re.fullmatch(r"(\d)\.(\d{1,2})(?:\.\d+)?", version)
    if match:
        found.append(
            Declared("python", f"{match[1]}.{match[2]}", Location(rel, _line(text, version)))
        )
    return found


def _package_json(rel: str, text: str) -> list[Declared]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    found = []
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            match = JS_MAJOR.match(str(spec)) if name in JS_PACKAGES else None
            if match:
                line = _line(text, f'"{name}"')
                found.append(Declared(JS_PACKAGES[name], match.group(1), Location(rel, line)))
    engine = str((data.get("engines") or {}).get("node", ""))
    match = JS_MAJOR.match(engine) if engine else None
    if match:
        found.append(Declared("node", match.group(1), Location(rel, _line(text, '"node"'))))
    return found


def _image(image: str) -> tuple[str, str] | None:
    name, _, tag = image.partition(":")
    name = name.rsplit("/", 1)[-1].lower()
    tag = tag.split("@", 1)[0].lower()
    if name == "python" and (match := re.match(r"(\d)\.(\d{1,2})", tag)):
        return "python", f"{match[1]}.{match[2]}"
    if name == "node" and (match := re.match(r"(\d+)", tag)):
        return "node", match[1]
    if name == "ubuntu" and (match := re.match(r"(\d\d\.\d\d)", tag)):
        return "ubuntu", match[1]
    if name == "debian":
        number = re.match(r"(\d+)", tag)
        release = DEBIAN_NAMES.get(tag.split("-")[0]) or (number[1] if number else None)
        return ("debian", release) if release else None
    return None


def _dockerfile(rel: str, text: str) -> list[Declared]:
    found = []
    for match in FROM.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        image = _image(match.group(1))
        if image:
            found.append(Declared(*image, Location(rel, line)))
        suffix = match.group(1).rsplit("-", 1)[-1].lower()
        if match.group(1).lower().startswith(("python:", "node:")) and suffix in DEBIAN_NAMES:
            found.append(Declared("debian", DEBIAN_NAMES[suffix], Location(rel, line)))
    in_run = False
    for number, row in enumerate(text.splitlines(), start=1):
        in_run = bool(re.match(r"\s*RUN\b", row, re.I)) or in_run
        if in_run and not row.lstrip().startswith("#"):
            for version in dict.fromkeys(RUN_PYTHON.findall(row)):
                found.append(Declared("python", version, Location(rel, number)))
        in_run = in_run and row.rstrip().endswith("\\")
    return found


def _single_version(rel: str, text: str, component: str) -> list[Declared]:
    value = text.strip().splitlines()[0].strip() if text.strip() else ""
    if component == "node":
        match = re.fullmatch(r"v?(\d+)(?:\.\d+)*", value)
        return [Declared("node", match[1], Location(rel, 1))] if match else []
    match = PY_VERSION.search(value)
    return [Declared("python", f"{match[1]}.{match[2]}", Location(rel, 1))] if match else []


def declared_versions(index: RepoIndex) -> list[Declared]:
    found: list[Declared] = []
    for entry in index.named("requirements*.txt"):
        found += _requirements(entry.rel, index.text(entry.rel))
    readers = {
        "pyproject.toml": _pyproject,
        "Pipfile": _pipfile,
        "package.json": _package_json,
    }
    for name, reader in readers.items():
        for entry in index.named(name):
            found += reader(entry.rel, index.text(entry.rel))
    for entry in index.named("Dockerfile", "Dockerfile.*", "*.dockerfile"):
        found += _dockerfile(entry.rel, index.text(entry.rel))
    for name, component in (
        (".python-version", "python"),
        ("runtime.txt", "python"),
        (".nvmrc", "node"),
    ):
        for entry in index.named(name):
            found += _single_version(entry.rel, index.text(entry.rel), component)
    return found
