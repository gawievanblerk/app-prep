"""Third-party code copied into the repository.

A JS or CSS file is vendored when its name matches a known library (vendored_libs.yaml), it is
minified (`.min.js`, or very long lines on average), or its header is a library banner (`/*!`,
`@license`, a webpack bootstrap). A folder is vendored when it is named after a known library and
holds no app source, sits under a third-party folder, holds its own licence file and no project
manifest anywhere below it (a copied package such as a Django app), or is collected static
output (`staticfiles`, or a `static` folder that holds Django admin's collected files). Sink
rules skip vendored files; the owasp review reports each library once instead.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from dpr.data import load

LIB_EXTS = (".js", ".mjs", ".cjs", ".css")
CODE_EXTS = (".js", ".mjs", ".cjs", ".py")
# A folder named after a library but holding these is the app's own code (`app/bootstrap/`).
OWN_SOURCE = (".py", ".ts", ".tsx", ".jsx", ".vue", ".svelte")
THIRD_PARTY_DIRS = frozenset(
    {"third-party", "third_party", "thirdparty", "3rdparty", "3rd-party", "vendors"}
    | {"bower_components", "jspm_packages"}
)
COLLECTED_DIRS = frozenset({"staticfiles", "collected_static", "collectstatic", "static_collected"})
COLLECTED_MARKERS = ("admin/js/core.js", "admin/css/base.css", "rest_framework/js/default.js")
LICENSE_FILE = re.compile(r"(?i)^(?:licen[cs]e|copying)(?:[.-][\w.-]+)?$")
PROJECT_FILES = frozenset(
    {"package.json", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "manage.py"}
    | {"requirements.txt", "go.mod", "Cargo.toml", "composer.json", "Gemfile", "pom.xml"}
)
EXTENSION = re.compile(r"\.(?:m?js|cjs|css)$")
MARKER = re.compile(r"[.-](?:min|slim|prod|production)$")
# A version at the end of the name, or before a build label (jquery-ui-1.11.1.custom).
FILE_VERSION = re.compile(r"[-.@_]v?(\d+(?:\.\d+)+(?:-[a-z0-9]+)?)(?=\.[a-z]\w*$|$)")
DIR_VERSION = re.compile(r"(?:[-_.]?v?\d+(?:\.\d+)*|-dist)$")
BANNER = re.compile(
    r"^\s*/\*!|@license\b|@preserve\b|webpackBootstrap|For license information please see"
)
BANNER_NAME = re.compile(
    r"/\*[!*]?\s*(?:\*\s*)?([A-Za-z][\w.-]*(?: [A-Z][\w.-]*)?)\s+v?(\d+\.\d+(?:\.\d+)?)\b"
)
PY_VERSION = re.compile(r"^__version__\s*=\s*(['\"])([^'\"]+)\1", re.M)
HEAD = 2048
LONG_LINES_MIN_BYTES = 4096
LONG_LINE_AVERAGE = 300


@dataclass(frozen=True)
class Library:
    name: str
    version: str | None
    evidence: str
    known: bool  # named by the library list or a banner, not only by its shape
    files: tuple[str, ...]
    folder: str | None = None


@dataclass(frozen=True)
class Vendored:
    files: frozenset[str]
    folders: tuple[str, ...]  # library and collected static folders, for build output paths
    libraries: tuple[Library, ...]


def _catalogue() -> list[dict]:
    return load("vendored_libs.yaml")["libraries"]


def split_name(name: str) -> tuple[str, str | None]:
    """jquery-1.10.2.min.js -> ("jquery", "1.10.2")."""
    stem, version = EXTENSION.sub("", name.lower()), None
    while True:
        shorter = MARKER.sub("", stem)
        found = FILE_VERSION.search(shorter)
        if found:
            version = version or found.group(1)
            shorter = shorter[: found.start()] + shorter[found.end() :]
        if shorter == stem:
            return stem, version
        stem = shorter


def _known_file(stem: str) -> dict | None:
    return next((e for e in _catalogue() if re.fullmatch(e["files"], stem)), None)


def _known_dir(name: str) -> dict | None:
    bare = DIR_VERSION.sub("", name.lower()) or name.lower()
    return next((e for e in _catalogue() if bare in e.get("dirs", ())), None)


def _banner_version(head: str, banner: str) -> str | None:
    if not banner:
        return None
    found = re.search(
        rf"(?i)(?<![\w.]){re.escape(banner)}(?![\w])[^\n\d]{{0,40}}?v?(\d+\.\d+(?:\.\d+)?)", head
    )
    return found.group(1) if found else None


def _long_lines(text: str) -> bool:
    return len(text) >= LONG_LINES_MIN_BYTES and len(text) / (text.count("\n") + 1) > (
        LONG_LINE_AVERAGE
    )


def file_library(rel: str, text: str) -> tuple[str, str | None, str, bool] | None:
    """(name, version, evidence, known) when a JS or CSS file is a library copy."""
    name = PurePosixPath(rel).name
    if not name.lower().endswith(LIB_EXTS):
        return None
    stem, version = split_name(name)
    head = text[:HEAD]
    entry = _known_file(stem)
    if entry is not None:
        banner = entry.get("banner", entry["name"])
        version = version or _banner_version(head, banner)
        return entry["name"].format(file=stem), version, "known library file name", True
    named = BANNER_NAME.search(head)
    if BANNER.search(head):
        if named:
            return named.group(1), version or named.group(2), "licence banner", True
        return stem, version, "licence or bundle banner", False
    if ".min." in name.lower() or name.lower().endswith(("-min.js", "-min.css")):
        if named:
            return named.group(1), version or named.group(2), "minified file with a banner", True
        return stem, version, "minified file name", False
    if _long_lines(text):
        return stem, version, "minified content (very long lines)", False
    return None


def _folder_version(
    index, folder: str, names: set[str], library: str, files: list[str]
) -> str | None:
    """From the folder's package.json, bower.json or __version__, else from the banner of one of
    its files that names the same library."""
    for manifest in ("package.json", "bower.json"):
        if f"{folder}/{manifest}" in names:
            try:
                version = json.loads(index.text(f"{folder}/{manifest}")).get("version")
            except (ValueError, AttributeError):
                version = None
            if isinstance(version, str):
                return version
    if f"{folder}/__init__.py" in names:
        found = PY_VERSION.search(index.text(f"{folder}/__init__.py"))
        if found:
            return found.group(2)
    for rel in files:
        if rel.endswith(LIB_EXTS):
            found = file_library(rel, index.text(rel))
            if found and found[0].lower() == library.lower() and found[1]:
                return found[1]
    return None


class _Folders:
    """Which folders are copies of a library, from the paths the index holds."""

    def __init__(self, paths: list[str]) -> None:
        self.names = set(paths)
        self.children: dict[str, set[str]] = {}
        self.own_source: set[str] = set()
        self.projects: set[str] = set()
        for rel in paths:
            parts = rel.split("/")
            for depth in range(1, len(parts)):
                self.children.setdefault("/".join(parts[:depth]), set())
            parent = "/".join(parts[:-1])
            self.children.setdefault(parent, set()).add(parts[-1])
            if rel.endswith(OWN_SOURCE):
                self.own_source |= {"/".join(parts[:d]) for d in range(1, len(parts))}
            if parts[-1] in PROJECT_FILES:
                self.projects |= {"/".join(parts[:d]) for d in range(1, len(parts))}

    def collected(self, folder: str) -> bool:
        name = folder.rsplit("/", 1)[-1]
        if name in COLLECTED_DIRS:
            return True
        return name == "static" and any(f"{folder}/{m}" in self.names for m in COLLECTED_MARKERS)

    def library(self, folder: str) -> tuple[str, str, bool] | None:
        """(name, evidence, known) when the folder holds a copied library."""
        name = folder.rsplit("/", 1)[-1]
        entry = _known_dir(name)
        if entry is not None and folder not in self.own_source:
            return entry["name"].format(file=name), "folder named after the library", True
        parent = folder.rsplit("/", 1)[0] if "/" in folder else ""
        if parent.rsplit("/", 1)[-1] in THIRD_PARTY_DIRS:
            return name, "third-party folder", False
        files = self.children.get(folder, set())
        if any(LICENSE_FILE.match(f) for f in files) and folder not in self.projects:
            return name, "own licence file and no project manifest", False
        return None


def detect_vendored(index) -> Vendored:
    paths = [f.rel for f in index.files]
    folders = _Folders(paths + [f.rel for f in index.build_files])
    vendored: set[str] = set()
    marked: set[str] = set()
    by_folder: dict[str, tuple[str, str, bool, list[str]]] = {}
    by_name: dict[tuple[str, str | None], tuple[str, str, bool, list[str]]] = {}
    for rel in paths:
        parts = rel.split("/")
        home = None
        for depth in range(1, len(parts)):
            folder = "/".join(parts[:depth])
            if folders.collected(folder):
                vendored.add(rel)
                marked.add(folder)
            elif (found := folders.library(folder)) is not None:
                home = folder
                by_folder.setdefault(folder, (*found, []))[3].append(rel)
                break
        if home is not None:
            vendored.add(rel)
            marked.add(home)
            continue
        if not rel.endswith(LIB_EXTS):
            continue
        found_file = file_library(rel, index.text(rel))
        if found_file is None and any(p in THIRD_PARTY_DIRS for p in parts[:-1]):
            found_file = (split_name(parts[-1])[0], None, "third-party folder", False)
        if found_file is None:
            continue
        name, version, evidence, known = found_file
        vendored.add(rel)
        by_name.setdefault((name.lower(), version), (name, evidence, known, []))[3].append(rel)
    libraries = [
        Library(
            name,
            _folder_version(index, folder, folders.names, name, files),
            evidence,
            known,
            tuple(sorted(files, key=lambda rel: not rel.endswith(CODE_EXTS + LIB_EXTS))),
            folder,
        )
        for folder, (name, evidence, known, files) in by_folder.items()
        if any(f.endswith(CODE_EXTS) for f in files)
    ]
    libraries += [
        Library(name, version, evidence, known, tuple(files))
        for (_, version), (name, evidence, known, files) in by_name.items()
    ]
    return Vendored(
        frozenset(vendored),
        tuple(sorted(marked)),
        tuple(sorted(libraries, key=lambda lib: lib.files[0])),
    )


def vendored(index) -> Vendored:
    """Computed once per index."""
    key = ("vendored", "")
    if key not in index.cache:
        index.cache[key] = detect_vendored(index)
    return index.cache[key]


def is_vendored(index, rel: str) -> bool:
    found = vendored(index)
    return rel in found.files or any(rel.startswith(f + "/") for f in found.folders)
