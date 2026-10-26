"""Walk a repository once into a RepoIndex."""

from __future__ import annotations

import fnmatch
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from dpr.gitutil import tracked_files, untracked_files
from dpr.model import ScanError

SKIP_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        ".next",
        "dist",
        "build",
        "out",
        "vendor",
        ".venv",
        "venv",
        "__pycache__",
        ".turbo",
        "coverage",
        ".pytest_cache",
        ".mypy_cache",
        "data-protection-review",
    }
)
BUILD_DIR_NAMES = frozenset({"dist", "build", "out"})
SOURCE_MAX_BYTES = 1_000_000
BUILD_MAX_BYTES = 10_000_000
JS_EXTS = frozenset(
    {
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".mts",
        ".cts",
        ".vue",
        ".svelte",
    }
)
PY_EXTS = frozenset({".py"})
ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=[ \t]*(.*?)[ \t\r]*$")
ENV_QUOTED = re.compile(r"^([\"'])(.*)\1$")
NO_GIT = (
    "Not a git repository, or git is unavailable: every file under the folder was scanned, "
    "including files git would ignore, and no finding can say whether a file is committed"
)


@dataclass(frozen=True)
class SourceFile:
    rel: str
    path: Path
    size: int

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def suffix(self) -> str:
        return self.path.suffix.lower()


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def is_env_file(name: str) -> bool:
    return name == ".env" or name.startswith(".env.")


def _is_virtualenv(path: Path, name: str) -> bool:
    return name == "site-packages" or (path / "pyvenv.cfg").is_file()


def _is_binary(path: Path) -> bool:
    with path.open("rb") as fh:
        return b"\0" in fh.read(8192)


class RepoIndex:
    """Files to scan. In a git repository only tracked files are read, plus untracked files git
    does not ignore when include_untracked is set. Build output is read whatever git says,
    because it is generated and usually ignored."""

    def __init__(self, root: str | os.PathLike[str], include_untracked: bool = False) -> None:
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            raise ScanError(f"path is not a directory: {root}")
        self.files: list[SourceFile] = []
        self.build_files: list[SourceFile] = []
        self.env_files: list[SourceFile] = []
        self.skipped: list[str] = []
        self.notes: list[str] = []
        # Tracked paths, or None outside git; untracked paths in scope (only with the flag).
        self.tracked: frozenset[str] | None = None
        self.untracked: frozenset[str] = frozenset()
        self.cache: dict[tuple[str, str], object] = {}
        self._text: dict[str, str] = {}
        self._scope: frozenset[str] | None = None
        self._scope_dirs: frozenset[str] = frozenset()
        self._set_scope(include_untracked)
        self._walk()

    def _set_scope(self, include_untracked: bool) -> None:
        tracked = tracked_files(self.root, notes=self.notes)
        if tracked is None:
            self.notes.append(NO_GIT)
            return
        self.tracked = frozenset(tracked)
        others = [
            rel
            for rel in untracked_files(self.root, notes=self.notes) or []
            if not SKIP_DIRS.union(BUILD_DIR_NAMES).intersection(rel.split("/")[:-1])
        ]
        scope = set(tracked)
        if not tracked and others:
            include_untracked = True
            self.notes.append(
                "git tracks no file under the folder yet, so untracked files that git does not "
                "ignore were scanned"
            )
        if include_untracked:
            self.untracked = frozenset(others) - self.tracked
            scope |= self.untracked
        elif others:
            examples = ", ".join(sorted(others, key=lambda p: (p.count("/"), p))[:3])
            self.notes.append(
                f"{len(others)} untracked file(s) that git does not ignore were not scanned (for "
                f"example {examples}); pass --include-untracked to scan them"
            )
        self._scope = frozenset(scope)
        self._scope_dirs = frozenset(
            str(parent) for rel in scope for parent in Path(rel).parents if str(parent) != "."
        )

    def _rel(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def _in_scope_dir(self, path: Path) -> bool:
        return self._scope is None or self._rel(path) in self._scope_dirs

    def _walk(self) -> None:
        for dirpath, dirnames, filenames in os.walk(
            self.root, followlinks=False, onerror=self._on_walk_error
        ):
            current = Path(dirpath)
            keep: list[str] = []
            for name in sorted(dirnames):
                sub = current / name
                if sub.is_symlink():
                    continue
                if name in BUILD_DIR_NAMES:
                    self._walk_build(sub)
                elif name == ".next":
                    try:
                        has_static = (sub / "static").is_dir()
                    except OSError:
                        self._skip_dir(sub)
                        continue
                    if has_static:
                        self._walk_build(sub / "static")
                elif name not in SKIP_DIRS and self._in_scope_dir(sub):
                    try:
                        virtualenv = _is_virtualenv(sub, name)
                    except OSError:
                        self._skip_dir(sub)
                        continue
                    if not virtualenv:
                        keep.append(name)
            dirnames[:] = keep
            for name in sorted(filenames):
                self._add(current / name)

    def _unreadable(self, path: Path, exc: OSError) -> None:
        self.skipped.append(f"{self._rel(path)}: could not be read ({type(exc).__name__})")

    def _skip_dir(self, path: Path) -> None:
        message = f"{self._rel(path)}/: directory could not be read"
        if message not in self.skipped:
            self.skipped.append(message)

    def _on_walk_error(self, exc: OSError) -> None:
        if exc.filename:
            self._skip_dir(Path(exc.filename))

    def _regular_size(self, path: Path) -> int | None:
        """Size of a regular file. Symlinks, pipes, sockets and devices give None."""
        try:
            info = path.lstat()
        except OSError as exc:
            self._unreadable(path, exc)
            return None
        return info.st_size if stat.S_ISREG(info.st_mode) else None

    def _add(self, path: Path) -> None:
        rel = self._rel(path)
        if self._scope is not None and rel not in self._scope:
            return
        size = self._regular_size(path)
        if size is None:
            return
        entry = SourceFile(rel, path, size)
        try:
            if is_env_file(path.name):
                with path.open("rb"):
                    pass
                self.env_files.append(entry)
                return
            if size > SOURCE_MAX_BYTES:
                self.skipped.append(f"{rel}: larger than 1 MB")
                return
            if _is_binary(path):
                return
        except OSError as exc:
            self._unreadable(path, exc)
            return
        self.files.append(entry)

    def _walk_build(self, top: Path) -> None:
        for dirpath, dirnames, filenames in os.walk(
            top, followlinks=False, onerror=self._on_walk_error
        ):
            current = Path(dirpath)
            dirnames[:] = sorted(
                d for d in dirnames if d != "node_modules" and not (current / d).is_symlink()
            )
            for name in sorted(filenames):
                path = current / name
                size = self._regular_size(path)
                if size is None:
                    continue
                if size > BUILD_MAX_BYTES:
                    self.skipped.append(f"{self._rel(path)}: build file larger than 10 MB")
                    continue
                try:
                    binary = _is_binary(path)
                except OSError as exc:
                    self._unreadable(path, exc)
                    continue
                if not binary:
                    self.build_files.append(SourceFile(self._rel(path), path, size))

    def text(self, rel: str) -> str:
        if is_env_file(Path(rel).name):
            raise ValueError("env files are read for variable names only")
        if rel not in self._text:
            self._text[rel] = (self.root / rel).read_text(encoding="utf-8-sig", errors="replace")
        return self._text[rel]

    def with_suffix(self, *suffixes: str) -> list[SourceFile]:
        wanted = {s.lower() for s in suffixes}
        return [f for f in self.files if f.suffix in wanted]

    def glob(self, *patterns: str) -> list[SourceFile]:
        return [f for f in self.files if any(fnmatch.fnmatch(f.rel, p) for p in patterns)]

    def named(self, *patterns: str) -> list[SourceFile]:
        return [f for f in self.files if any(fnmatch.fnmatch(f.name, p) for p in patterns)]

    @property
    def js_files(self) -> list[SourceFile]:
        return [f for f in self.files if f.suffix in JS_EXTS]

    @property
    def py_files(self) -> list[SourceFile]:
        return [f for f in self.files if f.suffix in PY_EXTS]

    def env_names(self, entry: SourceFile) -> list[tuple[str, int]]:
        return [(name, number) for name, _, number in self.env_pairs(entry)]

    def env_pairs(self, entry: SourceFile) -> list[tuple[str, str, int]]:
        """NAME, value and line number per assignment. Callers must not report a value."""
        pairs: list[tuple[str, str, int]] = []
        with entry.path.open("r", encoding="utf-8-sig", errors="replace") as fh:
            for number, raw in enumerate(fh, start=1):
                match = ENV_LINE.match(raw)
                if match:
                    value = match.group(2)
                    quoted = ENV_QUOTED.match(value)
                    pairs.append((match.group(1), quoted.group(2) if quoted else value, number))
        return pairs

    def language_counts(self) -> dict[str, int]:
        counts = {"javascript/typescript": len(self.js_files), "python": len(self.py_files)}
        return {k: v for k, v in counts.items() if v}

    def sanity_check(self) -> None:
        names = {f.name for f in self.files}
        manifests = []
        if "package.json" in names:
            manifests.append("package.json")
        if "pyproject.toml" in names or any(fnmatch.fnmatch(n, "requirements*.txt") for n in names):
            manifests.append("Python manifest")
        if manifests and not (self.js_files or self.py_files):
            raise ScanError(
                f"{' and '.join(manifests)} found but no JS/TS or Python source files were "
                "indexed; the scan would read nothing"
            )
