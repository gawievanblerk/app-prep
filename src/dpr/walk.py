"""Walk a repository once into a RepoIndex."""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass
from pathlib import Path

from dpr.model import ScanError

SKIP_DIRS = frozenset({
    "node_modules", ".git", ".next", "dist", "build", "out", "vendor", ".venv", "venv",
    "__pycache__", ".turbo", "coverage", ".pytest_cache", ".mypy_cache",
    "data-protection-review",
})
BUILD_DIR_NAMES = frozenset({"dist", "build", "out"})
SOURCE_MAX_BYTES = 1_000_000
BUILD_MAX_BYTES = 10_000_000
JS_EXTS = frozenset({
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte",
})
PY_EXTS = frozenset({".py"})
ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")


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


def _is_binary(path: Path) -> bool:
    with path.open("rb") as fh:
        return b"\0" in fh.read(8192)


class RepoIndex:
    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            raise ScanError(f"path is not a directory: {root}")
        self.files: list[SourceFile] = []
        self.build_files: list[SourceFile] = []
        self.env_files: list[SourceFile] = []
        self.skipped: list[str] = []
        self.cache: dict[tuple[str, str], object] = {}
        self._text: dict[str, str] = {}
        self._walk()

    def _rel(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def _walk(self) -> None:
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            current = Path(dirpath)
            keep: list[str] = []
            for name in sorted(dirnames):
                sub = current / name
                if sub.is_symlink():
                    continue
                if name in BUILD_DIR_NAMES:
                    self._walk_build(sub)
                elif name == ".next":
                    if (sub / "static").is_dir():
                        self._walk_build(sub / "static")
                elif name not in SKIP_DIRS:
                    keep.append(name)
            dirnames[:] = keep
            for name in sorted(filenames):
                self._add(current / name)

    def _add(self, path: Path) -> None:
        if path.is_symlink():
            return
        rel = self._rel(path)
        size = path.stat().st_size
        entry = SourceFile(rel, path, size)
        if is_env_file(path.name):
            self.env_files.append(entry)
            return
        if size > SOURCE_MAX_BYTES:
            self.skipped.append(f"{rel}: larger than 1 MB")
            return
        if _is_binary(path):
            return
        self.files.append(entry)

    def _walk_build(self, top: Path) -> None:
        for dirpath, dirnames, filenames in os.walk(top, followlinks=False):
            current = Path(dirpath)
            dirnames[:] = sorted(
                d for d in dirnames if d != "node_modules" and not (current / d).is_symlink()
            )
            for name in sorted(filenames):
                path = current / name
                if path.is_symlink():
                    continue
                size = path.stat().st_size
                if size > BUILD_MAX_BYTES:
                    self.skipped.append(f"{self._rel(path)}: build file larger than 10 MB")
                    continue
                if not _is_binary(path):
                    self.build_files.append(SourceFile(self._rel(path), path, size))

    def text(self, rel: str) -> str:
        if is_env_file(Path(rel).name):
            raise ValueError("env files are read for variable names only")
        if rel not in self._text:
            self._text[rel] = (self.root / rel).read_text(encoding="utf-8", errors="replace")
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
        names: list[tuple[str, int]] = []
        with entry.path.open("r", encoding="utf-8", errors="replace") as fh:
            for number, raw in enumerate(fh, start=1):
                match = ENV_LINE.match(raw)
                if match:
                    names.append((match.group(1), number))
        return names

    def language_counts(self) -> dict[str, int]:
        counts = {"javascript/typescript": len(self.js_files), "python": len(self.py_files)}
        return {k: v for k, v in counts.items() if v}

    def sanity_check(self) -> None:
        names = {f.name for f in self.files}
        if "package.json" in names and not self.js_files:
            raise ScanError(
                "package.json found but no JS/TS files were indexed; the scan would read nothing"
            )
        has_py_manifest = "pyproject.toml" in names or any(
            fnmatch.fnmatch(n, "requirements*.txt") for n in names
        )
        if has_py_manifest and not self.py_files:
            raise ScanError(
                "Python manifest found but no .py files were indexed; the scan would read nothing"
            )
