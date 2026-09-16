"""Run git without letting repository config execute commands."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from dpr.model import GitInfo


def run_git(root: Path, *args: str, timeout: int = 30) -> str | None:
    if shutil.which("git") is None:
        return None
    command = ["git", "-c", "core.fsmonitor=false", "-C", str(root), *args]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout,
                                check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout if result.returncode == 0 else None


def git_info(root: Path) -> GitInfo:
    inside = run_git(root, "rev-parse", "--is-inside-work-tree")
    if not inside or inside.strip() != "true":
        return GitInfo(False, "uncommitted working tree")
    sha = run_git(root, "rev-parse", "--short", "HEAD")
    if not sha:
        return GitInfo(True, "uncommitted working tree")
    dirty = run_git(root, "status", "--porcelain")
    suffix = " (with uncommitted changes)" if dirty else ""
    return GitInfo(True, sha.strip() + suffix)


def tracked_files(root: Path) -> list[str] | None:
    output = run_git(root, "ls-files", "-z")
    if output is None:
        return None
    return [name for name in output.split("\0") if name]
