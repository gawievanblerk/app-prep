"""Run git read-only commands for the scan.

Each call passes --no-optional-locks and sets GIT_OPTIONAL_LOCKS=0, so commands such as
git status do not refresh or rewrite .git/index. GIT_NO_LAZY_FETCH=1 stops a partial clone
from fetching missing objects. core.fsmonitor is turned off so no monitor hook starts.
Repository config can still run other programs, such as clean filters, so only scan
repositories you trust.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from dpr.model import GitInfo


def run_git(
    root: Path, *args: str, timeout: int = 30, notes: list[str] | None = None
) -> str | None:
    if shutil.which("git") is None:
        return None
    command = ["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-C", str(root), *args]
    env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1"}
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False, env=env
        )
    except subprocess.TimeoutExpired:
        if notes is not None:
            notes.append(
                f"git {args[0]} timed out after {timeout} s, so the git-based checks that use "
                "it are incomplete"
            )
        return None
    except OSError:
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


def tracked_files(root: Path, notes: list[str] | None = None) -> list[str] | None:
    output = run_git(root, "ls-files", "-z", notes=notes)
    if output is None:
        return None
    return [name for name in output.split("\0") if name]
