import subprocess

from dpr.gitutil import git_info, run_git, tracked_files


def git(root, *args):
    subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "-c",
            "user.name=dpr",
            "-c",
            "user.email=dpr@example.invalid",
            *args,
        ],
        check=True,
        capture_output=True,
    )


def test_not_a_repo(tmp_path):
    info = git_info(tmp_path)
    assert (info.is_repo, info.revision) == (False, "uncommitted working tree")
    assert run_git(tmp_path, "status") is None
    assert tracked_files(tmp_path) is None


def test_repo_without_commits(tmp_path):
    git(tmp_path, "init", "-q")
    info = git_info(tmp_path)
    assert (info.is_repo, info.revision) == (True, "uncommitted working tree")


def test_clean_and_dirty_repo(tmp_path):
    git(tmp_path, "init", "-q")
    (tmp_path / "a.txt").write_text("a")
    git(tmp_path, "add", "a.txt")
    git(tmp_path, "commit", "-q", "-m", "init")
    sha = run_git(tmp_path, "rev-parse", "--short", "HEAD").strip()
    assert git_info(tmp_path).revision == sha
    (tmp_path / "b.txt").write_text("b")
    assert git_info(tmp_path).revision == f"{sha} (with uncommitted changes)"
    assert tracked_files(tmp_path) == ["a.txt"]


def test_run_git_takes_no_optional_locks_and_never_fetches(tmp_path, monkeypatch):
    seen = {}

    def fake_run(command, **kwargs):
        seen["command"], seen["env"] = command, kwargs["env"]
        return subprocess.CompletedProcess(command, 0, stdout="true\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert run_git(tmp_path, "status", "--porcelain") == "true\n"
    assert seen["command"][:2] == ["git", "--no-optional-locks"]
    assert seen["command"][-2:] == ["status", "--porcelain"]
    assert seen["env"]["GIT_OPTIONAL_LOCKS"] == "0"
    assert seen["env"]["GIT_NO_LAZY_FETCH"] == "1"
