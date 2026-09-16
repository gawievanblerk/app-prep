import os

import pytest

from dpr.model import ScanError
from dpr.walk import RepoIndex, is_env_file, line_of


def write(root, rel, text="x", mode="w"):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if mode == "wb":
        path.write_bytes(text)
    else:
        path.write_text(text)
    return path


def rels(entries):
    return sorted(e.rel for e in entries)


def test_skips_dependency_and_vcs_dirs(tmp_path):
    write(tmp_path, "src/app.ts", "const a = 1")
    write(tmp_path, "node_modules/lib/index.js")
    write(tmp_path, "packages/web/node_modules/x.js")
    write(tmp_path, ".git/config")
    write(tmp_path, ".venv/lib/site.py")
    index = RepoIndex(tmp_path)
    assert rels(index.files) == ["src/app.ts"]


def test_build_output_is_indexed_separately(tmp_path):
    write(tmp_path, "src/app.ts")
    write(tmp_path, "dist/main.js", "bundle")
    write(tmp_path, ".next/static/chunks/a.js", "chunk")
    write(tmp_path, ".next/cache/big.bin", "cache")
    index = RepoIndex(tmp_path)
    assert rels(index.files) == ["src/app.ts"]
    assert rels(index.build_files) == [".next/static/chunks/a.js", "dist/main.js"]


def test_env_files_are_listed_but_never_read_as_text(tmp_path):
    write(tmp_path, "a.py")
    write(tmp_path, ".env", "SECRET_THING=value-that-must-not-leak\n")
    write(tmp_path, "apps/web/.env.local", "export NEXT_PUBLIC_X = 1\n# comment\nBAD LINE\n")
    index = RepoIndex(tmp_path)
    assert rels(index.env_files) == [".env", "apps/web/.env.local"]
    assert rels(index.files) == ["a.py"]
    with pytest.raises(ValueError):
        index.text(".env")
    names = index.env_names(next(e for e in index.env_files if e.rel == "apps/web/.env.local"))
    assert names == [("NEXT_PUBLIC_X", 1)]
    assert "value-that-must-not-leak" not in repr(index.env_names(index.env_files[0]))


def test_large_and_binary_files(tmp_path):
    write(tmp_path, "a.py")
    write(tmp_path, "big.js", "a" * 1_000_001)
    write(tmp_path, "img.png", b"\x89PNG\x00\x00", mode="wb")
    index = RepoIndex(tmp_path)
    assert rels(index.files) == ["a.py"]
    assert index.skipped == ["big.js: larger than 1 MB"]


def test_symlinks_are_not_followed(tmp_path):
    outside = tmp_path / "outside"
    write(outside, "secret.py")
    repo = tmp_path / "repo"
    write(repo, "a.py")
    os.symlink(outside, repo / "linked")
    os.symlink(outside / "secret.py", repo / "link.py")
    index = RepoIndex(repo)
    assert rels(index.files) == ["a.py"]


def test_sanity_check_package_json_without_js(tmp_path):
    write(tmp_path, "package.json", "{}")
    write(tmp_path, "README.md")
    with pytest.raises(ScanError, match="package.json"):
        RepoIndex(tmp_path).sanity_check()
    write(tmp_path, "src/index.ts")
    RepoIndex(tmp_path).sanity_check()


def test_sanity_check_requirements_without_python(tmp_path):
    write(tmp_path, "requirements-dev.txt", "pytest")
    with pytest.raises(ScanError, match="Python"):
        RepoIndex(tmp_path).sanity_check()


def test_missing_root(tmp_path):
    with pytest.raises(ScanError):
        RepoIndex(tmp_path / "nope")


def test_helpers(tmp_path):
    write(tmp_path, "app/api/x/route.ts")
    write(tmp_path, "app/page.tsx")
    write(tmp_path, "svc/models.py")
    index = RepoIndex(tmp_path)
    assert rels(index.glob("app/api/*")) == ["app/api/x/route.ts"]
    assert rels(index.named("models.py")) == ["svc/models.py"]
    assert rels(index.with_suffix(".tsx")) == ["app/page.tsx"]
    assert index.language_counts() == {"javascript/typescript": 2, "python": 1}
    assert line_of("a\nb\nc", 2) == 2
    assert is_env_file(".env.production") and not is_env_file("env.ts")
