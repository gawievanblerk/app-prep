import os
import threading

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


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read files without permission")
def test_unreadable_files_are_skipped(tmp_path):
    write(tmp_path, "a.py")
    locked = [write(tmp_path, "locked.py", "y = 2"), write(tmp_path, ".env", "A=1\n")]
    for path in locked:
        path.chmod(0)
    try:
        index = RepoIndex(tmp_path)
    finally:
        for path in locked:
            path.chmod(0o644)
    assert rels(index.files) == ["a.py"]
    assert index.env_files == []
    assert index.skipped == [
        ".env: could not be read (PermissionError)",
        "locked.py: could not be read (PermissionError)",
    ]


def test_named_pipes_are_skipped_without_blocking(tmp_path):
    write(tmp_path, "a.py")
    os.mkfifo(tmp_path / "pipe.py")
    os.mkfifo(tmp_path / ".env.local")
    (tmp_path / "dist").mkdir()
    os.mkfifo(tmp_path / "dist" / "main.js")
    result = {}
    worker = threading.Thread(target=lambda: result.update(index=RepoIndex(tmp_path)), daemon=True)
    worker.start()
    worker.join(10)
    assert not worker.is_alive(), "walking a named pipe blocked"
    index = result["index"]
    assert rels(index.files) == ["a.py"]
    assert index.env_files == [] and index.build_files == []


def test_virtualenvs_and_site_packages_are_skipped_whatever_their_name(tmp_path):
    write(tmp_path, "app.py", "x = 1")
    write(tmp_path, ".env/pyvenv.cfg", "home = /usr/bin\n")
    write(tmp_path, ".env/lib/python3.12/site-packages/django/__init__.py")
    write(tmp_path, "services/api/env/pyvenv.cfg", "home = /usr/bin\n")
    write(tmp_path, "services/api/env/lib/helper.py")
    write(tmp_path, "services/api/main.py")
    write(tmp_path, "tools/site-packages/requests/api.py")
    index = RepoIndex(tmp_path)
    assert rels(index.files) == ["app.py", "services/api/main.py"]
    assert index.env_files == []


def test_sanity_check_accepts_any_supported_source(tmp_path):
    py_repo = tmp_path / "py"
    write(py_repo, "package.json", '{"devDependencies": {"prettier": "3"}}')
    write(py_repo, "app/main.py", "x = 1")
    RepoIndex(py_repo).sanity_check()
    js_repo = tmp_path / "js"
    write(js_repo, "requirements.txt", "mkdocs\n")
    write(js_repo, "src/index.ts", "export const a = 1")
    RepoIndex(js_repo).sanity_check()
    empty = tmp_path / "empty"
    write(empty, "package.json", "{}")
    with pytest.raises(ScanError, match="package.json"):
        RepoIndex(empty).sanity_check()


def test_byte_order_mark_is_dropped_when_reading(tmp_path):
    from dpr.discovery.packages import collect_packages
    from dpr.parsing import pyast

    bom = b"\xef\xbb\xbf"
    write(tmp_path, "app.py", bom + b"import os\nx = 1\n", mode="wb")
    write(tmp_path, "package.json", bom + b'{"dependencies": {"next": "14"}}', mode="wb")
    write(tmp_path, ".env.local", bom + b"NEXT_PUBLIC_X=1\nSECOND=2\n", mode="wb")
    index = RepoIndex(tmp_path)
    assert index.text("app.py").startswith("import os")
    assert pyast.parse_file(index, "app.py") is not None
    assert index.skipped == []
    assert "next" in collect_packages(index)[0]
    assert index.env_names(index.env_files[0]) == [("NEXT_PUBLIC_X", 1), ("SECOND", 2)]
