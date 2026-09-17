import json
import subprocess

import pytest
import yaml

from dpr.cli import main
from tests.reviews.helpers import write


def app(tmp_path):
    root = tmp_path / "app"
    write(
        root,
        ".env.example",
        "NEXT_PUBLIC_SUPABASE_ANON_KEY=\nNEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=\n",
    )
    write(root, "supabase/migrations/1.sql", "create table public.notes (id int, user_id uuid);")
    write(root, "app/page.tsx", "export default function Page() { return null }\n")
    return root


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


def test_scan_writes_reports_and_summary(tmp_path, capsys):
    root = app(tmp_path)
    assert main(["scan", str(root)]) == 0
    out_dir = root / "data-protection-review"
    [md] = list(out_dir.glob("REPORT-*.md"))
    [js] = list(out_dir.glob("report-*.json"))
    assert md.read_text().startswith("# Data Protection Review: app")
    assert json.loads(js.read_text())["schema_version"] == 1
    lines = capsys.readouterr().out.strip().splitlines()
    assert lines[0].startswith(
        "dpr: 2 findings (critical 2, high 0, medium 0, low 0), 22 open questions"
    )
    assert lines[1] == "Top fixes:"
    assert any(line.startswith("Wrote ") and line.endswith(".md") for line in lines)
    assert len(lines) <= 15


def test_fail_on(tmp_path):
    root = app(tmp_path)
    assert main(["scan", str(root), "--fail-on", "critical", "--format", "json"]) == 1
    assert main(["scan", str(root), "--fail-on", "none", "--format", "json"]) == 0
    assert (
        main(["scan", str(root), "--reviews", "leaks", "--fail-on", "high", "--format", "md"]) == 1
    )


def test_formats_reviews_and_out(tmp_path, capsys):
    root = app(tmp_path)
    out = tmp_path / "elsewhere"
    assert main(["scan", str(root), "--reviews", "2,6", "--format", "json", "--out", str(out)]) == 0
    assert [p.suffix for p in out.iterdir()] == [".json"]
    assert "Tip:" not in capsys.readouterr().out
    assert main(["scan", str(root), "--format", "xml"]) == 2
    assert "unknown format: xml" in capsys.readouterr().err


def test_scan_errors_exit_2(tmp_path, capsys):
    root = app(tmp_path)
    assert main(["scan", str(root), "--url", "https://example.com"]) == 2
    assert "i-own-this-host" in capsys.readouterr().err
    assert main(["scan", str(tmp_path / "missing")]) == 2


def test_gitignore_tip(tmp_path, capsys):
    root = app(tmp_path)
    git(root, "init", "-q")
    main(["scan", str(root), "--format", "md"])
    assert 'Tip: add "data-protection-review/" to .gitignore' in capsys.readouterr().out
    (root / ".gitignore").write_text("data-protection-review/\n")
    main(["scan", str(root), "--format", "md"])
    assert "Tip:" not in capsys.readouterr().out


def test_questions_command(tmp_path, capsys):
    root = app(tmp_path)
    assert main(["questions", str(root)]) == 0
    target = root / "dpr-answers.yaml"
    assert set(yaml.safe_load(target.read_text())) and len(yaml.safe_load(target.read_text())) == 22
    assert main(["questions", str(root)]) == 2
    assert "already exists" in capsys.readouterr().err


def test_unexpected_error_exits_2_with_one_line(tmp_path, capsys, monkeypatch):
    root = app(tmp_path)

    def boom(*args, **kwargs):
        raise RuntimeError("parser exploded\nsecond line")

    monkeypatch.setattr("dpr.cli.review", boom)
    monkeypatch.delenv("DPR_STRICT")
    assert main(["scan", str(root)]) == 2
    assert capsys.readouterr().err == "dpr: error: RuntimeError: parser exploded second line\n"
    monkeypatch.setenv("DPR_STRICT", "1")
    with pytest.raises(RuntimeError):
        main(["scan", str(root)])


def test_write_failure_exits_2(tmp_path, capsys, monkeypatch):
    root = app(tmp_path)
    blocker = tmp_path / "not-a-folder"
    blocker.write_text("x")
    monkeypatch.delenv("DPR_STRICT")
    assert main(["scan", str(root), "--out", str(blocker)]) == 2
    assert capsys.readouterr().err.startswith("dpr: error: FileExistsError: ")
