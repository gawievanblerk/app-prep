from tests.reviews.helpers import findings_for, write

DOCKERFILE = """FROM ubuntu:20.04
RUN apt-get update && apt-get install -y python3.9 python3.9-venv
COPY requirements.txt /var/app/code/
COPY . /var/app/code/
RUN chmod ugo+rwx -R /var/app/code/
RUN chmod 1777 /tmp && chmod 755 /var/app
CMD gunicorn app.wsgi
"""

SCRIPT = """import os
from subprocess import call


def fix(today_dir):
    call(["chmod", "a+rw", "-R", today_dir])
    os.chmod(today_dir, 0o777)
    os.chmod(today_dir, 0o755)
"""


def test_container_runs_as_root(tmp_path):
    write(tmp_path, "Dockerfile", DOCKERFILE)
    write(tmp_path, "svc/Dockerfile", "FROM python:3.12-slim\nRUN useradd app\nUSER app\nCMD run\n")
    write(
        tmp_path,
        "multi/Dockerfile",
        "FROM node:22 AS build\nUSER node\nFROM gcr.io/distroless/nodejs22:nonroot\nCMD x\n",
    )
    write(tmp_path, "back/Dockerfile", "FROM python:3.12\nUSER app\nUSER root\nCMD run\n")
    found = {f.locations[0].file: f for f in findings_for(tmp_path, "baseline", "BASE-DOCKER-ROOT")}
    assert sorted(found) == ["Dockerfile", "back/Dockerfile"]
    assert str(found["Dockerfile"].locations[0]) == "Dockerfile:1"
    assert "has no USER instruction" in found["Dockerfile"].detail
    assert "switches back to root" in found["back/Dockerfile"].detail


def test_world_writable_chmod(tmp_path):
    write(tmp_path, "Dockerfile", DOCKERFILE)
    write(tmp_path, "scripts/fix_directory_permissions.py", SCRIPT)
    write(tmp_path, "scripts/py2.py", 'print "x"\ncall(["chmod", "a+rw", "-R", d])\n')
    write(tmp_path, "scripts/ok.sh", "chmod +x run.sh\nchmod 644 a\nchmod o-w b\n")
    found = {
        f.locations[0].file: f for f in findings_for(tmp_path, "baseline", "BASE-WORLD-WRITABLE")
    }
    assert sorted(found) == ["Dockerfile", "scripts/fix_directory_permissions.py", "scripts/py2.py"]
    assert [loc.line for loc in found["Dockerfile"].locations] == [5]
    assert [loc.line for loc in found["scripts/fix_directory_permissions.py"].locations] == [6, 7]
    assert found["scripts/fix_directory_permissions.py"].title == (
        "Files are made world-writable (a+rw, 0o777)"
    )
    assert found["Dockerfile"].severity.value == "high"


def test_thin_dockerignore(tmp_path):
    write(tmp_path, "Dockerfile", DOCKERFILE)
    write(tmp_path, ".dockerignore", ".git\nvenv\ndocs\n")
    write(tmp_path, ".gitignore", "local_settings.py\n*.pyc\n")
    (tmp_path / "policies" / "media").mkdir(parents=True)
    [finding] = findings_for(tmp_path, "baseline", "BASE-DOCKERIGNORE-THIN")
    assert [str(loc) for loc in finding.locations] == ["Dockerfile:4", ".dockerignore:1"]
    for part in ("environment files", "database dumps", "policies/media/", "local_settings.py"):
        assert part in finding.detail
    assert "the git history" not in finding.detail


def test_good_dockerignore_and_missing_one(tmp_path):
    write(tmp_path, "Dockerfile", DOCKERFILE)
    write(tmp_path, ".dockerignore", "*\n!app/\n!requirements.txt\n")
    assert findings_for(tmp_path, "baseline", "BASE-DOCKERIGNORE-THIN") == []
    (tmp_path / ".dockerignore").unlink()
    [finding] = findings_for(tmp_path, "baseline", "BASE-DOCKERIGNORE-THIN")
    assert "There is no .dockerignore" in finding.detail
    assert [str(loc) for loc in finding.locations] == ["Dockerfile:4"]
