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
    assert "there is no .dockerignore" in finding.detail
    assert [str(loc) for loc in finding.locations] == ["Dockerfile:4"]


DEV_COMPOSE = """services:
  api:
    build:
      context: ./api
      dockerfile: Dockerfile.dev
  worker:
    build: ./worker
  web:
    build:
      context: .
      dockerfile: Dockerfile
"""

PROD_COMPOSE = """services:
  api:
    build:
      context: ./api
      dockerfile: Dockerfile
  worker:
    build:
      context: ./worker
  web:
    build:
      context: .
      dockerfile: Dockerfile.prod
"""

API_MULTI = """FROM node:20-alpine AS builder
WORKDIR /app
COPY package.json ./
RUN npm ci
COPY . .
RUN npm run build
FROM node:20-alpine
WORKDIR /app
COPY --from=builder /app/package.json ./
COPY --from=builder /app/dist ./dist/
COPY --from=builder /app/prisma ./prisma/
USER node
CMD ["node", "dist/index.js"]
"""

WEB_PROD = """FROM node:20-alpine AS build
WORKDIR /app
COPY . .
RUN npm run build
FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
CMD ["nginx", "-g", "daemon off;"]
"""

SINGLE = "FROM node:20-alpine\nWORKDIR /app\nCOPY package.json ./\nCOPY . .\nCMD run\n"
WORKER = "FROM python:3.12-slim\nWORKDIR /app\nCOPY . .\nUSER app\nCMD run\n"
GOOD_IGNORE = ".git\nnode_modules\n.env*\n*.sql\n*.dump\n"


def compose_repo(tmp_path):
    write(tmp_path, "docker-compose.yml", DEV_COMPOSE)
    write(tmp_path, "docker-compose.prod.yml", PROD_COMPOSE)
    write(tmp_path, "package.json", "{}")
    write(tmp_path, ".dockerignore", GOOD_IGNORE)
    write(tmp_path, "Dockerfile", SINGLE)
    write(tmp_path, "Dockerfile.prod", WEB_PROD)
    write(tmp_path, "api/package.json", "{}")
    write(tmp_path, "api/.dockerignore", "node_modules\n.env\n")
    write(tmp_path, "api/Dockerfile", API_MULTI)
    write(tmp_path, "api/Dockerfile.dev", SINGLE)
    write(tmp_path, "worker/Dockerfile", WORKER)
    (tmp_path / ".git").mkdir()


def test_dockerignore_of_the_build_context(tmp_path):
    compose_repo(tmp_path)
    found = {
        f.locations[0].file: f for f in findings_for(tmp_path, "baseline", "BASE-DOCKERIGNORE-THIN")
    }
    # api/Dockerfile ships only named build output; Dockerfile.prod ships only dist to nginx;
    # the root Dockerfile's context is covered by the root .dockerignore.
    assert sorted(found) == ["api/Dockerfile.dev", "worker/Dockerfile"]
    assert "there is no .dockerignore" in found["worker/Dockerfile"].detail
    assert [str(loc) for loc in found["worker/Dockerfile"].locations] == ["worker/Dockerfile:3"]
    dev = found["api/Dockerfile.dev"].detail
    assert "api/.dockerignore does not exclude" in dev
    assert "environment files" in dev and "the git history" not in dev


def test_whole_stage_copied_into_final_stage(tmp_path):
    write(
        tmp_path,
        "Dockerfile",
        "FROM node:20 AS build\nWORKDIR /app\nCOPY . .\nRUN make\n"
        "FROM node:20-slim\nCOPY --from=build /app /app\nUSER node\n",
    )
    write(tmp_path, "svc/Dockerfile", "FROM node:20 AS base\nCOPY . /src\nFROM base\nUSER node\n")
    found = sorted(
        str(f.locations[0]) for f in findings_for(tmp_path, "baseline", "BASE-DOCKERIGNORE-THIN")
    )
    assert found == ["Dockerfile:3", "svc/Dockerfile:2"]


def test_root_container_dev_only_and_nginx(tmp_path):
    compose_repo(tmp_path)
    write(tmp_path, "tools/Dockerfile", "FROM python:3.12\nCMD run\n")
    write(tmp_path, "proxy/Dockerfile", "FROM nginx:1.27-alpine\nCOPY site /usr/share/nginx\n")
    found = {f.locations[0].file: f for f in findings_for(tmp_path, "baseline", "BASE-DOCKER-ROOT")}
    assert sorted(found) == ["Dockerfile", "api/Dockerfile.dev", "tools/Dockerfile"]
    assert found["Dockerfile"].severity.value == "low"
    assert found["api/Dockerfile.dev"].severity.value == "low"
    assert "development" in found["Dockerfile"].detail
    assert found["tools/Dockerfile"].severity.value == "medium"


def test_root_container_in_both_compose_files_stays_medium(tmp_path):
    compose = "services:\n  web:\n    build: .\n"
    write(tmp_path, "docker-compose.yml", compose)
    write(tmp_path, "docker-compose.prod.yml", compose)
    write(tmp_path, "Dockerfile", SINGLE)
    [finding] = findings_for(tmp_path, "baseline", "BASE-DOCKER-ROOT")
    assert finding.severity.value == "medium"


def test_git_history_only_where_the_context_holds_it(tmp_path):
    write(tmp_path, "Dockerfile", SINGLE)
    write(tmp_path, ".dockerignore", ".env*\n*.sql\n*.dump\n")
    (tmp_path / ".git").mkdir()
    [finding] = findings_for(tmp_path, "baseline", "BASE-DOCKERIGNORE-THIN")
    assert "the git history" in finding.detail
