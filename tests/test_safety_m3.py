import json
import socket

import pytest

from dpr import reviews, rules
from dpr.api import review
from dpr.cli import main
from dpr.model import Tag
from dpr.report.markdown import BANNED_PHRASES, render_markdown
from tests.fixture_builder import SECRETS, build
from tests.reviews.helpers import write

ALL = (
    "next-supabase-bad",
    "django-bad",
    "fastapi-bad",
    "express-prisma",
    "next-supabase-good",
    "fastapi-good",
)
SECTIONS = (
    "## Summary",
    "## Evidence tags",
    "## Detection",
    "## 1. Data inventory",
    "## 2. Database lock check",
    "## 3. Failure path test plan",
    "## 4. Security baseline",
    "## 5. OWASP sweep",
    "## 6. Leak hunt",
    "## 7. Abuse and bill guard",
    "## Open questions",
    "## What this review did not cover",
)
REQUIRED_PARTS = (
    "### Findings register",
    "### Personal data map",
    "### Table protection status",
    "### Cases",
    "### Checks that pass",
    "### Place 1: public variables reviewed",
    "### Cost surface",
    "### For the data protection lawyer",
)
PLANTED_EMAIL = "maria.okafor" + "@" + "gmail.com"


@pytest.mark.parametrize("name", ALL)
def test_every_review_runs_with_the_same_section_structure(tmp_path, name):
    report = review(build(name, tmp_path))
    assert all(status == "runs" for _, status in report.meta.applicability)
    text = render_markdown(report)
    assert tuple(line for line in text.splitlines() if line.startswith("## ")) == SECTIONS
    for heading in REQUIRED_PARTS:
        assert f"\n{heading}\n" in text, heading


@pytest.mark.parametrize("name", ALL)
def test_evidence_wording_and_templates_hold_in_every_fixture(tmp_path, name):
    report = review(build(name, tmp_path))
    for finding in report.findings:
        if finding.tag is Tag.CONFIRMED:
            assert finding.locations, finding.rule_id
        if finding.tag is Tag.INFERRED:
            assert finding.proof_needed, finding.rule_id
        for text in (finding.title, finding.detail, finding.fix, finding.proof_needed or ""):
            assert "${" not in text, finding.rule_id
    text = render_markdown(report)
    assert not any(phrase in text.lower() for phrase in BANNED_PHRASES)
    assert chr(0x2014) not in text


@pytest.mark.parametrize("name", ("express-prisma", "django-bad"))
def test_no_secret_or_planted_address_in_any_format(tmp_path, capsys, name):
    root = build(name, tmp_path)
    out_dir = tmp_path / "out"
    assert main(["scan", str(root), "--format", "md,json,sarif", "--out", str(out_dir)]) == 0
    outputs = [p.read_text() for p in out_dir.iterdir()]
    captured = capsys.readouterr()
    outputs += [captured.out, captured.err]
    for value in (*SECRETS, PLANTED_EMAIL):
        assert not any(value in text for text in outputs), value
    data = json.loads(next(p for p in out_dir.iterdir() if p.suffix == ".json").read_text())
    assert data["register"]


SNIPPET_ADDRESS = "ana.fictional" + "@" + "corpmail.io"
SNIPPET_PASSWORD = "Fict" + "ional-seed-" + "5521"


def snippet_repo(root):
    """Every line a snippet-producing rule points at holds a personal address."""
    write(root, "requirements.txt", "fastapi\nsendgrid\nsqlalchemy\npasslib\n")
    write(
        root,
        "app/notify.py",
        "import logging\n"
        "from sendgrid import SendGridAPIClient\n\n"
        "logger = logging.getLogger(__name__)\n"
        "client = SendGridAPIClient('x')\n\n\n"
        "def notify(user):\n"
        f"    client.send(to='{SNIPPET_ADDRESS}', subject='hi', content=user.name)\n"
        f"    logger.info('copied {SNIPPET_ADDRESS} for %s', user.email)\n",
    )
    write(
        root,
        "app/db/seed.py",
        "from app.core.security import get_password_hash\n"
        "from app.models import User\n\n\n"
        "def seed(db):\n"
        f"    db.add(User(email='{SNIPPET_ADDRESS}', "
        f"password_hash=get_password_hash('{SNIPPET_PASSWORD}')))\n",
    )
    write(
        root,
        "app/models.py",
        "from sqlalchemy import JSON, Integer, String\n"
        "from sqlalchemy.orm import Mapped, mapped_column\n\n\n"
        "class Profile(Base):\n"
        "    __tablename__ = 'profiles'\n"
        "    id: Mapped[int] = mapped_column(Integer, primary_key=True)\n"
        "    email: Mapped[str] = mapped_column(String)\n"
        f"    extra: Mapped[dict] = mapped_column(JSON, default={{'contact': '{SNIPPET_ADDRESS}'}})\n",
    )
    write(root, "start.sh", "#!/bin/sh\npython -m app.db.seed\nuvicorn app.main:app\n")
    write(
        root,
        "web/package.json",
        '{"dependencies": {"express": "4", "zod": "3"}}',
    )
    write(
        root,
        "web/src/server.js",
        "const express = require('express')\n"
        "const { z } = require('zod')\n"
        "const app = express()\n"
        f"const contactSchema = z.object({{ email: z.string().default('{SNIPPET_ADDRESS}') }})\n"
        "app.post('/contact', (req, res) => {\n"
        "  const input = contactSchema.parse(req.body)\n"
        f"  console.log('contact {SNIPPET_ADDRESS}', input.email)\n"
        "  res.json({ ok: true })\n"
        "})\n",
    )
    return root


def test_planted_address_on_snippet_lines_is_absent_from_every_format(tmp_path, capsys):
    root = snippet_repo(tmp_path / "repo")
    report = review(root)
    pointed = {
        f.rule_id
        for f in report.findings
        for loc in f.locations
        if SNIPPET_ADDRESS in (root / loc.file).read_text().splitlines()[loc.line - 1]
    }
    for rule_id in (
        "INV-SDK-RECEIVES-PII",
        "LEAK-LOGGED-PII",
        "BASE-LITERAL-PASSWORD-HASH",
        "INV-CATCHALL-JSON",
    ):
        assert rule_id in pointed, rule_id
    out_dir = tmp_path / "out"
    assert main(["scan", str(root), "--format", "md,json,sarif", "--out", str(out_dir)]) == 0
    outputs = [p.read_text() for p in out_dir.iterdir()]
    captured = capsys.readouterr()
    outputs += [captured.out, captured.err]
    for value in (SNIPPET_ADDRESS, SNIPPET_PASSWORD):
        assert not any(value in text for text in outputs), value
    assert any("<redacted:email>" in text for text in outputs)


def test_express_prisma_opens_no_network_connection(tmp_path, monkeypatch):
    root = build("express-prisma", tmp_path)

    def refuse(*args, **kwargs):
        raise AssertionError("network connection attempted")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    review(root, semgrep="off")


def test_every_rule_has_a_title_and_fix_without_em_dashes():
    reviews.available()
    for rule_id in rules.SPECS:
        text = rules.rule_text(rule_id)
        assert text.title and text.fix, rule_id
        assert chr(0x2014) not in f"{text.title}{text.detail}{text.fix}{text.proof_needed}", rule_id


def test_limits_found_by_the_comparison_are_listed_as_not_covered(tmp_path):
    report = review(build("express-prisma", tmp_path))
    assert any(
        n.startswith("Infrastructure hostnames and internal endpoints") for n in report.not_covered
    )
    assert any(
        n.startswith("Copies of personal data kept outside the repository")
        for n in report.not_covered
    )
    assert any(n.startswith("Screening new passwords") for n in report.not_covered)


def test_no_module_imports_a_private_name_from_another_module():
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "src"
    offenders = []
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("dpr"):
                offenders += [
                    f"{path.relative_to(root)}: {alias.name}"
                    for alias in node.names
                    if alias.name.startswith("_") and not alias.name.startswith("__")
                ]
    assert offenders == []


def test_every_source_module_stays_under_about_400_lines():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "src"
    sizes = {
        str(path.relative_to(root)): len(path.read_text(encoding="utf-8").splitlines())
        for path in root.rglob("*.py")
    }
    assert {rel: size for rel, size in sizes.items() if size > 410} == {}


# A capability URL: the random path segment is the only thing protecting these routes.
PATH_SECRET = "".join(format((i * 5 + 11) % 16, "x") for i in range(32))


def capability_repo(root):
    write(root, "requirements.txt", "django\nfastapi\n")
    write(
        root,
        "sms/urls.py",
        "from django.urls import path\nfrom sms import views\n\n"
        "urlpatterns = [\n"
        f"    path('sms/{PATH_SECRET}/delivery', views.delivery_hook),\n"
        "    path('sms/status/', views.status),\n]\n",
    )
    write(
        root,
        "sms/views.py",
        "from django.http import HttpResponse\n\n\n"
        "def delivery_hook(request):\n"
        "    Delivery.objects.create(ref=request.GET['ref'])\n"
        "    return HttpResponse('ok')\n\n\n"
        "def status(request):\n    return HttpResponse('ok')\n",
    )
    write(
        root,
        "api/main.py",
        "from fastapi import FastAPI\n\napp = FastAPI()\n\n\n"
        f"@app.post('/hooks/{PATH_SECRET}')\n"
        "def fastapi_hook(body: dict):\n    Event.create(**body)\n",
    )
    write(root, "web/package.json", '{"dependencies": {"express": "4.19.0"}}\n')
    write(
        root,
        "web/server.js",
        "const app = require('express')()\n"
        f"app.post('/webhook/{PATH_SECRET}', (req, res) => {{ db.save(req.body); res.send('ok') }})\n"
        "app.get('/health', (req, res) => res.send('ok'))\n",
    )
    return root


def test_secret_path_segment_never_reaches_any_output(tmp_path, capsys):
    root = capability_repo(tmp_path / "repo")
    report = review(root)
    paths = {route.path for route in report.detection.routes}
    assert {
        "/sms/<redacted:path-token>/delivery",
        "/sms/status",
        "/hooks/<redacted:path-token>",
        "/webhook/<redacted:path-token>",
        "/health",
    } <= paths
    assert PATH_SECRET not in render_markdown(report)
    [hook] = [
        f
        for f in report.findings
        if f.rule_id == "OWASP-A01-UNSIGNED-CALLBACK" and "/sms/" in f.title
    ]
    assert "protected only by a secret path segment" in hook.detail
    out_dir = tmp_path / "out"
    assert main(["scan", str(root), "--format", "md,json,sarif", "--out", str(out_dir)]) == 0
    captured = capsys.readouterr()
    outputs = [p.read_text() for p in out_dir.iterdir()] + [captured.out, captured.err]
    assert len(outputs) == 5
    assert not any(PATH_SECRET in text for text in outputs)
    assert any("<redacted:path-token>" in text for text in outputs)
