import json
import socket

import pytest

from dpr import reviews, rules
from dpr.api import review
from dpr.cli import main
from dpr.model import Tag
from dpr.report.json_out import render_json
from dpr.report.markdown import BANNED_PHRASES, render_markdown
from dpr.report.sarif import render_sarif
from tests.fixture_builder import SECRETS, build
from tests.reviews.helpers import write

BAD = ("next-supabase-bad", "django-bad", "fastapi-bad")


@pytest.mark.parametrize("name", BAD)
def test_no_secret_value_in_any_format(tmp_path, capsys, name):
    root = build(name, tmp_path)
    report = review(root)
    outputs = [render_markdown(report), render_sarif(report), repr(report.findings)]
    out_dir = tmp_path / "out"
    assert main(["scan", str(root), "--format", "md,json,sarif", "--out", str(out_dir)]) == 0
    outputs += [p.read_text() for p in out_dir.iterdir()]
    captured = capsys.readouterr()
    outputs += [captured.out, captured.err]
    for secret in SECRETS:
        for text in outputs:
            assert secret not in text
    sarif = json.loads(next(p for p in out_dir.iterdir() if p.suffix == ".sarif").read_text())
    assert len(sarif["runs"][0]["results"]) == len(report.findings)


@pytest.mark.parametrize("name", BAD)
def test_evidence_rules_and_wording_hold(tmp_path, name):
    report = review(build(name, tmp_path))
    for finding in report.findings:
        assert finding.tag is not Tag.UNKNOWN
        if finding.tag is Tag.CONFIRMED:
            assert finding.locations, finding.rule_id
        if finding.tag is Tag.INFERRED:
            assert finding.proof_needed, finding.rule_id
    text = render_markdown(report)
    assert not any(phrase in text.lower() for phrase in BANNED_PHRASES)
    assert chr(0x2014) not in text


@pytest.mark.parametrize("name", BAD)
def test_default_run_opens_no_network_connection(tmp_path, monkeypatch, name):
    root = build(name, tmp_path)

    def refuse(*args, **kwargs):
        raise AssertionError("network connection attempted")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    review(root, semgrep="off")


def test_every_milestone_2_rule_has_owasp_or_is_a_leak_or_rls_rule():
    reviews.available()
    for rule_id, spec in rules.SPECS.items():
        if spec.review in ("baseline", "owasp", "abuse"):
            assert spec.owasp, rule_id


URL_KEY = "c0ffee" + "9f8e7d6c5b4a" + "3210"
CLI_PASSWORD = "Seed" + "Admin-" + "88231"
CLI_QUOTED = "Quoted" + " Seed-" + "44120"
ENV_PASSWORD = "Env" + "Seed-" + "73310"
REDIS_PASSWORD = "red" + "is-pass-" + "5521"
LONG_PASSWORD = "Corr" + "ectHorseBattery" + "Staple-9931"
JS_API_KEY = "js" + "ApiKey-" + "60017"
PY_DB_PASSWORD = "py" + "DbPass-" + "11873"
SESSION_SECRET = "session" + "Secret-" + "20944"
CONCAT_KEY = "LIVE" + "wx7Hq2mZ" + "91Ab"
SPLIT_A = "Split" + "Half-One-" + "5521"
SPLIT_B = "Split" + "Half-Two-" + "5522"
ESCAPED = "it" + "\\'s-Secret-" + "4411"
TRIPLE = "Triple" + "Quoted-Line-" + "One-8812"
FORM_QUOTED = "form" + "Quoted-" + "30551"
ENV_DEFAULT = "env" + "Default-" + "61207"
AUTH_PAIR = "auth" + "Pair-" + "77013"
CORPUS = (
    ENV_DEFAULT,
    AUTH_PAIR,
    FORM_QUOTED,
    CONCAT_KEY,
    SPLIT_A,
    SPLIT_B,
    ESCAPED,
    ESCAPED.replace("\\'", "'"),
    TRIPLE,
    URL_KEY,
    CLI_PASSWORD,
    CLI_QUOTED,
    ENV_PASSWORD,
    REDIS_PASSWORD,
    LONG_PASSWORD,
    JS_API_KEY,
    PY_DB_PASSWORD,
    SESSION_SECRET,
)


def credential_corpus(root):
    """One repository with each credential shape on a line that some rule prints as a snippet."""
    write(root, "requirements.txt", "fastapi==0.110.0\nslowapi==0.1.9\npasslib==1.7.4\n")
    write(root, "render.yaml", "services:\n  - type: web\n    startCommand: uvicorn app.main:app\n")
    write(
        root,
        "src/weather.js",
        "export async function forecast(city, base, t) {\n"
        f'  const url = "https://api.weather.example/v1?api_key={URL_KEY}&city=" + city\n'
        f'  const apiKey = "{JS_API_KEY}"; const next = base + "?token=" + t\n'
        "  return fetch(url)\n}\n",
    )
    write(
        root,
        "startup.sh",
        "#!/bin/sh\n"
        f"python -m app.seed --admin-password {CLI_PASSWORD}\n"
        f'python -m app.seed --password "{CLI_QUOTED}"\n'
        f"ADMIN_PASSWORD={ENV_PASSWORD} python -m app.seed\n"
        "uvicorn app.main:app\n",
    )
    write(
        root,
        "app/main.py",
        "from fastapi import FastAPI\nfrom slowapi import Limiter\n"
        "from slowapi.util import get_remote_address\napp = FastAPI()\n"
        "limiter = Limiter(key_func=get_remote_address, "
        f'storage_uri="redis://:{REDIS_PASSWORD}@cache:6379/0", default_limits=["100/hour"])\n',
    )
    head = '    db.add(User(email="admin@example.invalid", note="'
    tail = '", password_hash=pwd_context.hash("'
    pad = "x" * (190 - len(head) - len(tail))
    write(
        root,
        "app/seed.py",
        "from passlib.context import CryptContext\npwd_context = CryptContext(schemes=['bcrypt'])\n\n"
        f'def seed(db):\n{head}{pad}{tail}{LONG_PASSWORD}")))\n',
    )
    write(
        root,
        "app/reports.py",
        "def report(cursor, column):\n"
        f'    DB_PASSWORD = "{PY_DB_PASSWORD}"; cursor.execute("select " + column)\n',
    )
    write(
        root,
        "app/sessions.py",
        f'SESSION = {{"same_site": "none", "secret": "{SESSION_SECRET}"}}\n',
    )
    write(
        root,
        "src/forecast.js",
        "export async function daily(city) {\n"
        '  const url = "https://api.weather.example/v1?city=" + city + "&api_key=" + '
        f'"{CONCAT_KEY}"\n'
        "  return fetch(url)\n}\n",
    )
    write(
        root,
        "app/login.py",
        f"def form(user):\n    return f\"user={{user}}&password='{FORM_QUOTED}'\"\n",
    )
    write(
        root,
        "app/settings.py",
        "import os\nINSTALLED_APPS = []\n"
        'DEBUG = os.environ.get("DEBUG", "True"); '
        f'API_TOKEN = os.environ.get("API_TOKEN", "{ENV_DEFAULT}")\n',
    )
    write(
        root,
        "app/mail.py",
        f'import requests\n\ndef send():\n    requests.post("u", auth=("api", "{AUTH_PAIR}"))\n',
    )
    hasher = "from passlib.context import CryptContext\npwd_context = CryptContext(schemes=['bcrypt'])\n\n"
    write(
        root,
        "app/seed_split.py",
        f'{hasher}def seed(db):\n    db.add(User(password_hash=pwd_context.hash("{SPLIT_A}" "{SPLIT_B}")))\n',
    )
    write(
        root,
        "app/seed_escaped.py",
        f"{hasher}def seed(db):\n    db.add(User(password_hash=pwd_context.hash('{ESCAPED}')))\n",
    )
    write(
        root,
        "app/seed_triple.py",
        f'{hasher}def seed(db):\n    db.add(User(password_hash=pwd_context.hash("""{TRIPLE}\nline two""")))\n',
    )
    return root


def test_credential_shapes_never_reach_any_output(tmp_path, capsys):
    root = credential_corpus(tmp_path / "corpus")
    report = review(root)
    fired = {(f.rule_id, f.locations[0].file) for f in report.findings if f.snippet}
    assert {
        ("OWASP-A02-SECRET-IN-URL", "src/weather.js"),
        ("BASE-SEED-ON-START", "startup.sh"),
        ("ABUSE-LIMITER-NOT-APPLIED", "app/main.py"),
        ("ABUSE-LIMITER-PROXY-IP", "app/main.py"),
        ("BASE-LITERAL-PASSWORD-HASH", "app/seed.py"),
        ("OWASP-A03-RAW-SQL", "app/reports.py"),
        ("BASE-SAMESITE-NONE-NO-CSRF", "app/sessions.py"),
        ("OWASP-A02-SECRET-IN-URL", "src/forecast.js"),
        ("OWASP-A02-SECRET-IN-URL", "app/login.py"),
        ("BASE-LITERAL-PASSWORD-HASH", "app/seed_split.py"),
        ("BASE-LITERAL-PASSWORD-HASH", "app/seed_escaped.py"),
        ("BASE-LITERAL-PASSWORD-HASH", "app/seed_triple.py"),
        ("BASE-DEBUG-ON", "app/settings.py"),
    } <= fired
    rules_fired = {f.rule_id for f in report.findings}
    assert {"LEAK-SECRET-ENV-DEFAULT", "LEAK-LITERAL-HTTP-AUTH"} <= rules_fired
    outputs = [render_markdown(report), render_json(report), render_sarif(report)]
    out_dir = tmp_path / "out"
    assert main(["scan", str(root), "--format", "md,json,sarif", "--out", str(out_dir)]) == 0
    outputs += [p.read_text() for p in out_dir.iterdir()]
    captured = capsys.readouterr()
    outputs += [captured.out, captured.err]
    for value in CORPUS:
        for text in outputs:
            assert value not in text
            assert value[:10] not in text
