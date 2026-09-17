from dpr.api import review
from dpr.report.json_out import render_json
from dpr.report.markdown import render_markdown
from tests.reviews.helpers import findings_for, write

SEED_PW = "Demo" + "Adm1n" + "#2031"
SHARED_PW = "Reset" + "Me" + "!2031"


def seed_app(root):
    write(root, "api/requirements.txt", "fastapi\n")
    write(
        root,
        "api/app/db/seed.py",
        "from app.core.security import get_password_hash\n"
        "async def seed_users(db):\n"
        f"    admin_pw = '{SEED_PW}'\n"
        "    db.add(User(email='admin@example.invalid', password_hash=get_password_hash(admin_pw)))\n"
        "    other = get_password_hash(data.password)\n",
    )
    write(
        root,
        "api/scripts/migrate.py",
        "from passlib.context import CryptContext\npwd_context = CryptContext(schemes=['bcrypt'])\n"
        f"PLACEHOLDER = '{SHARED_PW}'\nPLACEHOLDER_HASH = pwd_context.hash(PLACEHOLDER)\n",
    )
    write(
        root,
        "api/scripts/users.py",
        f"USERS = [{{'email': 'a@example.invalid', 'password': '{SEED_PW}'}}]\n"
        "def run():\n    for user in USERS:\n        make_password(user['password'])\n",
    )
    write(
        root,
        "api/app/db/demo_seed.py",
        "import os\nDEFAULT = 'Fallback' + 'Only'\n"
        f"DEFAULT_PW = '{SHARED_PW}x'\n"
        "def seed():\n    pw = os.environ.get('SEED_ADMIN_PASSWORD', DEFAULT_PW)\n"
        "    return get_password_hash(pw)\n",
    )
    write(root, "api/tests/test_security.py", "get_password_hash('password123')\n")
    write(root, "README.md", f"# App\n\nDemo login: admin@example.invalid / {SEED_PW}\n")
    write(
        root,
        "web/lib/users.js",
        "const bcrypt = require('bcrypt')\nconst hashed = bcrypt.hashSync('Str1ng-Pw-2031', 10)\n",
    )
    return root


def test_literal_password_hash(tmp_path):
    root = seed_app(tmp_path)
    found = {
        f.locations[0].file: f for f in findings_for(root, "baseline", "BASE-LITERAL-PASSWORD-HASH")
    }
    assert set(found) == {
        "api/app/db/demo_seed.py",
        "api/app/db/seed.py",
        "api/scripts/migrate.py",
        "api/scripts/users.py",
        "web/lib/users.js",
    }
    seed = found["api/app/db/seed.py"]
    assert (seed.tag.value, seed.severity.value) == ("CONFIRMED", "critical")
    assert [str(loc) for loc in seed.locations] == [
        "api/app/db/seed.py:4",
        "README.md:3",
        "api/scripts/users.py:1",
    ]
    assert "module level" in found["api/scripts/migrate.py"].detail
    fallback = found["api/app/db/demo_seed.py"]
    assert (fallback.tag.value, fallback.severity.value) == ("INFERRED", "high")
    assert fallback.proof_needed


def test_password_text_never_reaches_output(tmp_path):
    root = seed_app(tmp_path)
    write(root, "api/scripts/inline.py", f"h = get_password_hash('{SEED_PW}')\n")
    report = review(root)
    outputs = render_markdown(report) + render_json(report)
    assert SEED_PW not in outputs and SHARED_PW not in outputs
    inline = [
        f for f in report.findings if f.locations and f.locations[0].file == "api/scripts/inline.py"
    ]
    assert inline and "<redacted:password>" in inline[0].snippet


def test_seed_on_start(tmp_path):
    root = seed_app(tmp_path)
    write(
        root,
        "api/startup.sh",
        "#!/bin/bash\n# Seed reference data\necho 'Seeding...'\n"
        "PYTHONPATH=. python -m app.db.seed || echo done\ngunicorn app.main:app --workers 2\n",
    )
    write(
        root,
        "render.yaml",
        "services:\n  - startCommand: python -m other.seed && uvicorn app:app\n    buildCommand: pip install seed-lib\n",
    )
    write(
        root, "web/package.json", '{"scripts": {"start": "node server.js", "seed": "node seed.js"}}'
    )
    write(root, "worker/start.sh", "python -m app.db.demo_seed\n")
    found = sorted(
        findings_for(root, "baseline", "BASE-SEED-ON-START"), key=lambda f: str(f.locations[0])
    )
    assert [(str(f.locations[0]), f.severity.value) for f in found] == [
        ("api/startup.sh:4", "critical"),
        ("render.yaml:2", "high"),
        ("worker/start.sh:1", "high"),
    ]
    assert found[0].refs == ("BASE-LITERAL-PASSWORD-HASH",)
    assert found[0].tag.value == "INFERRED"


def test_short_password_minimum(tmp_path):
    write(
        tmp_path,
        "app/schemas.py",
        "from pydantic import BaseModel, Field, field_validator\n"
        "class AdminCreate(BaseModel):\n    password: str\n"
        "    @field_validator('password')\n    @classmethod\n    def check(cls, v):\n"
        "        if len(v) < 6:\n            raise ValueError('short')\n        return v\n"
        "class Signup(BaseModel):\n    password: str = Field(min_length=12)\n"
        "    @field_validator('password')\n    @classmethod\n    def check(cls, v):\n"
        "        if len(v) < 8:\n            raise ValueError('short')\n        return v\n"
        "class Reset(BaseModel):\n    new_password: str = Field(min_length=4)\n"
        "def name_check(name):\n    if len(name) < 3:\n        raise ValueError('x')\n",
    )
    write(
        tmp_path,
        "site/settings.py",
        "AUTH_PASSWORD_VALIDATORS = [\n    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',\n"
        "     'OPTIONS': {'min_length': 6}},\n]\n",
    )
    write(
        tmp_path,
        "web/schema.ts",
        "export const s = z.object({ email: z.string().min(3), password: z.string().min(6) })\n"
        "export const login = z.object({ password: z.string().min(1) })\n",
    )
    found = findings_for(tmp_path, "baseline", "BASE-SHORT-PASSWORD-MIN")
    assert sorted((str(f.locations[0]), f.title) for f in found) == [
        ("app/schemas.py:19", "Passwords can be as short as 4 characters"),
        ("app/schemas.py:7", "Passwords can be as short as 6 characters"),
        ("site/settings.py:2", "Passwords can be as short as 6 characters"),
        ("web/schema.ts:1", "Passwords can be as short as 6 characters"),
    ]


def test_samesite_none_without_csrf(tmp_path):
    write(
        tmp_path,
        "infra/main.tf",
        'resource "x" "y" {\n  app_settings = {\n    COOKIE_SAMESITE = "none"\n  }\n}\n',
    )
    write(
        tmp_path, "api/security.py", "def cookie():\n    return {'samesite': settings.samesite}\n"
    )
    [f] = findings_for(tmp_path, "baseline", "BASE-SAMESITE-NONE-NO-CSRF")
    assert str(f.locations[0]) == "infra/main.tf:3" and f.tag.value == "INFERRED"
    write(
        tmp_path,
        "api/csrf.py",
        "def verify_csrf(request):\n    return request.headers.get('x-csrf-token')\n",
    )
    assert findings_for(tmp_path, "baseline", "BASE-SAMESITE-NONE-NO-CSRF") == []
