from tests.reviews.helpers import findings_for, write


def locs(found):
    return sorted((str(f.locations[0]), f.severity.value) for f in found)


def test_js_cookie_flags(tmp_path):
    write(
        tmp_path,
        "app/api/login/route.ts",
        "import { cookies } from 'next/headers'\n"
        "export async function POST() {\n"
        "  cookies().set('session', 'x', { path: '/' })\n"
        "  cookies().set('theme', 'dark', { httpOnly: true, secure: true, sameSite: 'lax' })\n"
        "  cookies().set({ name: 'token', value: 'y', httpOnly: true, secure: true, sameSite: 'none' })\n"
        "  cookies().set('flag', 'z', { ...defaults })\n"
        "}\n",
    )
    write(
        tmp_path,
        "server/app.js",
        "app.post('/x', (req, res) => {\n"
        "  res.cookie('sid', 'v', { httpOnly: true, secure: process.env.PROD === '1', sameSite: 'strict' })\n"
        "  res.setHeader('Set-Cookie', 'auth=abc; Path=/; Secure; SameSite=Lax')\n"
        "})\n",
    )
    assert locs(findings_for(tmp_path, "baseline", "BASE-COOKIE-HTTPONLY")) == [
        ("app/api/login/route.ts:3", "high"),
        ("server/app.js:3", "high"),
    ]
    assert locs(findings_for(tmp_path, "baseline", "BASE-COOKIE-SECURE")) == [
        ("app/api/login/route.ts:3", "high"),
    ]
    assert locs(findings_for(tmp_path, "baseline", "BASE-COOKIE-SAMESITE")) == [
        ("app/api/login/route.ts:3", "low"),
        ("app/api/login/route.ts:5", "high"),
    ]


def test_python_cookie_flags_and_django_settings(tmp_path):
    write(
        tmp_path,
        "api/auth.py",
        "from fastapi import Response\n"
        "def login(response: Response):\n"
        "    response.set_cookie('access_token', 't', httponly=True, secure=True)\n"
        "    response.set_cookie('prefs', 'p')\n"
        "    response.set_cookie(**cookie_settings())\n"
        "    response.set_cookie('refresh_token', 'r', httponly=True, secure=settings.secure, samesite='none')\n",
    )
    write(
        tmp_path,
        "site/settings.py",
        "INSTALLED_APPS = []\nSESSION_COOKIE_SECURE = False\nSESSION_COOKIE_HTTPONLY = True\n"
        "CSRF_COOKIE_SAMESITE = 'None'\n",
    )
    assert locs(findings_for(tmp_path, "baseline", "BASE-COOKIE-HTTPONLY")) == [
        ("api/auth.py:4", "low")
    ]
    assert locs(findings_for(tmp_path, "baseline", "BASE-COOKIE-SECURE")) == [
        ("api/auth.py:4", "low"),
        ("site/settings.py:2", "high"),
    ]
    assert locs(findings_for(tmp_path, "baseline", "BASE-COOKIE-SAMESITE")) == [
        ("api/auth.py:6", "high"),
        ("site/settings.py:4", "low"),
    ]


def test_debug_on(tmp_path):
    write(tmp_path, "proj/settings.py", "INSTALLED_APPS = []\nDEBUG = True\n")
    write(tmp_path, "other/settings.py", "INSTALLED_APPS = []\nDEBUG = env.bool('DEBUG', False)\n")
    write(tmp_path, "api/main.py", "from fastapi import FastAPI\napp = FastAPI(debug=True)\n")
    write(
        tmp_path,
        "api/config.py",
        "from pydantic_settings import BaseSettings\n"
        "class Settings(BaseSettings):\n    debug: bool = True\n    name: str = 'x'\n"
        "class Other(BaseSettings):\n    debug: bool = False\n",
    )
    write(tmp_path, "notes.py", "DEBUG = True\n")
    found = findings_for(tmp_path, "baseline", "BASE-DEBUG-ON")
    assert sorted(str(f.locations[0]) for f in found) == [
        "api/main.py:2",
        "proj/settings.py:2",
    ]
    assert {f.tag.value for f in found} == {"INFERRED"}


def test_weak_hash(tmp_path):
    write(
        tmp_path,
        "accounts/hashing.py",
        "import hashlib\n"
        "def hash_password(raw):\n    return hashlib.md5(raw.encode()).hexdigest()\n"
        "def etag(body):\n    return hashlib.sha256(body).hexdigest()\n"
        "digest = hashlib.sha1(password.encode())\n",
    )
    write(
        tmp_path,
        "site/settings.py",
        "PASSWORD_HASHERS = [\n    'django.contrib.auth.hashers.MD5PasswordHasher',\n"
        "    'django.contrib.auth.hashers.PBKDF2PasswordHasher',\n]\n",
    )
    write(
        tmp_path,
        "safe/settings.py",
        "PASSWORD_HASHERS = ['django.contrib.auth.hashers.Argon2PasswordHasher', 'x.MD5PasswordHasher']\n",
    )
    write(
        tmp_path,
        "lib/users.js",
        "const crypto = require('crypto')\n"
        "function savePassword(pw) { return crypto.createHash('sha1').update(pw).digest('hex') }\n"
        "const fileId = crypto.createHash('md5').update(buffer).digest('hex')\n",
    )
    found = findings_for(tmp_path, "baseline", "BASE-WEAK-HASH")
    assert sorted((str(f.locations[0]), f.tag.value) for f in found) == [
        ("accounts/hashing.py:3", "INFERRED"),
        ("accounts/hashing.py:6", "INFERRED"),
        ("lib/users.js:2", "INFERRED"),
        ("site/settings.py:2", "CONFIRMED"),
    ]
    assert found[0].severity.value == "critical"


def test_mixed_content(tmp_path):
    write(
        tmp_path,
        "public/index.html",
        '<html xmlns="http://www.w3.org/1999/xhtml">\n'
        '<script src="http://cdn.example.com/a.js"></script>\n'
        '<link href="https://fonts.example.com/b.css">\n'
        '<img src="http://localhost:3000/x.png">\n',
    )
    write(
        tmp_path,
        "src/Logo.tsx",
        'export const Logo = () => <img src="https://cdn.example.com/l.png" />\n',
    )
    write(tmp_path, "static/pdfjs/web/viewer.js", "viewer();\n")
    write(tmp_path, "static/pdfjs/api/draft/page.html", '<img src="http://cdn.example.com/p.png">')
    [f] = findings_for(tmp_path, "baseline", "BASE-MIXED-CONTENT")
    # The copied library's own HTML is vendored and not scanned.
    assert [str(loc) for loc in f.locations] == ["public/index.html:2"]


def test_weak_hash_skips_random_tokens_but_keeps_passwords(tmp_path):
    write(
        tmp_path,
        "src/auth.js",
        "const crypto = require('crypto')\n"
        "function createPasswordResetToken(user) {\n"
        "  const resetToken = crypto.randomBytes(32).toString('hex')\n"
        "  user.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex')\n"
        "  return resetToken\n}\n"
        "function hashPasswordToken(password) {\n"
        "  return crypto.createHash('sha256').update(password).digest('hex')\n}\n"
        "function passwordFingerprint(user) {\n"
        "  const raw = crypto.randomBytes(16)\n"
        "  return crypto.createHash('md5').update(raw).digest('hex')\n}\n",
    )
    write(
        tmp_path,
        "app/tokens.py",
        "import hashlib, secrets\n"
        "def create_password_reset_token():\n"
        "    raw = secrets.token_urlsafe(32)\n"
        "    return raw, hashlib.sha256(raw.encode()).hexdigest()\n"
        "def store_password_api_key(user, api_key):\n"
        "    user.api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()\n"
        "def password_otp(code):\n"
        "    return hashlib.sha256(code.encode()).hexdigest()\n"
        "def hash_password(password, reset_token):\n"
        "    return hashlib.sha256((password + reset_token).encode()).hexdigest()\n",
    )
    found = findings_for(tmp_path, "baseline", "BASE-WEAK-HASH")
    assert sorted((str(f.locations[0]), f.severity.value) for f in found) == [
        ("app/tokens.py:10", "critical"),
        ("src/auth.js:8", "critical"),
    ]


def test_weak_hasher_in_test_and_ci_settings_is_not_reported(tmp_path):
    md5 = "INSTALLED_APPS = ['shop']\nPASSWORD_HASHERS = ['django.contrib.auth.hashers.MD5PasswordHasher']\n"
    write(tmp_path, "site/site/settings.py", "INSTALLED_APPS = ['shop']\n")
    write(tmp_path, "site/site/ci_settings.py", md5)
    write(tmp_path, "site/site/tests_settings.py", md5)
    write(tmp_path, "site/site/prod.py", md5)
    found = findings_for(tmp_path, "baseline", "BASE-WEAK-HASH")
    assert [str(f.locations[0]) for f in found] == ["site/site/prod.py:2"]
