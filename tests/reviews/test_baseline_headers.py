import pytest

from dpr import reviews, rules
from dpr.adapters.headers import HeaderRead
from dpr.api import review
from dpr.discovery.detect import detect
from dpr.reviews import baseline, baseline_headers
from dpr.reviews.baseline_headers import weak_csp_reason
from dpr.reviews.headers_static import csp_values, surfaces
from dpr.walk import RepoIndex
from tests.reviews.helpers import findings_for, write

SWA = '{\n  "globalHeaders": {\n    "X-Frame-Options": "DENY",\n    "Referrer-Policy": "no-referrer"\n  }\n}\n'


def context(root, **options):
    reviews.available()
    index = RepoIndex(root)
    return rules.Context(index=index, detection=detect(index), options=rules.Options(**options))


def repo(root):
    write(root, "web/package.json", "{}")
    write(root, "web/staticwebapp.config.json", SWA)
    write(root, "web/src/main.tsx", "export {}\n")
    write(root, "api/requirements.txt", "fastapi\n")
    write(
        root,
        "api/app/main.py",
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "@app.middleware('http')\nasync def headers(request, call_next):\n"
        "    response = await call_next(request)\n"
        "    response.headers['Strict-Transport-Security'] = 'max-age=31536000'\n"
        "    response.headers['X-Content-Type-Options'] = 'nosniff'\n"
        "    return response\n",
    )
    write(root, "site/package.json", "{}")
    write(root, "site/next.config.js", "module.exports = { reactStrictMode: true }\n")
    write(
        root,
        "site/vercel.json",
        '{"headers": [{"source": "/(.*)", "headers": [{"key": "Permissions-Policy", "value": "camera=()"}]}]}',
    )
    write(root, "legacy/package.json", "{}")
    write(
        root,
        "legacy/server.js",
        "const express = require('express')\nconst app = express()\napp.use(helmet())\n",
    )
    return root


def test_surfaces_collect_headers_per_app(tmp_path):
    found = {s.name: s for s in surfaces(context(repo(tmp_path)))}
    assert set(found) == {
        "api/app/main.py",
        "legacy/server.js",
        "site/next.config.js",
        "site/vercel.json",
        "web/staticwebapp.config.json",
    }
    assert found["web/staticwebapp.config.json"].headers == {"x-frame-options", "referrer-policy"}
    assert found["web/staticwebapp.config.json"].location.line == 2
    assert found["api/app/main.py"].headers == {
        "strict-transport-security",
        "x-content-type-options",
    }
    assert found["api/app/main.py"].kind == "FastAPI app"
    assert "permissions-policy" not in found["legacy/server.js"].headers
    assert "content-security-policy" in found["legacy/server.js"].headers
    assert found["site/vercel.json"].headers == {"strict-transport-security", "permissions-policy"}


def test_missing_headers_are_unverified_without_url(tmp_path):
    root = repo(tmp_path)
    [hsts] = findings_for(root, "baseline", "BASE-HEADER-MISSING-HSTS")
    assert hsts.tag.value == "UNVERIFIED" and hsts.severity.value == "low"
    assert [str(loc) for loc in hsts.locations] == [
        "site/next.config.js:1",
        "web/staticwebapp.config.json:2",
    ]
    assert "web/staticwebapp.config.json (static host config)" in hsts.detail
    [csp] = findings_for(root, "baseline", "BASE-HEADER-MISSING-CSP")
    assert len(csp.locations) == 3 and csp.severity.value == "medium"
    assert findings_for(root, "baseline", "BASE-HEADER-MISSING-FRAME")[0].severity.value == "low"


def test_django_settings_surface(tmp_path):
    write(
        tmp_path,
        "proj/settings.py",
        "INSTALLED_APPS = []\nMIDDLEWARE = ['django.middleware.security.SecurityMiddleware',\n"
        "  'django.middleware.clickjacking.XFrameOptionsMiddleware']\nSECURE_HSTS_SECONDS = 31536000\n",
    )
    [surface] = surfaces(context(tmp_path))
    assert surface.headers == {
        "strict-transport-security",
        "x-content-type-options",
        "referrer-policy",
        "x-frame-options",
    }


def test_weak_csp_reason():
    assert weak_csp_reason("default-src 'self'; script-src 'self' 'unsafe-inline'") == (
        "script-src allows 'unsafe-inline'"
    )
    assert weak_csp_reason("default-src * data:") == "default-src allows any origin (*)"
    assert weak_csp_reason("default-src 'self'; style-src 'unsafe-inline'") is None


def test_csp_weak_and_version_disclosure_from_config(tmp_path):
    root = repo(tmp_path)
    write(
        root,
        "site/next.config.js",
        "module.exports = { async headers() { return [{ source: '/(.*)', headers: [\n"
        "  { key: 'Content-Security-Policy', value: \"default-src 'self'; script-src 'self' 'unsafe-inline'\" },\n"
        "] }] } }\n",
    )
    write(root, "other/package.json", "{}")
    write(root, "other/app.js", "const express = require('express')\nconst app = express()\n")
    [weak] = findings_for(root, "baseline", "BASE-CSP-WEAK")
    assert str(weak.locations[0]) == "site/next.config.js:2"
    found = findings_for(root, "baseline", "BASE-VERSION-DISCLOSURE")
    assert sorted(str(f.locations[0]) for f in found) == ["other/app.js:2", "site/next.config.js:1"]
    write(root, "site/next.config.js", "module.exports = { poweredByHeader: false }\n")
    assert [
        str(f.locations[0]) for f in findings_for(root, "baseline", "BASE-VERSION-DISCLOSURE")
    ] == ["other/app.js:2"]


READS = [
    HeaderRead(
        "https root",
        "https://app.example.com/",
        200,
        {
            "server": "nginx/1.25.3",
            "content-security-policy": "default-src *",
            "x-frame-options": "DENY",
        },
    ),
    HeaderRead(
        "https login page", "https://app.example.com/login", 200, {"cache-control": "private"}
    ),
    HeaderRead("http root", "http://app.example.com/", 200, {}),
]


@pytest.fixture
def live(monkeypatch):
    calls = []

    def fake(url, login_path):
        calls.append((url, login_path))
        return READS

    monkeypatch.setattr(baseline_headers, "read_headers", fake)
    return calls


def test_live_reads_confirm_findings(tmp_path, live):
    root = repo(tmp_path)
    options = {"url": "https://app.example.com", "owns_host": True}
    [hsts] = findings_for(root, "baseline", "BASE-HEADER-MISSING-HSTS", **options)
    assert hsts.tag.value == "CONFIRMED" and str(hsts.locations[0]) == "https://app.example.com/:1"
    assert findings_for(root, "baseline", "BASE-HEADER-MISSING-FRAME", **options) == []
    assert findings_for(root, "baseline", "BASE-CSP-WEAK", **options)[0].tag.value == "CONFIRMED"
    assert (
        findings_for(root, "baseline", "BASE-NO-HTTPS-REDIRECT", **options)[0].severity.value
        == "high"
    )
    assert len(findings_for(root, "baseline", "BASE-CACHE-AUTH", **options)) == 1
    version = findings_for(root, "baseline", "BASE-VERSION-DISCLOSURE", **options)
    assert any(f.tag.value == "CONFIRMED" for f in version)
    assert live[0] == ("https://app.example.com", "/login")


def test_login_path_from_routes_and_option(tmp_path):
    write(tmp_path, "app/api/auth/signin/route.ts", "export async function POST() {}\n")
    assert baseline_headers.login_path(context(tmp_path)) == "/api/auth/signin"
    assert baseline_headers.login_path(context(tmp_path, login_path="/enter")) == "/enter"
    write(tmp_path / "other", "a.py", "x = 1\n")
    assert baseline_headers.login_path(context(tmp_path / "other")) == "/login"


def test_section_tables_and_failures(tmp_path, live, monkeypatch):
    root = repo(tmp_path)
    ctx = context(root)
    titles = [p.title for p in baseline.run(ctx).parts]
    assert titles == [
        "How headers were checked",
        "Security headers by surface",
        "Fix list",
        "Password storage and account enumeration",
    ]
    failed = [HeaderRead("https root", "https://app.example.com/", error="timed out"), *READS[1:]]
    monkeypatch.setattr(baseline_headers, "read_headers", lambda url, login: failed)
    ctx = context(root, url="https://app.example.com", owns_host=True)
    section = baseline.run(ctx)
    table = next(p for p in section.parts if p.title == "Live header read")
    assert table.rows[0][2:] == ("failed", "timed out")
    assert "Live header read of https://app.example.com/ failed: timed out" in ctx.not_covered


def test_root_app_does_not_take_headers_from_nested_app(tmp_path):
    root = tmp_path
    write(root, "package.json", "{}")
    write(root, "next.config.js", "module.exports = { reactStrictMode: true }\n")
    write(root, "api/requirements.txt", "fastapi\n")
    write(
        root,
        "api/app/main.py",
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "@app.middleware('http')\nasync def headers(request, call_next):\n"
        "    response = await call_next(request)\n"
        "    response.headers['Strict-Transport-Security'] = 'max-age=31536000'\n"
        "    response.headers['X-Content-Type-Options'] = 'nosniff'\n"
        "    return response\n",
    )
    found = {s.name: s for s in surfaces(context(root))}
    assert found["next.config.js"].headers == frozenset()
    assert found["api/app/main.py"].headers == {
        "strict-transport-security",
        "x-content-type-options",
    }
    [hsts] = findings_for(root, "baseline", "BASE-HEADER-MISSING-HSTS")
    assert [str(loc) for loc in hsts.locations] == ["next.config.js:1"]


def test_test_files_and_comments_do_not_count(tmp_path):
    root = tmp_path
    write(root, "site/package.json", "{}")
    write(
        root,
        "site/next.config.js",
        "module.exports = { async headers() { return [{ source: '/(.*)', headers: [\n"
        "  { key: 'Strict-Transport-Security', value: 'max-age=31536000' },\n"
        "] }] } }\n",
    )
    write(
        root,
        "site/tests/security.test.js",
        "test('has frame protection', () => {\n"
        "  expect(headers['x-frame-options']).toBe('DENY')\n"
        "  const csp = \"default-src *; script-src 'unsafe-inline'\"\n"
        "})\n",
    )
    write(
        root,
        "site/src/notes.js",
        "// TODO set 'Content-Security-Policy'\n/* 'referrer-policy' */\nexport {}\n",
    )
    [surface] = surfaces(context(root))
    assert surface.headers == {"strict-transport-security"}
    assert not any("unsafe-inline" in policy for policy, _ in csp_values(context(root)))


def test_comment_mask_is_per_language(tmp_path):
    root = tmp_path
    write(root, "app/package.json", "{}")
    write(root, "app/next.config.js", "module.exports = {}\n")
    write(
        root,
        "app/src/server.js",
        "class App {\n"
        "  #configure() { this.headers.set('Strict-Transport-Security', 'max-age=31536000') }\n"
        "}\n"
        "// res.setHeader('Permissions-Policy', 'camera=()')\n",
    )
    write(root, "api/requirements.txt", "fastapi\n")
    write(
        root,
        "api/app/main.py",
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        'limit = total // 2; response.headers["X-Frame-Options"] = "DENY"\n'
        '# response.headers["Referrer-Policy"] = "no-referrer"\n',
    )
    found = {s.name: s for s in surfaces(context(root))}
    next_headers = found["app/next.config.js"].headers
    assert "strict-transport-security" in next_headers
    assert "permissions-policy" not in next_headers
    api_headers = found["api/app/main.py"].headers
    assert "x-frame-options" in api_headers
    assert "referrer-policy" not in api_headers


def test_default_review_never_reads_headers(tmp_path, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("live header read without a URL")

    monkeypatch.setattr(baseline_headers, "read_headers", refuse)
    report = review(repo(tmp_path))
    assert "baseline" in report.sections


def test_nonce_or_hash_with_strict_dynamic_ignores_unsafe_inline():
    strict = (
        "default-src 'self'; script-src 'nonce-${nonce}' 'strict-dynamic' 'unsafe-inline' https:"
    )
    assert weak_csp_reason(strict) is None
    hashed = "script-src 'sha256-abc=' 'strict-dynamic' 'unsafe-inline'"
    assert weak_csp_reason(hashed) is None
    assert weak_csp_reason("script-src 'nonce-abc' 'unsafe-inline'") == (
        "script-src allows 'unsafe-inline'"
    )
