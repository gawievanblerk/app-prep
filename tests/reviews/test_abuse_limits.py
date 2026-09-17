from tests.reviews.helpers import findings_for, write

LIMITER = (
    "from slowapi import Limiter\nfrom slowapi.util import get_remote_address\n"
    "def get_limiter():\n"
    "    if settings.redis_url:\n        storage_uri = settings.redis_url\n"
    "    else:\n        storage_uri = 'memory://'\n"
    "    return Limiter(\n        key_func=get_remote_address,\n        storage_uri=storage_uri,\n"
    "        default_limits=['100/minute'],\n    )\n"
    "plain = Limiter(key_func=get_remote_address)\n"
)


def api(root):
    write(root, "api/requirements.txt", "fastapi\nslowapi\n")
    write(root, "api/app/rate_limit.py", LIMITER)
    write(root, "api/startup.sh", "gunicorn app.main:app --workers 2\n")
    write(root, "render.yaml", "services: []\n")
    return root


def test_inmemory_limiter_needs_multiple_processes(tmp_path):
    root = api(tmp_path)
    found = findings_for(root, "abuse", "ABUSE-INMEMORY-LIMITER")
    assert sorted((str(f.locations[0]), f.tag.value) for f in found) == [
        ("api/app/rate_limit.py:13", "CONFIRMED"),
        ("api/app/rate_limit.py:8", "INFERRED"),
    ]
    assert str(found[0].locations[1]) == "api/startup.sh:1"
    write(root, "api/startup.sh", "gunicorn app.main:app --workers 1\n")
    assert findings_for(root, "abuse", "ABUSE-INMEMORY-LIMITER") == []


def test_express_limiter_without_store(tmp_path):
    write(tmp_path, "vercel.json", "{}")
    write(
        tmp_path,
        "server/app.js",
        "const limiter = rateLimit({ windowMs: 60000, max: 5 })\n"
        "const shared = rateLimit({ windowMs: 60000, max: 5, store: new RedisStore(), keyGenerator: (r) => r.user.id })\n"
        "const attempts = new Map()\n",
    )
    found = findings_for(tmp_path, "abuse", "ABUSE-INMEMORY-LIMITER")
    assert sorted((str(f.locations[0]), f.tag.value) for f in found) == [
        ("server/app.js:1", "CONFIRMED"),
        ("server/app.js:3", "INFERRED"),
    ]
    assert [
        str(f.locations[0]) for f in findings_for(tmp_path, "abuse", "ABUSE-LIMITER-PROXY-IP")
    ] == ["server/app.js:1"]


def test_default_limits_not_applied_and_proxy_key(tmp_path):
    root = api(tmp_path)
    [unwired] = findings_for(root, "abuse", "ABUSE-LIMITER-NOT-APPLIED")
    assert str(unwired.locations[0]) == "api/app/rate_limit.py:11"
    proxy = findings_for(root, "abuse", "ABUSE-LIMITER-PROXY-IP")
    assert sorted(str(f.locations[0]) for f in proxy) == [
        "api/app/rate_limit.py:13",
        "api/app/rate_limit.py:9",
    ]
    write(root, "api/app/main.py", "app.add_middleware(SlowAPIMiddleware)\n")
    write(root, "api/startup.sh", "gunicorn app.main:app --workers 2 --forwarded-allow-ips='*'\n")
    assert findings_for(root, "abuse", "ABUSE-LIMITER-NOT-APPLIED") == []
    assert findings_for(root, "abuse", "ABUSE-LIMITER-PROXY-IP") == []


def test_upload_read_without_limit(tmp_path):
    write(
        tmp_path,
        "api/files.py",
        "from fastapi import APIRouter, File, UploadFile\nrouter = APIRouter()\n"
        "@router.post('/a')\nasync def a(file: UploadFile = File(...)):\n"
        "    content = await file.read()\n    if len(content) > MAX:\n        raise ValueError()\n"
        "@router.post('/b')\nasync def b(file: UploadFile = File(...)):\n    data = await file.read()\n"
        "@router.post('/c')\nasync def c(file: UploadFile = File(...)):\n    chunk = await file.read(1024)\n",
    )
    found = sorted(
        findings_for(tmp_path, "abuse", "ABUSE-UPLOAD-UNBOUNDED"), key=lambda f: f.locations[0].line
    )
    assert [(str(f.locations[0]), f.detail) for f in found] == [
        (
            "api/files.py:5",
            "The handler reads the whole upload into memory and only then checks its size.",
        ),
        ("api/files.py:10", "The handler reads the whole upload into memory with no size limit."),
    ]


INMEMORY_LIMITER = (
    "from slowapi import Limiter\nfrom slowapi.util import get_remote_address\n"
    "limiter = Limiter(key_func=get_remote_address)\n"
)


def test_multi_process_ignores_comments_and_other_tools(tmp_path):
    commented = tmp_path / "commented"
    write(commented, "api/app/rate_limit.py", INMEMORY_LIMITER)
    write(
        commented,
        "startup.sh",
        "# gunicorn app:app --workers 4\ngunicorn app:app --workers 1\n",
    )
    assert findings_for(commented, "abuse", "ABUSE-INMEMORY-LIMITER") == []

    other_tool = tmp_path / "other_tool"
    write(other_tool, "api/app/rate_limit.py", INMEMORY_LIMITER)
    write(other_tool, "start.sh", "curl -w 4 https://example.com\n")
    assert findings_for(other_tool, "abuse", "ABUSE-INMEMORY-LIMITER") == []

    procfile = tmp_path / "procfile"
    write(procfile, "api/app/rate_limit.py", INMEMORY_LIMITER)
    write(procfile, "Procfile", "web: gunicorn app:app -w 3\n")
    [found] = findings_for(procfile, "abuse", "ABUSE-INMEMORY-LIMITER")
    assert str(found.locations[1]) == "Procfile:1"

    pm2 = tmp_path / "pm2"
    write(pm2, "api/app/rate_limit.py", INMEMORY_LIMITER)
    write(pm2, "startup.sh", "pm2 start app.js -i max\n")
    [found] = findings_for(pm2, "abuse", "ABUSE-INMEMORY-LIMITER")
    assert str(found.locations[1]) == "startup.sh:1"
