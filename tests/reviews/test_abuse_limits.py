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
        ("api/app/rate_limit.py:13", "INFERRED"),
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
        "const rateLimit = require('express-rate-limit')\n"
        "const limiter = rateLimit({ windowMs: 60000, max: 5 })\n"
        "const shared = rateLimit({ windowMs: 60000, max: 5, store: new RedisStore(), keyGenerator: (r) => r.user.id })\n"
        "const attempts = new Map()\n",
    )
    found = findings_for(tmp_path, "abuse", "ABUSE-INMEMORY-LIMITER")
    assert sorted((str(f.locations[0]), f.tag.value) for f in found) == [
        ("server/app.js:2", "CONFIRMED"),
        ("server/app.js:4", "INFERRED"),
    ]
    assert {str(f.locations[1]) for f in found} == {"vercel.json:1"}
    assert [
        str(f.locations[0]) for f in findings_for(tmp_path, "abuse", "ABUSE-LIMITER-PROXY-IP")
    ] == ["server/app.js:2"]


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


def test_multi_process_joins_continued_shell_lines(tmp_path):
    continued = tmp_path / "continued"
    write(continued, "api/app/rate_limit.py", INMEMORY_LIMITER)
    write(
        continued,
        "startup.sh",
        'LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}" PYTHONPATH=/home/site/wwwroot gunicorn app.main:app \\\n'
        "    --worker-class uvicorn.workers.UvicornWorker \\\n"
        "    --workers 2 \\\n"
        "    --bind 0.0.0.0:${PORT:-8000} \\\n"
        "    --timeout 120\n",
    )
    [found] = findings_for(continued, "abuse", "ABUSE-INMEMORY-LIMITER")
    assert str(found.locations[1]) == "startup.sh:3"

    echo_only = tmp_path / "echo_only"
    write(echo_only, "api/app/rate_limit.py", INMEMORY_LIMITER)
    write(echo_only, "startup.sh", "echo starting \\\n--workers 4\n")
    assert findings_for(echo_only, "abuse", "ABUSE-INMEMORY-LIMITER") == []


def test_custom_rate_limit_helper_is_not_express_rate_limit(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"next": "14", "@upstash/ratelimit": "1"}}')
    write(tmp_path, "vercel.json", "{}")
    write(
        tmp_path,
        "lib/rate-limit.ts",
        "import { Ratelimit } from '@upstash/ratelimit'\nimport { Redis } from '@upstash/redis'\n"
        "const limiter = new Ratelimit({ redis: Redis.fromEnv(), limiter: Ratelimit.slidingWindow(10, '1 m') })\n"
        "export async function rateLimit(key: string) { return limiter.limit(key) }\n",
    )
    write(
        tmp_path,
        "app/api/contact/route.ts",
        "import { rateLimit } from '@/lib/rate-limit'\n"
        "export async function POST(req: Request) {\n"
        "  const { success } = await rateLimit(req.headers.get('x-forwarded-for') ?? 'anon')\n"
        "  return Response.json({ ok: success })\n}\n",
    )
    assert findings_for(tmp_path, "abuse", "ABUSE-INMEMORY-LIMITER") == []
    assert findings_for(tmp_path, "abuse", "ABUSE-LIMITER-PROXY-IP") == []


def test_limiter_storage_from_config_or_environment_is_inferred(tmp_path):
    flask = tmp_path / "flask"
    write(flask, "requirements.txt", "flask\nflask-limiter\ngunicorn\n")
    write(flask, "Procfile", "web: gunicorn app:app --workers 4\n")
    write(
        flask,
        "app.py",
        "import os\nfrom flask import Flask\nfrom flask_limiter import Limiter\n"
        "from flask_limiter.util import get_remote_address\napp = Flask(__name__)\n"
        "app.config['RATELIMIT_STORAGE_URI'] = os.environ['REDIS_URL']\n"
        "limiter = Limiter(get_remote_address, app=app)\n",
    )
    [found] = findings_for(flask, "abuse", "ABUSE-INMEMORY-LIMITER")
    assert (str(found.locations[0]), found.tag.value) == ("app.py:7", "INFERRED")
    assert str(found.locations[1]) == "Procfile:1"
    write(
        flask,
        "app.py",
        flask.joinpath("app.py")
        .read_text()
        .replace("os.environ['REDIS_URL']", "'redis://cache:6379'"),
    )
    assert findings_for(flask, "abuse", "ABUSE-INMEMORY-LIMITER") == []

    explicit = tmp_path / "explicit"
    write(explicit, "api/startup.sh", "gunicorn app.main:app --workers 2\n")
    write(
        explicit,
        "api/app/rate_limit.py",
        "from slowapi import Limiter\nfrom slowapi.util import get_remote_address\n"
        "limiter = Limiter(key_func=get_remote_address, storage_uri='memory://')\n",
    )
    [found] = findings_for(explicit, "abuse", "ABUSE-INMEMORY-LIMITER")
    assert found.tag.value == "CONFIRMED"
