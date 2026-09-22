from tests.reviews.helpers import findings_for, write

PY_LIMITER = (
    "from slowapi import Limiter\nfrom slowapi.util import get_remote_address\n"
    "limiter = Limiter(key_func=get_remote_address)\n"
)


def test_worker_count_from_another_app_root_is_not_borrowed(tmp_path):
    write(tmp_path, "azure-pipelines.yml", "steps:\n  - script: cd apps/api-py && pytest\n")
    write(tmp_path, "apps/api-py/requirements.txt", "fastapi\nslowapi\n")
    write(tmp_path, "apps/api-py/startup.sh", "gunicorn app.main:app --workers 2\n")
    write(tmp_path, "apps/api-py/app/main.py", "@app.get('/x')\ndef x(): ...\n")
    write(tmp_path, "apps/api/package.json", '{"dependencies": {"express": "4"}}')
    write(
        tmp_path,
        "apps/api/src/index.ts",
        "const app = express()\nconst limiter = rateLimit({ windowMs: 1000, max: 5 })\n"
        "app.use('/api/', limiter)\napp.get('/api/x', (req, res) => res.json({}))\n",
    )
    assert findings_for(tmp_path, "abuse", "ABUSE-INMEMORY-LIMITER") == []


def test_serverless_hosting_config_in_another_app_root_is_not_borrowed(tmp_path):
    write(tmp_path, "apps/api-py/requirements.txt", "fastapi\nslowapi\n")
    write(tmp_path, "apps/api-py/app/rate_limit.py", PY_LIMITER)
    write(
        tmp_path,
        "apps/api-py/app/main.py",
        "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/x')\ndef x(): ...\n",
    )
    write(tmp_path, "apps/web/package.json", '{"dependencies": {}}')
    write(tmp_path, "apps/web/index.html", "<html></html>\n")
    write(tmp_path, "apps/web/vercel.json", "{}")
    assert findings_for(tmp_path, "abuse", "ABUSE-INMEMORY-LIMITER") == []


def test_worker_count_in_the_same_app_root_still_counts(tmp_path):
    write(tmp_path, "api/requirements.txt", "fastapi\nslowapi\n")
    write(tmp_path, "api/app/rate_limit.py", PY_LIMITER)
    write(tmp_path, "api/startup.sh", "gunicorn app.main:app --workers 2\n")
    [finding] = findings_for(tmp_path, "abuse", "ABUSE-INMEMORY-LIMITER")
    assert [str(loc) for loc in finding.locations] == [
        "api/app/rate_limit.py:3",
        "api/startup.sh:1",
    ]


def test_proxy_key_in_an_undeployed_app_is_skipped(tmp_path):
    write(tmp_path, "render.yaml", "services:\n  - type: web\n    rootDir: apps/api-py\n")
    write(tmp_path, "apps/api-py/requirements.txt", "fastapi\nslowapi\n")
    write(tmp_path, "apps/api-py/app/rate_limit.py", PY_LIMITER)
    write(
        tmp_path,
        "apps/api-py/app/main.py",
        "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/x')\ndef x(): ...\n",
    )
    write(tmp_path, "apps/api/package.json", '{"dependencies": {"express": "4"}}')
    write(
        tmp_path,
        "apps/api/src/index.ts",
        "const app = express()\nconst limiter = rateLimit({ windowMs: 1000, max: 5 })\n"
        "app.get('/api/x', (req, res) => res.json({}))\n",
    )
    found = findings_for(tmp_path, "abuse", "ABUSE-LIMITER-PROXY-IP")
    assert [str(f.locations[0]) for f in found] == ["apps/api-py/app/rate_limit.py:3"]


def test_form_title_says_no_bot_challenge_when_limited(tmp_path):
    write(
        tmp_path,
        "api/auth.py",
        "from fastapi import APIRouter\nrouter = APIRouter(prefix='/auth')\n"
        "@router.post('/register')\n@limiter.limit('3/hour')\nasync def register(request, data): ...\n",
    )
    write(
        tmp_path,
        "api/contact.py",
        "from fastapi import APIRouter\nrouter = APIRouter()\n"
        "@router.post('/contact')\nasync def contact(data): ...\n",
    )
    titles = {
        f.locations[0].file: f.title
        for f in findings_for(tmp_path, "abuse", "ABUSE-FORM-NO-CHALLENGE")
    }
    assert titles == {
        "api/auth.py": "Public forms have rate limits but no bot challenge",
        "api/contact.py": "Public forms accept unlimited automated submissions",
    }


def test_mounted_express_limiter_counts_for_paid_routes(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"express": "4", "openai": "4"}}')
    write(
        tmp_path,
        "src/index.js",
        "import aiRoutes from './routes/ai.js'\nconst app = express()\n"
        "const limiter = rateLimit({ windowMs: 1000, max: 5 })\n"
        "app.use('/api', limiter)\napp.use('/api/ai', aiRoutes)\n",
    )
    write(
        tmp_path,
        "src/routes/ai.js",
        "import OpenAI from 'openai'\nconst client = new OpenAI()\nconst router = Router()\n"
        "router.post('/generate', requireUser, async (req, res) => {\n"
        "  res.json(await client.responses.create({ input: req.body.q }))\n})\n"
        "export default router\n",
    )
    assert findings_for(tmp_path, "abuse", "ABUSE-PAID-UNLIMITED") == []


def proxied_api(root):
    write(root, "render.yaml", "services:\n  - type: web\n    rootDir: api\n")
    write(root, "api/requirements.txt", "fastapi\nslowapi\n")
    write(root, "api/app/rate_limit.py", PY_LIMITER)
    write(
        root,
        "api/app/main.py",
        "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/x')\ndef x(): ...\n",
    )
    write(root, "worker/requirements.txt", "flask\n")
    write(
        root,
        "worker/app.py",
        "from flask import Flask\napp = Flask(__name__)\n@app.get('/y')\ndef y(): ...\n",
    )
    return root


def test_proxy_trust_in_another_root_or_a_test_does_not_cover_the_limiter(tmp_path):
    root = proxied_api(tmp_path)
    write(root, "worker/wsgi.py", "app.wsgi_app = ProxyFix(app.wsgi_app)\n")
    write(root, "api/tests/test_ip.py", "HEADERS = {'x-forwarded-for': '1.2.3.4'}\n")
    write(root, "docs/deploy.md", "Set x-forwarded-for on the proxy.\n")
    [finding] = findings_for(root, "abuse", "ABUSE-LIMITER-PROXY-IP")
    assert str(finding.locations[0]) == "api/app/rate_limit.py:3"
    write(root, "api/startup.sh", "uvicorn app.main:app --forwarded-allow-ips='*'\n")
    assert findings_for(root, "abuse", "ABUSE-LIMITER-PROXY-IP") == []


def test_shared_store_setting_of_another_root_does_not_cover_the_limiter(tmp_path):
    root = proxied_api(tmp_path)
    write(root, "api/startup.sh", "gunicorn app.main:app --workers 2\n")
    write(root, "worker/config.py", "RATELIMIT_STORAGE_URL = 'redis://cache:6379'\n")
    [finding] = findings_for(root, "abuse", "ABUSE-INMEMORY-LIMITER")
    assert (str(finding.locations[0]), finding.tag.value) == ("api/app/rate_limit.py:3", "INFERRED")
    write(root, "api/app/config.py", "RATELIMIT_STORAGE_URL = 'redis://cache:6379'\n")
    assert findings_for(root, "abuse", "ABUSE-INMEMORY-LIMITER") == []


def test_repository_level_compose_worker_count_applies_to_every_root(tmp_path):
    write(tmp_path, "backend/requirements.txt", "fastapi\nslowapi\n")
    write(
        tmp_path, "backend/main.py", "from fastapi import FastAPI\napp = FastAPI()\n" + PY_LIMITER
    )
    write(
        tmp_path,
        "docker-compose.yml",
        "services:\n  api:\n    build: ./backend\n"
        "    command: uvicorn main:app --host 0.0.0.0 --workers 4\n",
    )
    [finding] = findings_for(tmp_path, "abuse", "ABUSE-INMEMORY-LIMITER")
    assert [str(loc) for loc in finding.locations] == ["backend/main.py:5", "docker-compose.yml:4"]
