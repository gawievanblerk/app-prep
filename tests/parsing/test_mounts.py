from dpr.parsing.mounts import limiter_mounts
from dpr.parsing.routes import extract_routes
from dpr.walk import RepoIndex
from tests.reviews.helpers import write


def paths(root):
    return sorted((r.method, r.path) for r in extract_routes(RepoIndex(root)))


def test_fastapi_include_router_prefixes_chain_through_nested_routers(tmp_path):
    write(
        tmp_path,
        "api/app/config.py",
        "class Settings(BaseSettings):\n    api_v1_prefix: str = '/api/v1'\n",
    )
    write(
        tmp_path,
        "api/app/main.py",
        "from fastapi import FastAPI\nfrom app.api.v1.router import api_router\n"
        "from app.api import health\n"
        "app = FastAPI()\napp.include_router(api_router, prefix=settings.api_v1_prefix)\n"
        "app.include_router(health.router)\n",
    )
    write(
        tmp_path,
        "api/app/api/v1/router.py",
        "from fastapi import APIRouter\n"
        "from app.api.v1.endpoints.auth import router as auth_router\n"
        "from .endpoints import files\n"
        "api_router = APIRouter()\napi_router.include_router(auth_router)\n"
        "api_router.include_router(files.router, prefix='/storage/')\n",
    )
    write(
        tmp_path,
        "api/app/api/v1/endpoints/auth.py",
        "from fastapi import APIRouter\nrouter = APIRouter(prefix='/auth')\n"
        "@router.post('/login')\nasync def login(): ...\n",
    )
    write(
        tmp_path,
        "api/app/api/v1/endpoints/files.py",
        "from fastapi import APIRouter\nrouter = APIRouter()\n"
        "@router.get('/{file_id}')\nasync def download(file_id: str): ...\n",
    )
    write(
        tmp_path,
        "api/app/api/health.py",
        "from fastapi import APIRouter\nrouter = APIRouter()\n"
        "@router.get('/health')\nasync def health(): ...\n",
    )
    assert paths(tmp_path) == [
        ("GET", "/api/v1/storage/{file_id}"),
        ("GET", "/health"),
        ("POST", "/api/v1/auth/login"),
    ]


def test_unresolvable_prefix_leaves_the_path_alone(tmp_path):
    write(
        tmp_path,
        "app/main.py",
        "from fastapi import FastAPI\nfrom app import auth\napp = FastAPI()\n"
        "app.include_router(auth.router, prefix=os.environ['PREFIX'])\n",
    )
    write(
        tmp_path,
        "app/auth.py",
        "from fastapi import APIRouter\nrouter = APIRouter()\n@router.post('/login')\ndef login(): ...\n",
    )
    assert paths(tmp_path) == [("POST", "/login")]


def test_express_use_mounts_router_files_and_limiters(tmp_path):
    write(
        tmp_path,
        "api/src/index.ts",
        "import express from 'express'\nimport rateLimit from 'express-rate-limit'\n"
        "import authRoutes from './routes/auth.routes.js'\n"
        "const app = express()\nconst limiter = rateLimit({ windowMs: 1000, max: 5 })\n"
        "app.use('/api/', limiter)\napp.use('/api/v1/auth', authRoutes)\n"
        "app.get('/health', (req, res) => res.json({}))\n",
    )
    write(
        tmp_path,
        "api/src/routes/auth.routes.ts",
        "import { Router } from 'express'\nconst router = Router()\n"
        "router.post('/login', async (req, res) => res.json({}))\nexport default router\n",
    )
    assert paths(tmp_path) == [("GET", "/health"), ("POST", "/api/v1/auth/login")]
    assert limiter_mounts(RepoIndex(tmp_path)) == [("api/src/index.ts", "/api")]


def test_express_global_limiter_has_an_empty_prefix(tmp_path):
    write(
        tmp_path,
        "server.js",
        "const app = express()\nconst apiLimiter = rateLimit({ max: 5 })\napp.use(apiLimiter)\n"
        "app.post('/login', (req, res) => res.json({}))\n",
    )
    assert limiter_mounts(RepoIndex(tmp_path)) == [("server.js", "")]


def test_unresolvable_settings_prefix_is_not_borrowed_from_another_app_root(tmp_path):
    """C1: an unrelated class elsewhere in the repo happens to define the same attribute name
    with a literal default. The mounting file's own app root has the real Settings class, whose
    default is unresolvable (read from the environment), so the prefix must stay unresolved
    rather than pick up the other app root's literal."""
    write(
        tmp_path,
        "api/app/config.py",
        "import os\nclass Settings(BaseSettings):\n"
        "    api_v1_prefix: str = os.environ['API_V1_PREFIX']\n",
    )
    write(
        tmp_path,
        "api/app/main.py",
        "from fastapi import FastAPI\nfrom app.api.v1.router import api_router\n"
        "app = FastAPI()\napp.include_router(api_router, prefix=settings.api_v1_prefix)\n",
    )
    write(
        tmp_path,
        "api/app/api/v1/router.py",
        "from fastapi import APIRouter\napi_router = APIRouter()\n"
        "@api_router.post('/login')\nasync def login(): ...\n",
    )
    write(tmp_path, "api/requirements.txt", "fastapi\n")
    write(
        tmp_path,
        "other/config.py",
        "class Settings(BaseSettings):\n    api_v1_prefix: str = '/wrong'\n",
    )
    write(tmp_path, "other/package.json", '{"dependencies": {}}')
    assert paths(tmp_path) == [("POST", "/login")]


def test_settings_prefix_resolves_when_every_class_in_the_app_root_agrees(tmp_path):
    """C1: two classes in the same app root both give the attribute the same literal default;
    the prefix still resolves."""
    write(
        tmp_path,
        "api/app/config.py",
        "class Settings(BaseSettings):\n    api_v1_prefix: str = '/api/v1'\n"
        "class LegacySettings(BaseSettings):\n    api_v1_prefix: str = '/api/v1'\n",
    )
    write(
        tmp_path,
        "api/app/main.py",
        "from fastapi import FastAPI\nfrom app.api.v1.router import api_router\n"
        "app = FastAPI()\napp.include_router(api_router, prefix=settings.api_v1_prefix)\n",
    )
    write(
        tmp_path,
        "api/app/api/v1/router.py",
        "from fastapi import APIRouter\napi_router = APIRouter()\n"
        "@api_router.post('/login')\nasync def login(): ...\n",
    )
    write(tmp_path, "api/requirements.txt", "fastapi\n")
    assert paths(tmp_path) == [("POST", "/api/v1/login")]


def test_a_router_mount_in_a_test_file_is_not_evidence(tmp_path):
    """C2: `__tests__` sorts before `app` on disk, so without a test-file filter the test's own
    mount would be found first and win. The production mount in app/main.py must win instead."""
    write(
        tmp_path,
        "app/routers/ai.py",
        "from fastapi import APIRouter\nrouter = APIRouter()\n"
        "@router.post('/generate')\nasync def generate(): ...\n",
    )
    write(
        tmp_path,
        "app/main.py",
        "from fastapi import FastAPI\nfrom app.routers import ai\napp = FastAPI()\n"
        "app.include_router(ai.router, prefix='/ai')\n",
    )
    write(
        tmp_path,
        "__tests__/test_ai.py",
        "from fastapi import FastAPI\nfrom app.routers import ai\n"
        "def test_x():\n    app = FastAPI()\n    app.include_router(ai.router, prefix='/zz')\n",
    )
    assert paths(tmp_path) == [("POST", "/ai/generate")]


def test_express_use_mounts_a_router_imported_via_an_alias_path(tmp_path):
    """I4: the pre-fix local `_js_target` only resolved relative (`./`) import specifiers, so an
    `@/`-aliased router import was never recognised as a mount and the route path stayed
    unprefixed. Reusing dpr.parsing.imports.js_target (which resolves `@/` and `~/`) fixes it."""
    write(
        tmp_path,
        "src/index.js",
        "import express from 'express'\nimport authRoutes from '@/routes/auth.routes.js'\n"
        "const app = express()\napp.use('/api/v1/auth', authRoutes)\n",
    )
    write(
        tmp_path,
        "src/routes/auth.routes.js",
        "import { Router } from 'express'\nconst router = Router()\n"
        "router.post('/login', async (req, res) => res.json({}))\nexport default router\n",
    )
    assert paths(tmp_path) == [("POST", "/api/v1/auth/login")]
