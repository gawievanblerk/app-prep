from tests.reviews.helpers import findings_for, write


def with_auth_route(root):
    write(
        root,
        "app/api/me/route.ts",
        "export async function GET() {\n  const session = await auth()\n}\n",
    )


def summary(found):
    return sorted((str(f.locations[0]), f.severity.value) for f in found)


def test_js_cors(tmp_path):
    with_auth_route(tmp_path)
    write(
        tmp_path,
        "server/app.js",
        "app.use(cors())\n"
        "app.use(cors({ origin: true, credentials: true }))\n"
        "app.use(cors({ origin: (origin, cb) => cb(null, true) }))\n"
        "app.use(cors({ origin: (origin, cb) => cb(null, allowed.includes(origin)) }))\n"
        "app.use(cors({ origin: /example\\.com/ }))\n"
        "app.use(cors({ origin: /^https:\\/\\/app\\.example\\.com$/ }))\n"
        "app.use(cors({ origin: ['https://app.example.com'] }))\n"
        "res.setHeader('Access-Control-Allow-Origin', req.headers.origin)\n",
    )
    assert summary(findings_for(tmp_path, "abuse", "ABUSE-CORS-WILDCARD")) == [
        ("server/app.js:1", "high")
    ]
    assert summary(findings_for(tmp_path, "abuse", "ABUSE-CORS-REFLECT")) == [
        ("server/app.js:2", "critical"),
        ("server/app.js:3", "critical"),
        ("server/app.js:8", "critical"),
    ]
    assert summary(findings_for(tmp_path, "abuse", "ABUSE-CORS-LOOSE-REGEX")) == [
        ("server/app.js:5", "medium")
    ]


def test_python_cors(tmp_path):
    with_auth_route(tmp_path)
    write(
        tmp_path,
        "site/settings.py",
        "CORS_ALLOW_ALL_ORIGINS = True\nCORS_ALLOWED_ORIGIN_REGEXES = [r'https://.*\\.example\\.com']\n",
    )
    write(
        tmp_path,
        "api/main.py",
        "app.add_middleware(CORSMiddleware, allow_origins=['*'])\n"
        "app.add_middleware(CORSMiddleware, allow_origin_regex='.*', allow_credentials=True)\n"
        "app.add_middleware(CORSMiddleware, allow_origins=settings.origins, allow_credentials=True)\n",
    )
    assert summary(findings_for(tmp_path, "abuse", "ABUSE-CORS-WILDCARD")) == [
        ("api/main.py:1", "high"),
        ("site/settings.py:1", "high"),
    ]
    assert summary(findings_for(tmp_path, "abuse", "ABUSE-CORS-REFLECT")) == [
        ("api/main.py:2", "critical")
    ]
    assert summary(findings_for(tmp_path, "abuse", "ABUSE-CORS-LOOSE-REGEX")) == [
        ("site/settings.py:2", "medium")
    ]


def test_wildcard_ignored_without_signed_in_routes(tmp_path):
    write(
        tmp_path,
        "server/app.js",
        "app.use(cors())\napp.get('/status', (req, res) => res.send('ok'))\n",
    )
    assert findings_for(tmp_path, "abuse", "ABUSE-CORS-WILDCARD") == []


def test_error_leak(tmp_path):
    write(
        tmp_path,
        "api/routes.py",
        "from fastapi import APIRouter\nrouter = APIRouter()\n"
        "@router.get('/report')\nasync def report():\n"
        "    try:\n        build()\n    except Exception as e:\n"
        "        raise HTTPException(status_code=500, detail=f'Report error: {type(e).__name__}: {e}')\n"
        "@router.get('/health')\nasync def health():\n"
        "    status = 'ok'\n    try:\n        ping()\n    except Exception as e:\n"
        "        status = f'error: {type(e).__name__}'\n"
        "    return {'database': status}\n"
        "@router.post('/items')\nasync def create():\n"
        "    try:\n        save()\n    except ValueError as e:\n        raise HTTPException(status_code=400, detail=str(e))\n"
        "@router.get('/safe')\nasync def safe():\n"
        "    try:\n        build()\n    except Exception:\n        logger.exception('failed')\n"
        "        raise HTTPException(status_code=500, detail='Internal error')\n",
    )
    write(
        tmp_path,
        "app/api/export/route.ts",
        "export async function GET() {\n  try {\n    await run()\n  } catch (err) {\n"
        "    return NextResponse.json({ error: err.message }, { status: 500 })\n  }\n}\n"
        "export async function POST() {\n  try {\n    await run()\n  } catch (err) {\n"
        "    return NextResponse.json({ error: 'failed' }, { status: 500 })\n  }\n}\n",
    )
    found = findings_for(tmp_path, "abuse", "ABUSE-ERROR-LEAK")
    assert summary(found) == [
        ("api/routes.py:16", "medium"),
        ("api/routes.py:8", "medium"),
        ("app/api/export/route.ts:5", "medium"),
    ]
