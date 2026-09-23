"""A web-js route that reaches a paid route of another app root through an outbound call."""

from tests.reviews.helpers import findings_for, write

GATE = (
    "import secrets\nfrom fastapi import Header, HTTPException\nfrom app.config import settings\n"
    "async def verify_internal_token(x_internal_token: str | None = Header(default=None)):\n"
    "    if not secrets.compare_digest(x_internal_token or '', settings.internal_token):\n"
    "        raise HTTPException(status_code=401, detail='invalid token')\n"
)
PY_NOTES = (
    "from fastapi import APIRouter\nimport anthropic\nrouter = APIRouter()\n"
    "client = anthropic.Anthropic()\n"
    "@router.post('/generate-note')\nasync def generate_note(payload: dict):\n"
    "    return client.messages.create(messages=[])\n"
    "@router.post('/render-pdf')\nasync def render_pdf(payload: dict):\n"
    "    return {'ok': True}\n"
)
PY_SUMMARIES = (
    "from fastapi import APIRouter\nimport anthropic\nrouter = APIRouter()\n"
    "client = anthropic.Anthropic()\n"
    "@router.post('/jobs/{job_id}/summary')\nasync def summary(job_id: str):\n"
    "    return client.messages.create(messages=[])\n"
)
PY_MAIN = (
    "from fastapi import Depends, FastAPI\nfrom app.deps import verify_internal_token\n"
    "from app.routes import notes, summaries\napp = FastAPI()\n"
    "_internal = [Depends(verify_internal_token)]\n"
    "app.include_router(notes.router, prefix='/afs', dependencies=_internal)\n"
    "app.include_router(summaries.router, prefix='/api/extract', dependencies=_internal)\n"
)
ENV = (
    "export const env = {\n"
    "  AI_SERVICE_URL: process.env.AI_SERVICE_URL || 'http://localhost:8000',\n};\n"
)
PROXY = (
    "import { env } from '../config/env';\n"
    "export async function generateNoteViaAI(body: any) {\n"
    "  const url = `${env.AI_SERVICE_URL}/afs/generate-note`;\n"
    "  const res = await fetch(url, { method: 'POST', body: JSON.stringify(body) });\n"
    "  return res.json();\n}\n"
    "export async function renderPdfViaAI(body: any) {\n"
    "  const res = await fetch(`${env.AI_SERVICE_URL}/afs/render-pdf`, { method: 'POST' });\n"
    "  return res.json();\n}\n"
    "export async function vendorNote(body: any) {\n"
    "  const res = await fetch('https://api.vendor.example/afs/generate-note', { method: 'POST' });\n"
    "  return res.json();\n}\n"
)
CLIENT = (
    "const SERVICE = process.env.SUMMARY_HOST || 'http://localhost:4001';\n"
    "export async function servicePost(path: string, body: any) {\n"
    "  const res = await fetch(`${SERVICE}${path}`, { method: 'POST', body: JSON.stringify(body) });\n"
    "  return res.json();\n}\n"
)
CONTROLLER = (
    "import { generateNoteViaAI, renderPdfViaAI, vendorNote } from '../services/proxy';\n"
    "import { servicePost } from '../services/client';\n"
    "export async function handleGenerate(req: any, res: any) {\n"
    "  res.json(await generateNoteViaAI(req.body));\n}\n"
    "export async function handleRender(req: any, res: any) {\n"
    "  res.json(await renderPdfViaAI(req.body));\n}\n"
    "export async function handleVendor(req: any, res: any) {\n"
    "  res.json(await vendorNote(req.body));\n}\n"
    "async function buildSummary(jobId: string) {\n"
    "  const out = await servicePost<{ ok: boolean }>(\n"
    "    `/api/extract/jobs/${jobId}/summary`,\n    {},\n  );\n  return out;\n}\n"
    "export async function handleSummary(req: any, res: any) {\n"
    "  res.json(await buildSummary(req.params.jobId));\n}\n"
)
ROUTES = (
    "import { Router } from 'express';\n"
    "import { authenticate, requireWriteAccess } from '../middleware/auth';\n"
    "import { requireCredit } from '../middleware/credit';\n"
    "import { summaryLimiter } from '../middleware/rateLimit';\n"
    "import * as ctrl from '../controllers/notes.controller';\n"
    "const router = Router();\nrouter.use(authenticate);\n"
    "router.post('/notes/:id/generate', requireWriteAccess, ctrl.handleGenerate);\n"
    "router.post('/notes/:id/render', requireWriteAccess, ctrl.handleRender);\n"
    "router.post('/notes/:id/vendor', requireWriteAccess, ctrl.handleVendor);\n"
    "router.post('/jobs/:jobId/summary', ctrl.handleSummary);\n"
    "router.post('/jobs/:jobId/summary-limited', summaryLimiter, ctrl.handleSummary);\n"
    "router.post('/jobs/:jobId/summary-credit', requireCredit('summary'), ctrl.handleSummary);\n"
    "export default router;\n"
)
AUTH = (
    "export function authenticate(req: any, res: any, next: any) {\n"
    "  if (!req.headers.authorization) return res.status(401).end();\n  next();\n}\n"
    "export function requireWriteAccess(req: any, res: any, next: any) { next(); }\n"
)


def repo(root, py_main=PY_MAIN, routes=ROUTES):
    write(root, "api-py/requirements.txt", "fastapi\nanthropic\n")
    write(root, "api-py/app/__init__.py", "")
    write(root, "api-py/app/routes/__init__.py", "")
    write(root, "api-py/app/deps.py", GATE)
    write(root, "api-py/app/routes/notes.py", PY_NOTES)
    write(root, "api-py/app/routes/summaries.py", PY_SUMMARIES)
    write(root, "api-py/app/main.py", py_main)
    write(
        root, "web-js/package.json", '{"dependencies": {"express": "4", "express-rate-limit": "7"}}'
    )
    write(root, "web-js/src/config/env.ts", ENV)
    write(root, "web-js/src/services/proxy.ts", PROXY)
    write(root, "web-js/src/services/client.ts", CLIENT)
    write(root, "web-js/src/controllers/notes.controller.ts", CONTROLLER)
    write(root, "web-js/src/middleware/auth.ts", AUTH)
    write(
        root,
        "web-js/src/middleware/credit.ts",
        "export const requireCredit = (k: string) => (req: any, res: any, next: any) => next();\n",
    )
    write(
        root,
        "web-js/src/middleware/rateLimit.ts",
        "import rateLimit from 'express-rate-limit';\n"
        "export const summaryLimiter = rateLimit({ windowMs: 60000, max: 5 });\n",
    )
    write(root, "web-js/src/routes/notes.routes.ts", routes)
    write(
        root,
        "web-js/src/app.ts",
        "import express from 'express';\nimport notesRoutes from './routes/notes.routes';\n"
        "const app = express();\napp.use('/api', notesRoutes);\n",
    )
    return root


def _by_path(found):
    return {f.title.split(" calls ")[0]: f for f in found}


def test_caller_of_internal_paid_route_is_reported(tmp_path):
    found = _by_path(findings_for(repo(tmp_path), "abuse", "ABUSE-PAID-UNLIMITED"))
    assert sorted(found) == ["POST /api/jobs/:jobId/summary", "POST /api/notes/:id/generate"]
    note = found["POST /api/notes/:id/generate"]
    assert note.severity.value == "medium"
    assert note.tag.value == "CONFIRMED"
    assert "anthropic" in note.title
    assert "POST /afs/generate-note" in note.detail
    assert [str(loc) for loc in note.locations] == [
        "web-js/src/routes/notes.routes.ts:8",
        "api-py/app/routes/notes.py:6",
    ]


def test_helper_that_takes_the_path_is_followed(tmp_path):
    found = _by_path(findings_for(repo(tmp_path), "abuse", "ABUSE-PAID-UNLIMITED"))
    summary = found["POST /api/jobs/:jobId/summary"]
    assert "POST /api/extract/jobs/{job_id}/summary" in summary.detail
    assert "servicePost()" in summary.detail
    assert str(summary.locations[1]) == "api-py/app/routes/summaries.py:6"


def test_limited_or_credit_checked_callers_stay_quiet(tmp_path):
    found = _by_path(findings_for(repo(tmp_path), "abuse", "ABUSE-PAID-UNLIMITED"))
    assert "POST /api/jobs/:jobId/summary-limited" not in found
    assert "POST /api/jobs/:jobId/summary-credit" not in found


def test_unpaid_targets_and_outside_hosts_are_not_matched(tmp_path):
    found = _by_path(findings_for(repo(tmp_path), "abuse", "ABUSE-PAID-UNLIMITED"))
    assert "POST /api/notes/:id/render" not in found
    assert "POST /api/notes/:id/vendor" not in found


def test_limiter_mounted_on_the_router_quiets_every_caller(tmp_path):
    routes = ROUTES.replace(
        "router.use(authenticate);\n", "router.use(authenticate);\nrouter.use(summaryLimiter);\n"
    )
    assert findings_for(repo(tmp_path, routes=routes), "abuse", "ABUSE-PAID-UNLIMITED") == []


def test_ungated_service_keeps_its_own_findings_and_the_callers(tmp_path):
    root = repo(tmp_path, py_main=PY_MAIN.replace(", dependencies=_internal", ""))
    found = findings_for(root, "abuse", "ABUSE-PAID-UNLIMITED")
    files = sorted(str(f.locations[0]).split(":")[0] for f in found)
    assert files == [
        "api-py/app/routes/notes.py",
        "api-py/app/routes/summaries.py",
        "web-js/src/routes/notes.routes.ts",
        "web-js/src/routes/notes.routes.ts",
    ]


def test_route_in_the_same_app_root_is_not_an_internal_service(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"express": "4", "openai": "4"}}')
    write(
        tmp_path,
        "src/app.ts",
        "import express from 'express';\nimport OpenAI from 'openai';\n"
        "const ai = new OpenAI();\nconst app = express();\n"
        "const BASE = process.env.SELF_URL || 'http://localhost:3000';\n"
        "app.post('/ai/complete', async (req, res) => res.json(await ai.chat.completions.create({})));\n"
        "app.post('/proxy', async (req, res) => {\n"
        "  const r = await fetch(`${BASE}/ai/complete`, { method: 'POST' });\n"
        "  res.json(await r.json());\n});\n",
    )
    found = findings_for(tmp_path, "abuse", "ABUSE-PAID-UNLIMITED")
    assert [f.title.split(" calls ")[0] for f in found] == ["POST /ai/complete"]
