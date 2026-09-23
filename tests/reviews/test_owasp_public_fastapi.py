"""OWASP-A01-PUBLIC-SENSITIVE on FastAPI: LLM calls are not writes, rendered files are not
stored files."""

from tests.reviews.helpers import findings_for, write

HELPERS = (
    "import anthropic\nfrom app.models import Record\nclient = anthropic.Anthropic()\n"
    "def draft():\n    return client.messages.create(messages=[])\n"
    "def chat():\n    return client.chat.completions.create(messages=[])\n"
    "def store():\n    Record.objects.create(kind='x')\n"
)
ROUTES = (
    "from fastapi import APIRouter, Depends\nfrom fastapi.responses import Response\n"
    "from app.helpers import draft, chat, store\nrouter = APIRouter()\n"
    "@router.post('/draft')\nasync def make_draft():\n    return draft()\n"
    "@router.post('/chat')\nasync def make_chat():\n    return chat()\n"
    "@router.post('/store')\nasync def make_store():\n    return store()\n"
    "@router.post('/render')\nasync def render(payload: dict):\n"
    "    pdf = build_pdf(payload)\n"
    "    return Response(content=pdf, media_type='application/pdf',\n"
    "                    headers={'Content-Disposition': 'attachment; filename=x.pdf'})\n"
    "@router.get('/invoice/{invoice_id}')\nasync def invoice(invoice_id: int, db=Depends(get_db)):\n"
    "    row = db.get(Invoice, invoice_id)\n"
    "    return Response(content=row.pdf, media_type='application/pdf',\n"
    "                    headers={'Content-Disposition': 'attachment; filename=x.pdf'})\n"
)


def test_llm_calls_and_body_rendered_files_are_not_sensitive(tmp_path):
    write(tmp_path, "requirements.txt", "fastapi\nanthropic\nopenai\n")
    write(tmp_path, "app/__init__.py", "")
    write(tmp_path, "app/models.py", "class Record:\n    pass\n")
    write(tmp_path, "app/helpers.py", HELPERS)
    write(tmp_path, "app/routes.py", ROUTES)
    found = findings_for(tmp_path, "owasp", "OWASP-A01-PUBLIC-SENSITIVE")
    assert sorted(f.title for f in found) == [
        "GET /invoice/{invoice_id} returns a file without sign-in",
        "POST /store runs a back-office write that takes no input without sign-in",
    ]
