from dpr.api import review
from dpr.report.markdown import render_markdown
from tests.reviews.helpers import write


def app(root):
    write(root, "requirements.txt", "fastapi\nanthropic\n")
    write(
        root,
        "api/chat.py",
        "import anthropic\nclient = anthropic.Anthropic()\n"
        "def ask(messages):\n    return client.messages.create(messages=messages)\n",
    )
    write(
        root,
        "api/routes.py",
        "from fastapi import APIRouter, Depends\nfrom api.chat import ask\n"
        "router = APIRouter(prefix='/api')\n"
        "@router.post('/chat')\nasync def chat(user=Depends(get_current_user)):\n    return ask([])\n"
        "@router.post('/auth/register')\nasync def register(data): ...\n"
        "@router.post('/auth/login')\nasync def login(data): ...\n"
        "@router.get('/report')\nasync def report(user=Depends(get_current_user)):\n"
        "    try:\n        build()\n    except Exception as e:\n"
        "        raise HTTPException(status_code=500, detail=str(e))\n",
    )
    return root


def test_abuse_section_parts(tmp_path):
    report = review(app(tmp_path), reviews=["abuse"])
    parts = {p.title: p for p in report.sections["abuse"].parts}
    assert list(parts) == [
        "How to read the limits",
        "Cost surface",
        "Limits per endpoint",
        "Implementation for this stack",
        "Guards",
        "CORS and error messages",
        "Alerts and kill switches",
    ]
    assert parts["Cost surface"].rows == (
        (
            "POST /api/chat",
            "anthropic",
            "tokens per call, priced per model",
            "any signed-in user",
            "none found",
        ),
        (
            "POST /api/auth/register",
            "public form",
            "a stored row and often an email per submission",
            "no",
            "none found",
        ),
        (
            "POST /api/auth/login",
            "public form",
            "password hashing CPU and credential stuffing",
            "no",
            "none found",
        ),
    )
    assert parts["Limits per endpoint"].rows[0] == (
        "POST /api/chat",
        "tokens per call, priced per model",
        "20",
        "40",
        "1 h",
        "starting default, not measured traffic",
    )
    assert parts["Limits per endpoint"].rows[2][2:5] == ("10", "20", "15 min")
    assert "SlowAPIMiddleware" in parts["Implementation for this stack"].body
    assert "- `api/routes.py:16`: return a generic message" in parts["CORS and error messages"].body
    assert "- `API_CHAT_ENABLED` for POST /api/chat" in parts["Alerts and kill switches"].body
    text = render_markdown(report)
    assert "## 7. Abuse and bill guard" in text and "#### GUARD 1:" in text
