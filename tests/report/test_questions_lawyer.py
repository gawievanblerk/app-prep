import subprocess

from dpr.api import review
from dpr.model import Detection, SdkUse
from dpr.questions.catalogue import load_questions, questions_for, relevant
from dpr.report.markdown import render_markdown
from tests.reviews.helpers import write

PASSWORD = "Adm" + "in-" + "7713"


def ids(detection):
    return {q.id for q in questions_for(["rls", "auth", "baseline", "abuse"], detection)}


def test_questions_follow_the_detected_stack():
    supabase = Detection(databases=["supabase"], auth_providers=["supabase-auth"])
    assert {"buckets_public", "provider_session_lifetimes"} <= ids(supabase)
    assert "db_runtime_role" not in ids(supabase)
    server = Detection(databases=["postgres"], auth_providers=["custom-jwt"])
    assert "db_runtime_role" in ids(server)
    assert not {"buckets_public", "provider_email_templates", "traffic_peak"} & ids(server)
    paid = Detection(sdks=[SdkUse("openai", "llm", True, True, ())])
    assert {"traffic_peak", "spend_caps"} <= ids(paid)
    [question] = [q for q in load_questions() if q.id == "user_countries"]
    assert relevant(question, Detection())


def git(root, *args):
    subprocess.run(
        ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        check=True,
        capture_output=True,
    )


def app(root):
    write(root, "requirements.txt", "fastapi\nopenai\nsqlalchemy\npython-jose\npasslib\n")
    write(
        root,
        "app/seed.py",
        f"from app.security import get_password_hash\nADMIN = '{PASSWORD}'\n"
        "def seed(db):\n    db.add(User(password_hash=get_password_hash(ADMIN)))\n",
    )
    write(
        root,
        "app/routes.py",
        "from fastapi import APIRouter\nfrom openai import OpenAI\nrouter = APIRouter()\n"
        "client = OpenAI()\n\n@router.post('/generate')\n"
        "async def generate(body: dict, user: CurrentUser):\n"
        "    return client.responses.create(input=body['prompt'])\n",
    )
    write(root, "docs/customers.pdf", "%PDF-1.4 binary\0data")
    git(root, "init", "-q")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "init")
    return root


def test_lawyer_questions_and_coverage_notes(tmp_path):
    report = review(app(tmp_path))
    text = render_markdown(report)
    lawyer = text[
        text.index("### For the data protection lawyer") : text.index(
            "\n## What this review did not cover"
        )
    ]
    credential = next(i.id for i in report.register if "BASE-LITERAL-PASSWORD-HASH" in i.findings)
    assert f"If the exposed credentials ({credential}) were used" in lawyer
    assert "before personal data or free text reaches openai?" in lawyer
    assert lawyer.count("\n1. ") == 1
    not_covered = text[text.index("\n## What this review did not cover") :]
    assert "- Dependency vulnerability audit (npm audit, pip-audit) was not run" in not_covered
    assert (
        "1 committed documents, images, spreadsheets or database files (for example docs/customers.pdf)"
        in not_covered
    )
    assert "- Paid routes are not compared with the roles the product intends" in not_covered
    assert "openapi.json" in not_covered
    detection = text[text.index("## Detection") : text.index("## 1. Data inventory")]
    assert "| CI | none detected |" in detection
