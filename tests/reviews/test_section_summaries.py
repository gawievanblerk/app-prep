from dpr.api import review
from tests.reviews.helpers import write

SETTINGS = (
    "class Settings(BaseSettings):\n"
    "    cookie_httponly: bool = True\n"
    "    cookie_secure: bool = False\n"
    "    jwt_secret_key: str = 'dev-only'\n\n"
    "    def check(self):\n"
    "        if self.environment == 'production':\n"
    "            if 'dev-only' in self.jwt_secret_key:\n"
    "                raise ValueError('set JWT_SECRET_KEY')\n"
    "            if not self.cookie_secure:\n"
    "                raise ValueError('COOKIE_SECURE must be True')\n"
)


def parts(report, slug):
    return {p.title: p for p in report.sections[slug].parts}


def test_baseline_checks_that_pass(tmp_path):
    write(tmp_path, "api/requirements.txt", "fastapi\npasslib\n")
    write(tmp_path, "api/app/config.py", SETTINGS)
    write(
        tmp_path,
        "api/app/security.py",
        "from passlib.context import CryptContext\npwd = CryptContext(schemes=['bcrypt'])\n",
    )
    write(
        tmp_path,
        "infra/main.tf",
        'locals {\n  url = "postgresql://${var.user}:${var.pw}@db:5432/app?sslmode=require"\n}\n',
    )
    write(tmp_path, "web/index.html", '<script src="/main.js"></script>\n')
    body = parts(review(tmp_path, reviews=["baseline"]), "baseline")["Checks that pass"].body
    assert body.splitlines() == [
        "- Password hashing uses bcrypt (`api/app/security.py:2`). CONFIRMED",
        "- Cookie httponly defaults to on (`api/app/config.py:2`). CONFIRMED",
        "- Cookie secure is enforced in production by a validator (`api/app/config.py:10`). CONFIRMED",
        "- The signing secret jwt_secret_key is checked by a production validator that rejects "
        "development values (`api/app/config.py:8`). CONFIRMED",
        "- Database connections require TLS (`infra/main.tf:2`). CONFIRMED",
        "- No http:// asset URLs in 1 HTML file(s). CONFIRMED",
    ]


def test_baseline_without_passing_evidence(tmp_path):
    write(tmp_path, "api/app/main.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    found = parts(review(tmp_path, reviews=["baseline"]), "baseline")
    assert found["Checks that pass"].body == "No passing checks could be confirmed from code."
    assert "AUTH-ENUM-SIGNUP-MESSAGE" in found["Password storage and account enumeration"].body


def test_leak_hunt_places(tmp_path):
    write(
        tmp_path,
        ".env.example",
        "VITE_API_URL=\nVITE_STAFF_BYPASS_KEY=\nNEXT_PUBLIC_WEBHOOK_SECRET=\nDATABASE_URL=\n",
    )
    write(tmp_path, "web/src/main.ts", "export const api = import.meta.env.VITE_API_URL\n")
    found = parts(review(tmp_path, reviews=["leaks"]), "leaks")
    assert list(found)[:5] == [
        "What this review never prints",
        "Place 1: public variables reviewed",
        "Place 1: keys, env files and git history",
        "Place 2: over-broad responses",
        "Place 3: logs",
    ]
    public = found["Place 1: public variables reviewed"].body.splitlines()
    assert public == [
        "- `NEXT_PUBLIC_WEBHOOK_SECRET`: secret word in a browser variable (LEAK-PUBLIC-SECRET) "
        "(`.env.example:3`)",
        "- `VITE_API_URL`: publishable (`.env.example:1`)",
        "- `VITE_STAFF_BYPASS_KEY`: access gate key shipped to browsers (LEAK-PUBLIC-GATE-KEY) "
        "(`.env.example:2`)",
    ]
    history = found["Place 1: keys, env files and git history"].body
    assert history.startswith(
        "- Not a git repository, so tracked files and history were not checked."
    )
    assert (
        found["Place 3: logs"].body
        == "No log call writes a request, user, token or personal value."
    )
