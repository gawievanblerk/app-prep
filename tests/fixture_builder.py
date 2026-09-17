"""Copy a fixture app to a temporary folder and add what must never be committed."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
LIVE_STRIPE = "sk_" + "live_" + "Fx7Qp2Lm9Zr4Tb8Kw3Yd6Hn1"
ENV_VALUE = "ENVVALUE-" + "DO-NOT-PRINT-7731"
SEED_PASSWORD = "Demo" + "-Admin-" + "2031!"
BYPASS_KEY = "maint" + "enance-bypass-" + "7731"
COMPOSE_PASSWORD = "compose" + "-local-" + "4412"
SECRETS = (LIVE_STRIPE, ENV_VALUE, SEED_PASSWORD, BYPASS_KEY, COMPOSE_PASSWORD)


def git(root: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "-c",
            "user.name=dpr",
            "-c",
            "user.email=dpr@example.invalid",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        check=True,
        capture_output=True,
    )


def _commit(root: Path) -> None:
    git(root, "init", "-q")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "initial")


def _bad_extras(root: Path) -> None:
    (root / "lib/stripe.ts").write_text(
        'import Stripe from "stripe"\n\nexport const stripe = new Stripe("' + LIVE_STRIPE + '")\n'
    )
    chunks = root / ".next/static/chunks"
    chunks.mkdir(parents=True)
    (chunks / "main.js").write_text('var cfg={k:"' + LIVE_STRIPE + '"};')
    (chunks / "main.js.map").write_text("{}")
    git(root, "init", "-q")
    (root / ".env.production").write_text(f"OLD_TOKEN={ENV_VALUE}\n")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "initial")
    git(root, "rm", "-q", "--cached", ".env.production")
    (root / ".env.production").unlink()
    (root / ".env").write_text(f"DEBUG_LABEL={ENV_VALUE}\n")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "second")


def _good_extras(root: Path) -> None:
    (root / "lib/stripe.ts").write_text(
        'import Stripe from "stripe"\n\nexport const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)\n'
    )
    (root / ".env").write_text(f"STRIPE_SECRET_KEY={ENV_VALUE}\n")
    _commit(root)


def _fastapi_bad_extras(root: Path) -> None:
    (root / "api/app/db").mkdir(parents=True, exist_ok=True)
    (root / "api/app/db/seed.py").write_text(
        "from app.core.security import get_password_hash\n"
        "from app.models import User\n\n"
        f'ADMIN_PASSWORD = "{SEED_PASSWORD}"\n\n\n'
        "async def seed(db):\n"
        '    db.add(User(email="admin@example.invalid", password_hash=get_password_hash(ADMIN_PASSWORD)))\n'
    )
    (root / "README.md").write_text(
        f"# Demo\n\nSign in as admin@example.invalid with {SEED_PASSWORD}\n"
    )
    (root / "docker-compose.yml").write_text(
        "services:\n  db:\n    image: postgres:16\n    environment:\n"
        f"      POSTGRES_PASSWORD: ${{DB_PASSWORD:-{COMPOSE_PASSWORD}}}\n"
    )
    workflow = root / ".github/workflows/deploy.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "on: push\nenv:\n"
        f"  VITE_MAINTENANCE_BYPASS_KEY: '{BYPASS_KEY}'\n"
        "jobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: npx @azure/static-web-apps-cli deploy web/dist\n"
    )
    _commit(root)


def _fastapi_good_extras(root: Path) -> None:
    (root / ".env").write_text(f"SEED_ADMIN_PASSWORD={ENV_VALUE}\n")
    _commit(root)


EXTRAS = {
    "next-supabase-bad": _bad_extras,
    "next-supabase-good": _good_extras,
    "django-bad": _commit,
    "fastapi-bad": _fastapi_bad_extras,
    "fastapi-good": _fastapi_good_extras,
}


def build(name: str, tmp_path: Path) -> Path:
    root = tmp_path / name
    shutil.copytree(FIXTURES / name, root)
    EXTRAS[name](root)
    return root
