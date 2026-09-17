"""Copy a fixture app to a temporary folder and add what must never be committed."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
LIVE_STRIPE = "sk_" + "live_" + "Fx7Qp2Lm9Zr4Tb8Kw3Yd6Hn1"
ENV_VALUE = "ENVVALUE-" + "DO-NOT-PRINT-7731"
SECRETS = (LIVE_STRIPE, ENV_VALUE)


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


EXTRAS = {
    "next-supabase-bad": _bad_extras,
    "next-supabase-good": _good_extras,
}


def build(name: str, tmp_path: Path) -> Path:
    root = tmp_path / name
    shutil.copytree(FIXTURES / name, root)
    EXTRAS[name](root)
    return root
