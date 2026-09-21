import hashlib

from dpr.api import review
from dpr.report.json_out import render_json
from dpr.report.markdown import render_markdown
from tests.reviews.helpers import findings_for, write

ADMIN = "Adm1n" + "-Merge-" + "7713"
OTHER = "Oth3r" + "-Merge-" + "7713"
FIRST = "Fst3d" + "-Bug1-" + "5521"
SECOND = "Sc0nd" + "-Bug1-" + "5521"


def hashing(root, rel, literal, fallback=False):
    value = f"os.environ.get('SEED_ADMIN_PASSWORD', '{literal}')" if fallback else f"'{literal}'"
    write(
        root,
        rel,
        "import os\nfrom app.core.security import get_password_hash\n"
        f"def seed(db):\n    db.add(User(password_hash=get_password_hash({value})))\n",
    )


def found(root):
    return {
        f.locations[0].file: f for f in findings_for(root, "baseline", "BASE-LITERAL-PASSWORD-HASH")
    }


def test_files_hashing_the_same_text_become_one_finding(tmp_path):
    write(tmp_path, "api/requirements.txt", "fastapi\n")
    hashing(tmp_path, "api/app/services/bootstrap.py", ADMIN)
    hashing(tmp_path, "api/scripts/seed_data.py", ADMIN)
    hashing(tmp_path, "worker/app/db/seed.py", ADMIN, fallback=True)
    hashing(tmp_path, "api/app/services/other.py", OTHER)
    write(tmp_path, "README.md", f"Sign in with {ADMIN}\n")
    result = found(tmp_path)
    assert set(result) == {"api/app/services/bootstrap.py", "api/app/services/other.py"}
    merged = result["api/app/services/bootstrap.py"]
    assert (merged.tag.value, merged.severity.value) == ("CONFIRMED", "critical")
    assert [str(loc) for loc in merged.locations] == [
        "api/app/services/bootstrap.py:4",
        "api/scripts/seed_data.py:4",
        "worker/app/db/seed.py:4",
        "README.md:1",
    ]
    assert "The same text is hashed in 3 files." in merged.detail
    assert "worker/app/db/seed.py it is the fallback" in merged.detail


def test_unreferenced_seed_script_alone_is_low(tmp_path):
    hashing(tmp_path, "scripts/seed_data.py", ADMIN)
    [finding] = found(tmp_path).values()
    assert (finding.tag.value, finding.severity.value) == ("CONFIRMED", "low")
    assert "Only scripts that no start command" in finding.detail


def test_seed_script_run_at_start_is_critical(tmp_path):
    hashing(tmp_path, "api/app/db/seed.py", ADMIN)
    write(tmp_path, "api/startup.sh", "python -m app.db.seed\n")
    [finding] = found(tmp_path).values()
    assert finding.severity.value == "critical"


def test_seed_script_run_in_ci_is_critical(tmp_path):
    hashing(tmp_path, "scripts/seed_demo.py", ADMIN)
    write(
        tmp_path,
        ".github/workflows/deploy.yml",
        "jobs:\n  x:\n    steps:\n      - run: python scripts/seed_demo.py\n",
    )
    [finding] = found(tmp_path).values()
    assert finding.severity.value == "critical"


def test_merged_output_never_contains_the_text(tmp_path):
    write(tmp_path, "api/requirements.txt", "fastapi\n")
    hashing(tmp_path, "api/app/services/bootstrap.py", ADMIN)
    hashing(tmp_path, "api/scripts/seed_data.py", ADMIN)
    report = review(tmp_path, reviews=["baseline"])
    assert ADMIN not in render_json(report)


def test_distinct_literals_in_one_file_are_separate_findings(tmp_path):
    write(
        tmp_path,
        "api/app/services/bootstrap.py",
        "import os\nfrom app.core.security import get_password_hash\n"
        "def seed(db):\n"
        f"    db.add(User(password_hash=get_password_hash('{FIRST}')))\n"
        f"    db.add(User(password_hash=get_password_hash('{SECOND}')))\n",
    )
    hashing(tmp_path, "api/scripts/other_seed.py", FIRST)
    results = findings_for(tmp_path, "baseline", "BASE-LITERAL-PASSWORD-HASH")
    assert len(results) == 2
    shared = next(f for f in results if len(f.locations) == 2)
    alone = next(f for f in results if len(f.locations) == 1)
    assert [str(loc) for loc in shared.locations] == [
        "api/app/services/bootstrap.py:4",
        "api/scripts/other_seed.py:4",
    ]
    assert "The same text is hashed in 2 files." in shared.detail
    assert [str(loc) for loc in alone.locations] == ["api/app/services/bootstrap.py:5"]
    assert "hashed in" not in alone.detail


def test_neither_literal_nor_digest_reaches_output(tmp_path):
    write(
        tmp_path,
        "api/app/services/bootstrap.py",
        "import os\nfrom app.core.security import get_password_hash\n"
        "def seed(db):\n"
        f"    db.add(User(password_hash=get_password_hash('{FIRST}')))\n"
        f"    db.add(User(password_hash=get_password_hash('{SECOND}')))\n",
    )
    hashing(tmp_path, "api/scripts/other_seed.py", FIRST)
    report = review(tmp_path, reviews=["baseline"])
    outputs = render_markdown(report) + render_json(report)
    assert FIRST not in outputs and SECOND not in outputs
    assert hashlib.sha256(FIRST.encode("utf-8")).hexdigest() not in outputs
    assert hashlib.sha256(SECOND.encode("utf-8")).hexdigest() not in outputs


def _api_server(root):
    write(root, "api/requirements.txt", "fastapi\n")
    write(
        root,
        "api/app/main.py",
        "from fastapi import FastAPI\napp = FastAPI()\n\n\n@app.get('/x')\ndef x():\n    return 'ok'\n",
    )


def _worker_server(root):
    write(root, "worker/requirements.txt", "flask\n")
    write(
        root,
        "worker/app.py",
        "from flask import Flask\napp = Flask(__name__)\n\n\n@app.route('/x')\ndef x():\n"
        "    return 'ok'\n",
    )


def test_deploy_file_in_a_different_app_root_does_not_mark_a_seed_script_referenced(tmp_path):
    _api_server(tmp_path)
    hashing(tmp_path, "api/scripts/seed_data.py", ADMIN)
    _worker_server(tmp_path)
    write(
        tmp_path,
        "worker/infra/main.tf",
        'resource "x" "y" {\n  command = "python scripts/seed_data.py"\n}\n',
    )
    [finding] = found(tmp_path).values()
    assert (finding.tag.value, finding.severity.value) == ("CONFIRMED", "low")


def test_repository_level_deploy_file_still_marks_a_seed_script_referenced(tmp_path):
    _api_server(tmp_path)
    hashing(tmp_path, "api/scripts/seed_data.py", ADMIN)
    _worker_server(tmp_path)
    write(
        tmp_path,
        "infra/main.tf",
        'resource "x" "y" {\n  command = "python scripts/seed_data.py"\n}\n',
    )
    [finding] = found(tmp_path).values()
    assert finding.severity.value == "critical"
