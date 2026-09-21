from dpr.api import review
from dpr.report.json_out import render_json
from tests.reviews.helpers import findings_for, write

ADMIN = "Adm1n" + "-Merge-" + "7713"
OTHER = "Oth3r" + "-Merge-" + "7713"


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
