"""Personal values found by value (ID numbers, bank accounts, IBANs, mobile numbers, email
addresses) never reach any output: Markdown, JSON, SARIF, the files the CLI writes, stdout or
stderr. The values are built at runtime by tests.fake_pii."""

from dpr.api import review
from dpr.cli import main
from dpr.report.json_out import render_json
from dpr.report.markdown import render_markdown
from dpr.report.sarif import render_sarif
from tests.fake_pii import fake_account, fake_iban, fake_id, fake_mobile
from tests.fixture_builder import git
from tests.reviews.helpers import write

IDS = [fake_id(i) for i in range(15)]
ACCOUNTS = [fake_account(i) for i in range(6)]
MOBILES = [fake_mobile(i) for i in range(12)]
IBANS = [fake_iban(i) for i in range(4)]
EMAILS = [f"client{i}@example.invalid" for i in range(12)]


def corpus(root):
    write(root, "app/requirements.txt", "django\n")
    write(root, "app/manage.py", "import django\n")
    rows = "".join(
        f"R{i},Client {i},{IDS[i]},Savings,{ACCOUNTS[i]},250655,{MOBILES[i]}\n" for i in range(6)
    )
    write(root, "app/migrations/archived/refunds.csv", rows)
    listed = "\n".join(f'        "{value}",' for value in IDS)
    write(
        root,
        "app/migrations/0045_flag_ids.py",
        f"def run(apps, schema):\n    flagged = [\n{listed}\n    ]\n",
    )
    numbers = "\n".join(f'    "{value}",  # staff' for value in MOBILES)
    write(root, "app/settings/site_settings.py", f"TEST_NUMBERS = [\n{numbers}\n]\n")
    write(root, "data/payees.sql", "\n".join(f"INSERT INTO p VALUES ('{v}');" for v in IBANS))
    write(root, "data/contacts.txt", "\n".join(EMAILS + MOBILES))
    git(root, "init", "-q")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "initial")
    return root


def test_personal_values_found_by_value_never_reach_any_output(tmp_path, capsys):
    root = corpus(tmp_path / "repo")
    report = review(root)
    fired = {(f.rule_id, f.locations[0].file) for f in report.findings}
    assert {
        ("INV-PII-FILE-IN-REPO", "app/migrations/archived/refunds.csv"),
        ("INV-PII-FILE-IN-REPO", "data/payees.sql"),
        ("INV-PII-FILE-IN-REPO", "data/contacts.txt"),
        ("LEAK-PII-LITERAL-IN-CODE", "app/migrations/0045_flag_ids.py"),
        ("LEAK-PII-LITERAL-IN-CODE", "app/settings/site_settings.py"),
    } <= fired
    outputs = [render_markdown(report), render_json(report), render_sarif(report)]
    outputs.append(repr(report.findings))
    out_dir = tmp_path / "out"
    assert main(["scan", str(root), "--format", "md,json,sarif", "--out", str(out_dir)]) == 0
    outputs += [p.read_text() for p in out_dir.iterdir()]
    captured = capsys.readouterr()
    outputs += [captured.out, captured.err]
    for value in IDS + ACCOUNTS + MOBILES + IBANS + EMAILS:
        for text in outputs:
            assert value not in text
    for value in MOBILES:
        for text in outputs:
            assert value[1:] not in text
