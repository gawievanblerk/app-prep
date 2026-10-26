from dpr.pii_values import code_counts, iban_valid, sa_id_valid, table_counts, text_counts
from tests.fake_pii import (
    bad_citizen,
    bad_date,
    failing_luhn,
    fake_account,
    fake_iban,
    fake_id,
    fake_mobile,
    random_numbers,
)
from tests.fixture_builder import git
from tests.reviews.helpers import findings_for, write


def test_sa_id_needs_date_citizenship_and_checksum():
    assert all(sa_id_valid(fake_id(i)) for i in range(40))
    assert not any(sa_id_valid(failing_luhn(i)) for i in range(40))
    assert not any(sa_id_valid(bad_date(i)) for i in range(40))
    assert not any(sa_id_valid(bad_citizen(i)) for i in range(40))
    assert not sa_id_valid(fake_id(1)[:12])
    assert not sa_id_valid("abcdefghijklm")


def test_iban_needs_mod_97():
    assert all(iban_valid(fake_iban(i)) for i in range(5))
    broken = fake_iban(1)
    assert not iban_valid(broken[:-1] + str((int(broken[-1]) + 1) % 10))


def test_headerless_table_is_judged_by_values():
    rows = [
        f"REF{i:04d},Person {i},{fake_id(i)},Savings,Bank,{fake_account(i)},250655,100\n"
        for i in range(8)
    ]
    counts = table_counts("".join(rows), ",")
    assert counts.headerless
    assert (counts.ids, counts.accounts) == (8, 8)
    assert counts.confirmed
    assert counts.describe().startswith("8 South African ID numbers that pass the checksum")


def test_weak_header_with_id_values_is_caught():
    text = "Policy Number,Reference\n" + "".join(f"P{i},{fake_id(i)}\n" for i in range(6))
    counts = table_counts(text, ",")
    assert not counts.headerless
    assert counts.ids == 6


def test_phone_column_without_leading_zero_needs_a_phone_header():
    rows = "".join(f"P{i},{fake_mobile(i)[1:]}\n" for i in range(6))
    assert table_counts("Policy,Preferred Nr\n" + rows, ",").phones == 6
    assert table_counts("Policy,Order\n" + rows, ",").phones == 0
    full = "".join(f"P{i},{fake_mobile(i)}\n" for i in range(6))
    counts = table_counts("Policy,Contact\n" + full, ",")
    assert counts.phones == 6
    assert not counts.confirmed


def test_random_numbers_and_order_ids_do_not_count():
    numbers = random_numbers(200)
    text = "order_id,amount\n" + "".join(f"{n},10\n" for n in numbers)
    assert table_counts(text, ",").ids == 0
    headerless = "".join(
        f"{n},{m}\n" for n, m in zip(numbers, random_numbers(200, 3, 10), strict=True)
    )
    counts = table_counts(headerless, ",")
    assert (counts.ids, counts.phones, counts.accounts) == (0, 0, 0)
    bad = "".join(f"{failing_luhn(i)},{bad_date(i)},{bad_citizen(i)}\n" for i in range(30))
    assert table_counts(bad, ",").ids == 0
    assert text_counts(" ".join(numbers)).ids == 0


def test_account_numbers_need_a_branch_column():
    rows = "".join(f"{fake_id(i)},{fake_account(i)},{i}\n" for i in range(5))
    assert table_counts(rows, ",").accounts == 0
    header = "id,account,branch_code\n"
    assert table_counts(header + rows, ",").accounts == 5


def test_two_valid_ids_are_not_enough():
    text = "id\n" + fake_id(1) + "\n" + fake_id(2) + "\n"
    assert table_counts(text, ",").ids == 0
    assert text_counts(f"{fake_id(1)} {fake_id(2)}").ids == 0
    assert text_counts(" ".join(fake_id(i) for i in range(3))).ids == 3


def test_text_counts_bulk_contacts():
    emails = " ".join(f"person{i}@example.invalid" for i in range(12))
    assert text_counts(emails).emails == 12
    assert text_counts("a@example.invalid b@example.invalid").emails == 0
    ibans = " ".join(fake_iban(i) for i in range(3))
    assert text_counts(ibans).ibans == 3


def test_code_counts_literals():
    ids = "\n".join(f'    "{fake_id(i)}",' for i in range(5))
    counts = code_counts(f"IDS = [\n{ids}\n]\n")
    assert (counts.ids, counts.first_line, counts.last_line) == (5, 2, 6)
    phones = "\n".join(f'    "{fake_mobile(i)}",  # someone' for i in range(6))
    assert code_counts(f"NUMS = [\n{phones}\n]\n").phones == 6
    assert code_counts("created = 1704067200000\nx = 8001015009087.5\n").ids == 0


def test_headerless_data_file_is_reported_by_values(tmp_path):
    rows = "".join(f"R{i},Person {i},{fake_id(i)},{fake_account(i)},632005\n" for i in range(6))
    write(tmp_path, "app/migrations/archived/refunds.csv", rows)
    write(tmp_path, "data/orders.csv", "".join(f"{n},1\n" for n in random_numbers(30)))
    git(tmp_path, "init", "-q")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "initial")
    [finding] = findings_for(tmp_path, "inventory", "INV-PII-FILE-IN-REPO")
    assert str(finding.locations[0]) == "app/migrations/archived/refunds.csv:1"
    assert finding.tag.value == "CONFIRMED"
    assert finding.severity.value == "high"
    assert "6 South African ID numbers that pass the checksum" in finding.detail
    assert "no header row" in finding.detail
    for i in range(6):
        assert fake_id(i) not in finding.detail + finding.title + finding.fix
        assert f"Person {i}" not in finding.detail


def test_value_only_data_file_under_tests_is_low(tmp_path):
    rows = "".join(f"{fake_id(i)}\n" for i in range(4))
    write(tmp_path, "app/tests/ids.txt", rows)
    [finding] = findings_for(tmp_path, "inventory", "INV-PII-FILE-IN-REPO")
    assert finding.severity.value == "low"


def test_contact_only_data_file_is_inferred(tmp_path):
    write(
        tmp_path,
        "data/contacts.json",
        "[" + ",".join(f'"{fake_mobile(i)}"' for i in range(12)) + "]",
    )
    [finding] = findings_for(tmp_path, "inventory", "INV-PII-FILE-IN-REPO")
    assert finding.tag.value == "INFERRED"
    assert "12 South African mobile numbers" in finding.detail


def test_id_literals_in_code_are_reported_once_per_file(tmp_path):
    ids = "\n".join(f'        "{fake_id(i)}",' for i in range(13))
    write(
        tmp_path,
        "app/migrations/0045_flag_ids.py",
        f"def run(apps, schema):\n    flagged = [\n{ids}\n    ]\n",
    )
    phones = "\n".join(f'    "{fake_mobile(i)}",  # name' for i in range(8))
    write(tmp_path, "app/settings/site_settings.py", f"TEST_NUMBERS = [\n{phones}\n]\n")
    write(
        tmp_path,
        "app/tests/test_ids.py",
        f'SAMPLE = ["{fake_id(1)}", "{fake_id(2)}", "{fake_id(3)}"]\n',
    )
    write(tmp_path, "app/clock.py", "STAMPS = [1704067200000, 1704153600000, 1704240000000]\n")
    found = {
        f.locations[0].file: f for f in findings_for(tmp_path, "leaks", "LEAK-PII-LITERAL-IN-CODE")
    }
    assert sorted(found) == [
        "app/migrations/0045_flag_ids.py",
        "app/settings/site_settings.py",
        "app/tests/test_ids.py",
    ]
    migration = found["app/migrations/0045_flag_ids.py"]
    assert migration.tag.value == "CONFIRMED" and migration.severity.value == "high"
    assert "13 South African ID numbers that pass the checksum" in migration.detail
    assert (migration.locations[0].line, migration.locations[0].end_line) == (3, 15)
    settings = found["app/settings/site_settings.py"]
    assert settings.tag.value == "INFERRED" and settings.severity.value == "medium"
    assert "8 South African mobile numbers" in settings.detail
    assert found["app/tests/test_ids.py"].severity.value == "low"
    for finding in found.values():
        assert finding.snippet is None
        for i in range(13):
            assert fake_id(i) not in finding.detail


def test_licence_and_notes_files_are_not_records(tmp_path):
    authors = "\n".join(f"Author {i} <author{i}@example.invalid>" for i in range(20))
    write(tmp_path, "static/fonts/LICENSE.txt", authors)
    write(tmp_path, "docs/AUTHORS", authors)
    write(tmp_path, "CHANGELOG.md.txt", authors)
    assert findings_for(tmp_path, "inventory", "INV-PII-FILE-IN-REPO") == []
    write(tmp_path, "exports/people.txt", authors)
    [finding] = findings_for(tmp_path, "inventory", "INV-PII-FILE-IN-REPO")
    assert finding.locations[0].file == "exports/people.txt"
