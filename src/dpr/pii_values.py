"""Personal data found by value: South African ID numbers, IBANs, bank account numbers next to a
branch code, South African mobile numbers and email addresses. Functions here validate and count;
none returns or keeps a value beyond the call."""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass
from datetime import date

# Caps that keep a scan of a large repository fast: characters read per file and rows sampled.
MAX_CHARS = 262_144
MAX_ROWS = 2_000
# A kind counts only with this many distinct valid values, and in a table only when they are at
# least this share of a column's non-empty cells.
MIN_DISTINCT = 3
MIN_SHARE = 0.2
# Contact details in free text (JSON, SQL, text) count only in bulk.
MIN_CONTACTS = 10
# Mobile numbers written as string literals in code.
MIN_CODE_PHONES = 5
# Universal branch codes of South African banks.
BRANCH_CODES = frozenset(
    {
        "250655",  # First National Bank
        "632005",  # Absa
        "470010",  # Capitec
        "198765",  # Nedbank
        "051001",  # Standard Bank
        "678910",  # TymeBank / older African Bank code
        "430000",  # African Bank
        "580105",  # Investec
        "462005",  # Bidvest Bank
        "450105",  # Mercantile Bank
        "460005",  # Postbank
        "679000",  # Discovery Bank
        "888000",  # Bank Zero
        "410506",  # Ubank
        "000205",  # Standard Bank (older)
    }
)

DIGITS13 = re.compile(r"(?<![\w.])\d{13}(?![\w.])")
IBAN = re.compile(r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}[A-Z0-9]{11,30}(?![A-Za-z0-9])")
MOBILE = re.compile(r"(?:\+?27|0027|0)[678]\d{8}")
LOCAL_MOBILE = re.compile(r"[678]\d{8}")
MOBILE_TEXT = re.compile(r"(?<![\w+])(?:\+27|0027|0)[678]\d[ -]?\d{3}[ -]?\d{4}(?![\w])")
CODE_MOBILE = re.compile(r"""(["'`])((?:\+27|0027|0)[678]\d[ -]?\d{3}[ -]?\d{4})\1""")
EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
ACCOUNT = re.compile(r"\d{7,12}")
PHONE_HEADER = re.compile(r"(?i)phone|cell|mobile|\btel|contact|whats|msisdn|preferred|sms")
BRANCH_HEADER = re.compile(r"(?i)branch")
SEPARATORS = str.maketrans("", "", " -().'\"")


def _luhn(digits: str) -> bool:
    total = 0
    for position, char in enumerate(reversed(digits)):
        digit = ord(char) - 48
        if position % 2:
            digit *= 2
            digit -= 9 if digit > 9 else 0
        total += digit
    return total % 10 == 0


def _date_ok(yy: int, mm: int, dd: int) -> bool:
    for century in (1900, 2000):
        try:
            date(century + yy, mm, dd)
        except ValueError:
            continue
        return True
    return False


def sa_id_valid(value: str) -> bool:
    """13 digits: a real YYMMDD birth date, citizenship digit 0, 1 or 2, and the Luhn check."""
    if len(value) != 13 or not value.isdigit() or value[10] not in "012":
        return False
    return _date_ok(int(value[:2]), int(value[2:4]), int(value[4:6])) and _luhn(value)


def iban_valid(value: str) -> bool:
    if not IBAN.fullmatch(value):
        return False
    moved = value[4:] + value[:4]
    return int("".join(str(int(char, 36)) for char in moved)) % 97 == 1


def mobile_valid(value: str, phone_header: bool = False) -> bool:
    """A South African mobile number (+27 or 0, then 6, 7 or 8 and eight digits). Under a phone
    column header the leading 0 may be missing, as spreadsheets drop it."""
    value = value.translate(SEPARATORS)
    return bool(MOBILE.fullmatch(value) or (phone_header and LOCAL_MOBILE.fullmatch(value)))


@dataclass
class ValueCounts:
    """Distinct valid values per kind. Never holds a value."""

    ids: int = 0
    ibans: int = 0
    accounts: int = 0
    phones: int = 0
    emails: int = 0
    headerless: bool = False
    sampled: bool = False
    first_line: int = 0
    last_line: int = 0

    @property
    def confirmed(self) -> bool:
        """Checksum and date validation passed for several values."""
        return bool(self.ids or self.ibans or self.accounts)

    def __bool__(self) -> bool:
        return bool(self.confirmed or self.phones or self.emails)

    def describe(self) -> str:
        parts = [
            (self.ids, "South African ID numbers that pass the checksum and date check"),
            (self.ibans, "IBANs that pass the mod-97 check"),
            (self.accounts, "bank account numbers next to a branch code column"),
            (self.phones, "South African mobile numbers"),
            (self.emails, "email addresses"),
        ]
        text = [f"{n} {label}" for n, label in parts if n]
        joined = ", ".join(text[:-1]) + (" and " if len(text) > 1 else "") + text[-1]
        return joined + (" in the rows sampled" if self.sampled else "")


def _clean(cell: str) -> str:
    return cell.strip().strip("'\"").strip()


def _share(hits: set[str], cells: list[str]) -> bool:
    return len(hits) >= MIN_DISTINCT and sum(1 for c in cells if c in hits) >= MIN_SHARE * len(
        cells
    )


def _strong(cell: str) -> bool:
    cell = _clean(cell)
    digits = cell.translate(SEPARATORS)
    return (
        sa_id_valid(digits)
        or mobile_valid(cell)
        or iban_valid(digits)
        or bool(EMAIL.fullmatch(cell))
    )


def _rows(text: str, delimiter: str) -> tuple[list[list[str]], bool]:
    sampled = len(text) > MAX_CHARS
    body = text[:MAX_CHARS]
    if sampled:
        body = body[: body.rfind("\n") + 1]
    rows: list[list[str]] = []
    try:
        for row in csv.reader(io.StringIO(body), delimiter=delimiter):
            if len(rows) >= MAX_ROWS:
                return rows, True
            rows.append(row)
    except csv.Error:
        pass
    return rows, sampled


def table_counts(text: str, delimiter: str) -> ValueCounts:
    """Values per column of a delimited file. The first row is a header unless one of its cells
    is itself a valid ID number, IBAN, mobile number or email address."""
    rows, sampled = _rows(text, delimiter)
    if not rows:
        return ValueCounts()
    headerless = any(_strong(cell) for cell in rows[0])
    header = [] if headerless else rows[0]
    data = rows if headerless else rows[1:]
    width = max((len(r) for r in data), default=0)
    found: dict[str, set[str]] = {
        k: set() for k in ("ids", "ibans", "phones", "emails", "accounts")
    }
    accounts: list[set[str]] = []
    branch = False
    for col in range(width):
        name = header[col] if col < len(header) else ""
        cells = [_clean(r[col]) for r in data if col < len(r) and r[col].strip()]
        if not cells:
            continue
        digits = [c.translate(SEPARATORS) for c in cells]
        phone_header = bool(PHONE_HEADER.search(name))
        checks = (
            ("ids", digits, sa_id_valid),
            ("ibans", digits, iban_valid),
            ("emails", cells, lambda c: bool(EMAIL.fullmatch(c))),
            ("phones", cells, lambda c, header=phone_header: mobile_valid(c, header)),
        )
        for kind, values, valid in checks:
            hits = {v for v in values if valid(v)}
            if _share(hits, values):
                found[kind] |= hits
                break
        else:
            if BRANCH_HEADER.search(name) or sum(c in BRANCH_CODES for c in cells) * 2 >= len(
                cells
            ):
                branch = True
                continue
            hits = {d for d in digits if ACCOUNT.fullmatch(d) and not sa_id_valid(d)}
            if len(hits) >= MIN_DISTINCT and len([d for d in digits if d in hits]) * 2 >= len(
                cells
            ):
                accounts.append(hits)
    if branch:
        for hits in accounts:
            found["accounts"] |= hits
    return ValueCounts(
        **{k: len(v) for k, v in found.items()}, headerless=headerless, sampled=sampled
    )


def _distinct(pattern: re.Pattern[str], text: str, valid) -> int:
    return len({m.group(0) for m in pattern.finditer(text) if valid(m.group(0))})


def text_counts(text: str) -> ValueCounts:
    """Values anywhere in free text (JSON, SQL, plain text): ID numbers and IBANs from three
    distinct valid values, mobile numbers and email addresses in bulk only."""
    sampled = len(text) > MAX_CHARS
    body = text[:MAX_CHARS]
    ids = _distinct(DIGITS13, body, sa_id_valid)
    ibans = _distinct(IBAN, body, iban_valid)
    phones = len({m.group(0).translate(SEPARATORS) for m in MOBILE_TEXT.finditer(body)})
    emails = len({m.group(0).lower() for m in EMAIL.finditer(body)})
    return ValueCounts(
        ids=ids if ids >= MIN_DISTINCT else 0,
        ibans=ibans if ibans >= MIN_DISTINCT else 0,
        phones=phones if phones >= MIN_CONTACTS else 0,
        emails=emails if emails >= MIN_CONTACTS else 0,
        sampled=sampled,
    )


def code_counts(text: str) -> ValueCounts:
    """ID number literals (quoted or bare) and quoted mobile numbers in source code, with the
    lines of the first and last hit."""
    ids: dict[str, int] = {}
    phones: dict[str, int] = {}
    for match in DIGITS13.finditer(text):
        if sa_id_valid(match.group(0)):
            ids.setdefault(match.group(0), match.start())
    for match in CODE_MOBILE.finditer(text):
        phones.setdefault(match.group(2).translate(SEPARATORS), match.start())
    counts = ValueCounts()
    starts: list[int] = []
    if len(ids) >= MIN_DISTINCT:
        counts.ids = len(ids)
        starts += ids.values()
    if len(phones) >= MIN_CODE_PHONES:
        counts.phones = len(phones)
        starts += phones.values()
    if starts:
        counts.first_line = text.count("\n", 0, min(starts)) + 1
        counts.last_line = text.count("\n", 0, max(starts)) + 1
    return counts
