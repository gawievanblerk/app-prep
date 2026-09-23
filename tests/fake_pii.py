"""Fake personal values built at runtime, so no real-looking value sits in the test source."""

from __future__ import annotations

import random


def luhn_check_digit(body: str) -> str:
    """The digit that makes body + digit pass the Luhn checksum."""
    total = 0
    for position, char in enumerate(reversed(body)):
        digit = int(char)
        if position % 2 == 0:
            digit *= 2
            digit -= 9 if digit > 9 else 0
        total += digit
    return str((10 - total % 10) % 10)


def fake_id(index: int, citizen: str = "0", day: str = "01") -> str:
    """A South African ID number that passes the date and checksum checks."""
    month = 1 + index % 12
    body = f"9{index % 10}{month:02d}{day}{5000 + index:04d}{citizen}8"
    return body + luhn_check_digit(body)


def failing_luhn(index: int) -> str:
    valid = fake_id(index)
    return valid[:-1] + str((int(valid[-1]) + 1) % 10)


def bad_date(index: int) -> str:
    body = f"9{index % 10}13{index % 28 + 1:02d}{5000 + index:04d}08"
    return body + luhn_check_digit(body)


def bad_citizen(index: int) -> str:
    body = f"9{index % 10}0101{5000 + index:04d}58"
    return body + luhn_check_digit(body)


def fake_mobile(index: int) -> str:
    return f"0{7 + index % 2}{index:08d}"


def fake_iban(index: int) -> str:
    """A GB-shaped IBAN whose mod-97 check passes."""
    bban = f"WEST{600000 + index:06d}{index:08d}"
    digits = "".join(str(int(c, 36)) for c in bban + "GB00")
    check = 98 - int(digits) % 97
    return f"GB{check:02d}{bban}"


def fake_account(index: int) -> str:
    return f"62{index:08d}"


def random_numbers(count: int, seed: int = 7, length: int = 13) -> list[str]:
    """Random digit strings of `length`, as order numbers or references would be."""
    rng = random.Random(seed)
    return ["".join(rng.choice("0123456789") for _ in range(length)) for _ in range(count)]
