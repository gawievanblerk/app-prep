"""Path helpers shared by review rules."""

from __future__ import annotations

import re

TEST_PATH = re.compile(
    r"(?:^|/)(?:tests?|__tests__|specs?|fixtures?|e2e|cypress|__mocks__)/"
    r"|(?:^|/)test_[^/]*\.py$|_test\.py$|(?:^|/)conftest\.py$"
    r"|\.(?:test|spec)\.[cm]?[jt]sx?$"
)


def is_test(rel: str) -> bool:
    return bool(TEST_PATH.search(rel))
