"""Review 4, baseline: password rules that current guidance advises against.

Composition rules (an upper case letter, a digit, a symbol) and forced periodic changes make
users pick predictable passwords. NIST SP 800-63B asks verifiers not to impose either.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Tag
from dpr.redact import snippet
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule

LISTED = 5
COMMENT = re.compile(r"^\s*(?:#|//|\*|/\*)")
PASSWORD = re.compile(r"(?i)passw(?:or)?d")
MESSAGE = re.compile(
    r"(?i)(?:must|should|needs?\s+to)\s+(?:contain|include|have)\s+(?:at\s+least\s+)?"
    r"(?:one\s+|1\s+|an?\s+)?(?:upper|lower|capital|digit|number|numeric|special|symbol"
    r"|non-alphanumeric|punctuation)"
)
VALIDATOR = re.compile(
    r"\b\w*(?:Upper(?:case)?|Lower(?:case)?|Symbol|Special\w*|(?:Has|Contains|Requires?)"
    r"(?:Number|Digit))\w*Validator\b"
)
CLASS_PATTERN = re.compile(
    r"\[A-Z\]|\[a-z\]|\\d|\[0-9\]|\[\^a-zA-Z0-9|\[\^A-Za-z0-9|\[!@#|\(\?=\.\*"
)
REGEX_CALL = re.compile(r"re\.(?:search|match|fullmatch|compile)|\.test\(|\.regex\(|\.matches\(")
EXPIRY = re.compile(
    r"\b\w*passw(?:or)?d_?(?:expir|max_?age|rotation|change_?interval|age_?days)\w*", re.I
)
NOT_EXPIRY = re.compile(r"(?i)reset|token|link|otp|code|email|verif|invite|hint")


def _source_lines(ctx: Context) -> Iterator[tuple[str, str, int, str]]:
    for entry in [*ctx.index.py_files, *ctx.index.js_files]:
        if is_test(entry.rel):
            continue
        text = ctx.index.text(entry.rel)
        if not PASSWORD.search(text):
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if not COMMENT.match(line):
                yield entry.rel, text, number, line


def _near_password(lines: list[str], index: int) -> bool:
    return any(PASSWORD.search(line) for line in lines[max(0, index - 3) : index + 4])


@rule(
    "BASE-PASSWORD-COMPOSITION",
    review="baseline",
    severity="low",
    exploitability="low",
    owasp="A07",
)
def password_composition(ctx: Context) -> Iterator[Finding]:
    """One finding per file. A rule message or a validator class name is read as enforced; a
    character-class regex next to a password may also be a strength meter, so it is INFERRED."""
    sites: dict[str, list[tuple[int, bool]]] = {}
    texts: dict[str, str] = {}
    split: dict[str, list[str]] = {}
    for rel, text, number, line in _source_lines(ctx):
        texts.setdefault(rel, text)
        lines = split.setdefault(rel, text.splitlines())
        if (MESSAGE.search(line) and _near_password(lines, number - 1)) or VALIDATOR.search(line):
            sites.setdefault(rel, []).append((number, True))
        elif PASSWORD.search(line) and CLASS_PATTERN.search(line) and REGEX_CALL.search(line):
            sites.setdefault(rel, []).append((number, False))
    for rel, found in sites.items():
        direct = any(stated for _, stated in found)
        first = found[0][0]
        yield make_finding(
            "BASE-PASSWORD-COMPOSITION",
            tag=Tag.CONFIRMED if direct else Tag.INFERRED,
            locations=[Location(rel, line) for line, _ in found[:LISTED]],
            snippet=snippet(texts[rel], first),
        )


@rule("BASE-PASSWORD-EXPIRY", review="baseline", severity="low", exploitability="low", owasp="A07")
def password_expiry(ctx: Context) -> Iterator[Finding]:
    """Names such as PASSWORD_EXPIRY_DAYS or passwordMaxAge. Names about reset links, tokens and
    one-time codes are left out: their expiry is wanted."""
    found: list[Location] = []
    first_text = ""
    for rel, text, number, line in _source_lines(ctx):
        names = [m.group(0) for m in EXPIRY.finditer(line)]
        if any(not NOT_EXPIRY.search(name) for name in names):
            first_text = first_text or text
            found.append(Location(rel, number))
    if found:
        yield make_finding(
            "BASE-PASSWORD-EXPIRY",
            tag=Tag.INFERRED,
            locations=found[:LISTED],
            snippet=snippet(first_text, found[0].line),
        )
