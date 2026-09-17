"""Split SQL into statements and find top-level clauses."""

from __future__ import annotations

import re
from dataclasses import dataclass

IDENT = r'(?:"[^"]+"|[a-z_][a-z0-9_$]*)'
QNAME = rf"(?:{IDENT}\s*\.\s*)?{IDENT}"
DOLLAR = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)?\$")


@dataclass(frozen=True)
class Statement:
    text: str
    norm: str
    line: int


class _Builder:
    def __init__(self) -> None:
        self.statements: list[Statement] = []
        self.raw: list[str] = []
        self.norm: list[str] = []
        self.start_line: int | None = None

    def emit(self, line: int) -> None:
        normalized = re.sub(r"\s+", " ", "".join(self.norm)).strip()
        if normalized:
            text = "".join(self.raw).strip()
            self.statements.append(Statement(text, normalized, self.start_line or line))
        self.raw, self.norm, self.start_line = [], [], None


def _is_escape_string(sql: str, i: int) -> bool:
    """True for the quote of an E'...' string, where a backslash escapes the next character."""
    if sql[i] != "'" or i == 0 or sql[i - 1] not in "eE":
        return False
    return i == 1 or not (sql[i - 2].isalnum() or sql[i - 2] in "_$")


def _quoted_end(sql: str, i: int) -> int:
    quote = sql[i]
    backslash = _is_escape_string(sql, i)
    j = i + 1
    while j < len(sql):
        if backslash and sql[j] == "\\":
            j += 2
            continue
        if sql[j] == quote:
            if j + 1 < len(sql) and sql[j + 1] == quote:
                j += 2
                continue
            return j + 1
        j += 1
    return len(sql)


def _block_comment_end(sql: str, i: int) -> int:
    depth, j = 1, i + 2
    while j < len(sql) and depth:
        if sql.startswith("/*", j):
            depth, j = depth + 1, j + 2
        elif sql.startswith("*/", j):
            depth, j = depth - 1, j + 2
        else:
            j += 1
    return j


def split_sql(sql: str) -> list[Statement]:
    b = _Builder()
    i, line, n = 0, 1, len(sql)
    while i < n:
        ch = sql[i]
        if sql.startswith("--", i):
            end = sql.find("\n", i)
            end = n if end == -1 else end
            b.raw.append(sql[i:end])
            b.norm.append(" ")
            i = end
            continue
        if sql.startswith("/*", i):
            end = _block_comment_end(sql, i)
            b.raw.append(sql[i:end])
            b.norm.append(" ")
            line += sql.count("\n", i, end)
            i = end
            continue
        if b.start_line is None and not ch.isspace() and ch != ";":
            b.start_line = line
        if ch in ("'", '"'):
            end = _quoted_end(sql, i)
            b.raw.append(sql[i:end])
            b.norm.append(sql[i:end])
            line += sql.count("\n", i, end)
            i = end
            continue
        if ch == "$":
            match = DOLLAR.match(sql, i)
            follows_word = i > 0 and (sql[i - 1].isalnum() or sql[i - 1] == "_")
            if match and not follows_word:
                close = sql.find(match.group(0), match.end())
                end = n if close == -1 else close + len(match.group(0))
                b.raw.append(sql[i:end])
                b.norm.append(sql[i:end].lower())
                line += sql.count("\n", i, end)
                i = end
                continue
        if ch == ";":
            b.emit(line)
            i += 1
            continue
        if ch == "\n":
            line += 1
        b.raw.append(ch)
        b.norm.append(ch.lower())
        i += 1
    b.emit(line)
    return b.statements


def find_top_level(s: str, keyword_regex: str, start: int = 0) -> int:
    pattern = re.compile(keyword_regex)
    depth, quote = 0, None
    for i in range(start, len(s)):
        ch = s[i]
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0 and pattern.match(s, i):
            if i == 0 or not (s[i - 1].isalnum() or s[i - 1] == "_"):
                return i
    return -1


def balanced(s: str, open_index: int) -> tuple[str, int]:
    depth, quote = 0, None
    for i in range(open_index, len(s)):
        ch = s[i]
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return s[open_index + 1 : i], i + 1
    return s[open_index + 1 :], len(s)


def split_top_level(s: str, sep: str = ",") -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    depth, quote = 0, None
    for ch in s:
        if quote:
            current.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == sep and depth == 0:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def qualify(name: str, default_schema: str = "public") -> str:
    parts = [p[1:-1] if p.startswith('"') else p for p in re.findall(IDENT, name)]
    if len(parts) == 1:
        parts.insert(0, default_schema)
    return ".".join(parts[-2:])


def clean_predicate(predicate: str) -> str:
    p = predicate.strip()
    while p.startswith("("):
        inner, end = balanced(p, 0)
        if end != len(p):
            break
        p = inner.strip()
    return p
