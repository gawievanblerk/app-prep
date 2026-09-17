"""Just enough HCL for Terraform checks: top-level blocks and their top-level attributes."""

from __future__ import annotations

import re
from dataclasses import dataclass

HEAD = re.compile(r'^[ \t]*([A-Za-z_][\w-]*)((?:\s+"[^"]*")*)\s*\{', re.MULTILINE)
ATTRIBUTE = re.compile(r"^\s*([A-Za-z_][\w-]*)\s*=\s*(.*?)\s*$")
LABEL = re.compile(r'"([^"]*)"')
HEREDOC_START = re.compile(r"<<-?([A-Za-z_][A-Za-z0-9_]*)")


@dataclass(frozen=True)
class Block:
    kind: str
    labels: tuple[str, ...]
    line: int
    body: str
    body_line: int


def _blank(chars: list[str], start: int, end: int) -> None:
    for i in range(start, end):
        if chars[i] != "\n":
            chars[i] = " "


def _string_end(text: str, start: int) -> int:
    """Index just past the closing quote of the string opened at text[start - 1].

    Tracks a stack of "string"/"interp" frames so `${...}` interpolation, which may itself
    contain nested quoted strings (for example a ternary expression), does not end the string
    early.
    """
    stack = ["string"]
    i, n = start, len(text)
    while i < n and stack:
        ch = text[i]
        mode = stack[-1]
        if mode == "string":
            if ch == "\\":
                i += 2
                continue
            if text.startswith("${", i):
                stack.append("interp")
                i += 2
                continue
            if ch == '"':
                stack.pop()
        elif ch == '"':
            stack.append("string")
        elif ch == "{":
            stack.append("interp")
        elif ch == "}":
            stack.pop()
        i += 1
    return i


def _heredoc_end(text: str, start: int, marker: str) -> int:
    """Index just past the line whose stripped text is `marker`, searching from `start`."""
    n = len(text)
    pos = start
    while pos < n:
        newline = text.find("\n", pos)
        line_end = n if newline == -1 else newline
        if text[pos:line_end].strip() == marker:
            return n if newline == -1 else newline + 1
        if newline == -1:
            return n
        pos = newline + 1
    return n


def _mask(text: str) -> str:
    """A same-length copy of `text` with comments, strings and heredoc bodies blanked to spaces.

    Newlines are kept, so line numbers computed from either copy agree. Used to find real block
    and attribute boundaries without being misled by a brace, `#` or `//` inside a string or
    comment, or by a resource block that is commented out or sits inside a heredoc body.
    """
    chars = list(text)
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = n if end == -1 else end + 2
            _blank(chars, i, end)
            i = end
        elif ch == "#" or text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end == -1 else end
            _blank(chars, i, end)
            i = end
        elif ch == '"':
            end = _string_end(text, i + 1)
            _blank(chars, i, end)
            i = end
        elif ch == "<":
            match = HEREDOC_START.match(text, i)
            if match:
                newline = text.find("\n", match.end())
                body_start = n if newline == -1 else newline + 1
                end = _heredoc_end(text, body_start, match.group(1))
                _blank(chars, i, end)
                i = end
            else:
                i += 1
        else:
            i += 1
    return "".join(chars)


def _strip_comments(text: str) -> str:
    """`text` with `#`, `//` and `/* ... */` comments blanked, strings kept verbatim.

    A comment marker inside a string is never mistaken for the start of a comment.
    """
    chars = list(text)
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = n if end == -1 else end + 2
            _blank(chars, i, end)
            i = end
        elif ch == "#" or text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end == -1 else end
            _blank(chars, i, end)
            i = end
        elif ch == '"':
            i = _string_end(text, i + 1)
        else:
            i += 1
    return "".join(chars)


def _block_end(masked: str, start: int) -> int:
    """Index just past the brace that closes the block opened at masked[start - 1].

    `masked` must already have comments, strings and heredoc bodies blanked, so every
    remaining brace is real HCL structure.
    """
    depth, i, n = 1, start, len(masked)
    while i < n:
        ch = masked[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def blocks(text: str) -> list[Block]:
    masked = _mask(text)
    found = []
    position = 0
    while True:
        match = HEAD.search(masked, position)
        if match is None:
            return found
        end = _block_end(masked, match.end())
        head = text[match.start() : match.end()]
        labels = tuple(LABEL.findall(head))
        line = text.count("\n", 0, match.start()) + 1
        body = text[match.end() : end - 1]
        body_line = text.count("\n", 0, match.end()) + 1
        found.append(Block(match.group(1), labels, line, body, body_line))
        position = end


def attributes(block: Block) -> dict[str, tuple[str, int]]:
    """Top-level `name = value` pairs of a block, with the line of each.

    Comments are stripped before matching (`#` and `//` outside strings, `/* ... */`
    anywhere) and brace depth is counted on comment- and string-free text, so a nested block,
    or a brace or comment marker inside a string, never confuses top level with nested.
    """
    found: dict[str, tuple[str, int]] = {}
    masked_lines = _mask(block.body).split("\n")
    value_lines = _strip_comments(block.body).split("\n")
    depth = 0
    for offset, (masked_line, value_line) in enumerate(zip(masked_lines, value_lines, strict=True)):
        if depth == 0:
            match = ATTRIBUTE.match(value_line)
            if match:
                found[match.group(1)] = (match.group(2), block.body_line + offset)
        depth += masked_line.count("{") - masked_line.count("}")
        depth = max(depth, 0)
    return found


def unquote(value: str) -> str:
    value = value.strip()
    return value[1:-1] if len(value) >= 2 and value[0] == value[-1] == '"' else value
