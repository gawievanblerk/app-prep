"""Just enough HCL for Terraform checks: top-level blocks and their top-level attributes."""

from __future__ import annotations

import re
from dataclasses import dataclass

HEAD = re.compile(r'^([A-Za-z_][\w-]*)((?:\s+"[^"]*")*)\s*\{', re.MULTILINE)
ATTRIBUTE = re.compile(r"^\s*([A-Za-z_][\w-]*)\s*=\s*(.*?)\s*$")


@dataclass(frozen=True)
class Block:
    kind: str
    labels: tuple[str, ...]
    line: int
    body: str
    body_line: int


def _block_end(text: str, start: int) -> int:
    """Index just past the brace that closes the block opened at text[start - 1]."""
    depth, i, stack = 1, start, []
    while i < len(text):
        ch = text[i]
        mode = stack[-1] if stack else "code"
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
        elif text.startswith("#", i) or text.startswith("//", i):
            end = text.find("\n", i)
            i = len(text) if end == -1 else end
            continue
        elif ch == '"':
            stack.append("string")
        elif ch == "{":
            if mode == "interp":
                stack.append("interp")
            else:
                depth += 1
        elif ch == "}":
            if mode == "interp":
                stack.pop()
            else:
                depth -= 1
                if depth == 0:
                    return i + 1
        i += 1
    return len(text)


def blocks(text: str) -> list[Block]:
    found = []
    position = 0
    while True:
        match = HEAD.search(text, position)
        if match is None:
            return found
        end = _block_end(text, match.end())
        labels = tuple(re.findall(r'"([^"]*)"', match.group(2)))
        line = text.count("\n", 0, match.start()) + 1
        body = text[match.end() : end - 1]
        body_line = text.count("\n", 0, match.end()) + 1
        found.append(Block(match.group(1), labels, line, body, body_line))
        position = end


def attributes(block: Block) -> dict[str, tuple[str, int]]:
    """Top-level `name = value` pairs of a block, with the line of each."""
    found: dict[str, tuple[str, int]] = {}
    depth = 0
    for offset, raw in enumerate(block.body.split("\n")):
        line = raw.split("#", 1)[0]
        if depth == 0:
            match = ATTRIBUTE.match(line)
            if match:
                found[match.group(1)] = (match.group(2), block.body_line + offset)
        depth += line.count("{") - line.count("}")
        depth = max(depth, 0)
    return found


def unquote(value: str) -> str:
    value = value.strip()
    return value[1:-1] if len(value) >= 2 and value[0] == value[-1] == '"' else value
