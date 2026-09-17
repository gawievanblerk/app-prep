"""Parser for model blocks in schema.prisma files."""

from __future__ import annotations

import re
from dataclasses import dataclass

MODEL_START = re.compile(r"^\s*model\s+(\w+)\s*\{")
FIELD = re.compile(r"^\s*(\w+)\s+(\w+)(\[\])?(\?)?\s*(.*?)\s*$")
TABLE_MAP = re.compile(r'@@map\(\s*"([^"]+)"\s*\)')
COLUMN_MAP = re.compile(r'(?<!@)@map\(\s*"([^"]+)"\s*\)')


@dataclass(frozen=True)
class PrismaField:
    name: str
    type: str
    optional: bool
    is_list: bool
    attributes: str
    column: str
    line: int


@dataclass(frozen=True)
class PrismaModel:
    name: str
    table: str
    fields: tuple[PrismaField, ...]
    line: int


def _strip_comment(line: str) -> str:
    quote = False
    for i, ch in enumerate(line):
        if ch == '"':
            quote = not quote
        elif not quote and line.startswith("//", i):
            return line[:i]
    return line


def parse_prisma(text: str) -> list[PrismaModel]:
    models: list[PrismaModel] = []
    name, table, start = "", "", 0
    fields: list[PrismaField] = []
    inside = False
    for number, raw in enumerate(text.splitlines(), start=1):
        line = _strip_comment(raw)
        if not inside:
            match = MODEL_START.match(line)
            if match:
                name = table = match.group(1)
                start, fields, inside = number, [], True
            continue
        stripped = line.strip()
        if stripped.startswith("}"):
            models.append(PrismaModel(name, table, tuple(fields), start))
            inside = False
            continue
        if not stripped:
            continue
        if stripped.startswith("@@"):
            mapped = TABLE_MAP.search(stripped)
            if mapped:
                table = mapped.group(1)
            continue
        match = FIELD.match(line)
        if match:
            attributes = match.group(5)
            column = COLUMN_MAP.search(attributes)
            fields.append(
                PrismaField(
                    name=match.group(1),
                    type=match.group(2),
                    optional=bool(match.group(4)),
                    is_list=bool(match.group(3)),
                    attributes=attributes,
                    column=column.group(1) if column else match.group(1),
                    line=number,
                )
            )
    return models
