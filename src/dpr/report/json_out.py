"""Render a Report as JSON."""

from __future__ import annotations

import dataclasses
import json
from enum import Enum
from pathlib import PurePath

from dpr.model import Report


def to_data(obj: object) -> object:
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {
            f.name: to_data(getattr(obj, f.name))
            for f in dataclasses.fields(obj)
            if f.metadata.get("json", True)
        }
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, dict):
        return {str(k): to_data(v) for k, v in obj.items()}
    if isinstance(obj, set | frozenset):
        return sorted(to_data(v) for v in obj)
    if isinstance(obj, list | tuple):
        return [to_data(v) for v in obj]
    if isinstance(obj, PurePath):
        return str(obj)
    return obj


def render_json(report: Report) -> str:
    data = {"schema_version": 1, **to_data(report)}
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"
