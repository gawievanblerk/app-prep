"""Package data files (YAML)."""

from functools import cache
from importlib.resources import files

import yaml


@cache
def load(name: str) -> object:
    text = files("dpr.data").joinpath(name).read_text(encoding="utf-8")
    return yaml.safe_load(text)
