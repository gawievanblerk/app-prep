"""Build a Detection from one RepoIndex."""

from __future__ import annotations

import re

from dpr.data import load
from dpr.discovery.packages import collect_env_vars, collect_packages, normalise
from dpr.gitutil import git_info
from dpr.model import Detection, Location, SdkUse
from dpr.parsing.routes import extract_routes
from dpr.parsing.schemas import extract_models
from dpr.parsing.sqlschema import load_schema
from dpr.walk import RepoIndex


def _code_matches(index: RepoIndex, pattern: str) -> bool:
    regex = re.compile(pattern)
    return any(regex.search(index.text(f.rel)) for f in index.js_files + index.py_files)


def _match(signals: dict, index: RepoIndex, packages: set[str]) -> list[str]:
    found = []
    for name, spec in signals.items():
        if (any(normalise(p) in packages for p in spec.get("packages", []))
                or any(index.named(pattern) for pattern in spec.get("files", []))
                or (spec.get("text") and _code_matches(index, spec["text"]))):
            found.append(name)
    return found


def _header_config(index: RepoIndex, spec: dict) -> list[str]:
    regex = re.compile(spec["text"])
    return sorted(f.rel for f in index.named(*spec["files"]) if regex.search(
        index.text(f.rel)))


def _sdks(packages: set[str], sites: dict[str, list[Location]]) -> list[SdkUse]:
    found = []
    for sdk in load("sdks.yaml"):
        names = [normalise(p) for p in sdk["packages"]]
        if not any(n in packages for n in names):
            continue
        locations = sorted({loc for n in names for loc in sites.get(n, [])},
                           key=lambda loc: (loc.file, loc.line))[:20]
        found.append(SdkUse(sdk["name"], sdk["category"], sdk["recipient"], sdk["paid"],
                            tuple(locations)))
    return found


def detect(index: RepoIndex) -> Detection:
    stack = load("stack.yaml")
    packages, sites = collect_packages(index)
    schema = load_schema(index)
    env_vars = collect_env_vars(index)
    hosting = _match(stack["hosting"], index, packages)
    return Detection(
        languages=index.language_counts(),
        frameworks=_match(stack["frameworks"], index, packages),
        databases=_match(stack["databases"], index, packages),
        orms=_match(stack["orms"], index, packages),
        auth_providers=_match(stack["auth_providers"], index, packages),
        hosting=hosting,
        ci=sorted(f.rel for f in index.glob(".github/workflows/*")),
        logging=_match(stack["logging"], index, packages),
        header_config=_header_config(index, stack["header_config"]),
        rate_limiters=_match(stack["rate_limiters"], index, packages),
        test_frameworks=_match(stack["test_frameworks"], index, packages),
        env_vars=env_vars,
        sdks=_sdks(packages, sites),
        routes=extract_routes(index),
        models=extract_models(index, schema),
        git=git_info(index.root),
        serverless=any(h in stack["serverless_hosting"] for h in hosting),
        public_supabase_key=any(e.public and "SUPABASE" in e.name for e in env_vars),
        packages=packages,
        schema=schema,
    )
