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
from dpr.walk import RepoIndex, line_of


def _code_matches(index: RepoIndex, pattern: str) -> bool:
    regex = re.compile(pattern)
    return any(regex.search(index.text(f.rel)) for f in index.js_files + index.py_files)


def _iac_matches(index: RepoIndex, pattern: str) -> bool:
    regex = re.compile(rf'^\s*resource\s+"(?:{pattern})"', re.MULTILINE)
    return any(regex.search(index.text(f.rel)) for f in index.with_suffix(".tf"))


def _all_groups(spec: dict, packages: set[str]) -> bool:
    groups = spec.get("all_packages") or []
    return bool(groups) and all(any(normalise(p) in packages for p in g) for g in groups)


def _match(signals: dict, index: RepoIndex, packages: set[str]) -> list[str]:
    found = []
    for name, spec in signals.items():
        if (
            any(normalise(p) in packages for p in spec.get("packages", []))
            or any(index.named(pattern) for pattern in spec.get("files", []))
            or (spec.get("text") and _code_matches(index, spec["text"]))
            or (spec.get("iac") and _iac_matches(index, spec["iac"]))
            or _all_groups(spec, packages)
        ):
            found.append(name)
    return [n for n in found if not set(signals[n].get("unless", [])) & set(found)]


def _hosting(signals: dict, index: RepoIndex, packages: set[str]) -> list[str]:
    """Hosts from config files and IaC; a weak signal is dropped when a platform is known."""
    found = _match(signals, index, packages)
    platforms = [n for n in found if not signals[n].get("weak") and not signals[n].get("tooling")]
    return [n for n in found if not (signals[n].get("weak") and platforms)]


def _ci(index: RepoIndex, names: list[str]) -> list[str]:
    files = {f.rel for f in index.glob(".github/workflows/*")}
    files |= {f.rel for f in index.files if f.rel in names}
    return sorted(files)


def _header_config(index: RepoIndex, spec: dict) -> list[str]:
    regex = re.compile(spec["text"])
    return sorted(f.rel for f in index.named(*spec["files"]) if regex.search(index.text(f.rel)))


def _module_sites(index: RepoIndex, modules: list[str]) -> set[Location]:
    found: set[Location] = set()
    for module in modules:
        name = re.escape(module)
        regex = re.compile(rf"^\s*(?:from\s+{name}(?:\.\w+)*\s+import\b|import\s+{name}\b)", re.M)
        for entry in index.py_files:
            text = index.text(entry.rel)
            if module.split(".")[0] in text:
                found |= {
                    Location(entry.rel, line_of(text, m.start())) for m in regex.finditer(text)
                }
    return found


def _html_sites(index: RepoIndex, patterns: list[str]) -> set[Location]:
    found: set[Location] = set()
    for pattern in patterns:
        regex = re.compile(pattern)
        for entry in index.with_suffix(".html", ".htm"):
            text = index.text(entry.rel)
            found |= {Location(entry.rel, line_of(text, m.start())) for m in regex.finditer(text)}
    return found


def _sdks(index: RepoIndex, packages: set[str], sites: dict[str, list[Location]]) -> list[SdkUse]:
    found = []
    for sdk in load("sdks.yaml"):
        names = [normalise(p) for p in sdk["packages"]]
        html = _html_sites(index, sdk["html"]) if sdk.get("html") else set()
        if not any(n in packages for n in names) and not html:
            continue
        extra = _module_sites(index, sdk["modules"]) if sdk.get("modules") else set()
        locations = sorted(
            {loc for n in names for loc in sites.get(n, [])} | extra | html,
            key=lambda loc: (loc.file, loc.line),
        )[:20]
        found.append(
            SdkUse(sdk["name"], sdk["category"], sdk["recipient"], sdk["paid"], tuple(locations))
        )
    return found


def detect(index: RepoIndex) -> Detection:
    stack = load("stack.yaml")
    packages, sites = collect_packages(index)
    schema = load_schema(index)
    env_vars = collect_env_vars(index)
    hosting = _hosting(stack["hosting"], index, packages)
    return Detection(
        languages=index.language_counts(),
        frameworks=_match(stack["frameworks"], index, packages),
        databases=_match(stack["databases"], index, packages),
        orms=_match(stack["orms"], index, packages),
        auth_providers=_match(stack["auth_providers"], index, packages),
        hosting=hosting,
        ci=_ci(index, stack["ci_files"]),
        logging=_match(stack["logging"], index, packages),
        header_config=_header_config(index, stack["header_config"]),
        rate_limiters=_match(stack["rate_limiters"], index, packages),
        test_frameworks=_match(stack["test_frameworks"], index, packages),
        env_vars=env_vars,
        sdks=_sdks(index, packages, sites),
        routes=extract_routes(index),
        models=extract_models(index, schema),
        git=git_info(index.root),
        serverless=any(h in stack["serverless_hosting"] for h in hosting),
        public_supabase_key=any(e.public and "SUPABASE" in e.name for e in env_vars),
        packages=packages,
        schema=schema,
    )
