"""Review 7, abuse: everything a route costs to run, traced from the handler into its helpers."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from dpr.discovery.approots import root_of
from dpr.model import Route, SdkUse
from dpr.parsing import pyast
from dpr.reviews.access import ADMIN, PUBLIC, access
from dpr.reviews.auth_flows import Code, route_code
from dpr.reviews.owasp_a01 import attacker
from dpr.reviews.paid import _names_from_import, _tree_names, _uses
from dpr.reviews.paths import is_test
from dpr.rules import Context

CPU_CATEGORIES = frozenset({"pdf", "vector-store", "browser", "image"})
TRACE_DEPTH = 3
SPREADSHEET = re.compile(
    r"\b(?:load_workbook|read_excel|open_workbook|XLSX\.read|ExcelJS\.Workbook|csv\.DictReader)\s*\("
)
PY_HTTP = re.compile(r"\b(?:httpx|requests|aiohttp)\.\w+\(|\bAsyncClient\(|\bClientSession\(")
JS_HTTP = re.compile(r"\b(?:axios\.\w+|fetch)\(\s*[`'\"]https://")


@dataclass(frozen=True)
class CostRow:
    app: str
    route: Route
    calls: tuple[str, ...]
    categories: tuple[str, ...]


def cost_names(ctx: Context) -> dict[str, dict[str, SdkUse]]:
    """File to imported identifier to SDK, for SDKs that bill or burn CPU per call."""
    if "cost_names" not in ctx.facts:
        found: dict[str, dict[str, SdkUse]] = {}
        for sdk in ctx.detection.sdks:
            if not (sdk.paid or sdk.category in CPU_CATEGORIES):
                continue
            for loc in sdk.locations:
                lines = ctx.index.text(loc.file).splitlines()
                if loc.line > len(lines):
                    continue
                for name in _names_from_import(lines[loc.line - 1], loc.file.endswith(".py")):
                    found.setdefault(loc.file, {})[name] = sdk
        ctx.facts["cost_names"] = found
    return ctx.facts["cost_names"]


def _self_clients(tree: ast.Module, node: ast.AST, names: dict[str, SdkUse]) -> dict[str, SdkUse]:
    """Attributes such as self._client built from an SDK anywhere in the method's class."""
    found: dict[str, SdkUse] = {}
    for cls in pyast.class_defs(tree):
        if node not in cls.body:
            continue
        for sub in ast.walk(cls):
            if isinstance(sub, ast.Assign):
                sdk = _uses(ast.unparse(sub.value), names)
                for target in sub.targets if sdk else []:
                    if isinstance(target, ast.Attribute) and pyast.dotted(target.value) == "self":
                        found[f"self.{target.attr}"] = sdk
    return found


def code_costs(ctx: Context, code: Code) -> list[tuple[str, str]]:
    names = _tree_names(code.tree, cost_names(ctx).get(code.rel, {}))
    text = code.text()
    hits: list[tuple[str, str]] = []
    if code.python and isinstance(code.tree, ast.Module):
        for attr, sdk in _self_clients(code.tree, code.node, names).items():
            if re.search(rf"{re.escape(attr)}\b", text):
                hits.append((sdk.name, sdk.category))
    sdk = _uses(text, names)
    if sdk is not None:
        hits.append((sdk.name, sdk.category))
    if SPREADSHEET.search(text):
        hits.append(("spreadsheet parse", "spreadsheet"))
    if (PY_HTTP if code.python else JS_HTTP).search(text):
        hits.append(("outbound HTTP", "http"))
    return hits


def app_label(ctx: Context, rel: str) -> str:
    home = root_of(ctx.detection.app_roots, rel)
    return home.path if home is not None and home.path else "."


def auth_label(ctx: Context, route: Route) -> str:
    level = access(ctx, route)
    if level.level == PUBLIC:
        return "no"
    if level.level == ADMIN:
        return "admin only"
    return attacker(level.evidence)


def cost_rows(ctx: Context) -> list[CostRow]:
    """One row per route that reaches a billed SDK, a CPU-heavy library or an outbound call."""
    if "cost_rows" not in ctx.facts:
        rows = []
        for route in ctx.detection.routes:
            if is_test(route.file) or route.handler is None:
                continue
            hits: list[tuple[str, str]] = []
            for code in route_code(ctx, route, TRACE_DEPTH):
                hits += code_costs(ctx, code)
            if hits:
                unique = list(dict.fromkeys(hits))
                rows.append(
                    CostRow(
                        app_label(ctx, route.file),
                        route,
                        tuple(name for name, _ in unique),
                        tuple(dict.fromkeys(category for _, category in unique)),
                    )
                )
        ctx.facts["cost_rows"] = rows
    return ctx.facts["cost_rows"]
