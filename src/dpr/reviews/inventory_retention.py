"""Review 1, inventory: how long personal data stays, and who can read it."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.discovery.approots import root_of
from dpr.model import DataModel, Finding, Location, Tag
from dpr.parsing import hcl, jsts, pyast
from dpr.reviews.access import access
from dpr.reviews.paths import is_test
from dpr.reviews.personal import personal_fields
from dpr.rules import Context, make_finding, rule

DELETE_CALL = re.compile(
    r"(?:^|\.)(?:delete|destroy|deleteMany|deleteOne|findByIdAndDelete|remove|purge)$"
)
SQL_DELETE = re.compile(r"(?i)delete\s+from\s+\"?(\w+)")
SOFT_FIELDS = {"deleted", "is_deleted", "deleted_at", "deletedat", "archived", "is_archived"}
RETENTION_ATTRS = re.compile(
    r"^\s*((?:backup_)?retention(?:_in)?_(?:days|period)|log_retention_days"
    r"|soft_delete_retention_days|retention_days|geo_redundant_backup_enabled)\s*=\s*(\S+)",
    re.MULTILINE,
)
SCHEDULE = re.compile(
    r"(?i)crons|schedule:|beat_schedule|add_job|cron\.schedule|@periodic_task|scheduler"
)


def _functions(ctx: Context) -> list[tuple[str, object, object, str]]:
    key = ("inventory-functions", "")
    if key not in ctx.index.cache:
        found = []
        for entry in ctx.index.py_files:
            if is_test(entry.rel):
                continue
            tree = pyast.parse_file(ctx.index, entry.rel)
            for fn in pyast.functions(tree) if tree else []:
                found.append((entry.rel, fn, tree, ast.unparse(fn)))
        for entry in ctx.index.js_files:
            if is_test(entry.rel):
                continue
            for tree in jsts.parse_file(ctx.index, entry.rel):
                for fn in jsts.walk(tree.root, jsts.FUNCTION_TYPES):
                    found.append((entry.rel, fn, tree, jsts.node_text(fn)))
        ctx.index.cache[key] = found
    return ctx.index.cache[key]


def _origin(name: str, assigned: dict[str, str], depth: int = 3) -> str:
    """The text a variable was built from, following earlier variables a few steps back."""
    text, seen, frontier = "", {name}, [name]
    for _ in range(depth):
        following = []
        for current in frontier:
            value = assigned.get(current, "")
            text += " " + value
            words_in = re.findall(r"[A-Za-z_]\w*", value)
            following += [w for w in words_in if w in assigned and w not in seen]
        seen.update(following)
        frontier = following
    return text


def _deleted_models(fn: object, tree: object, models: list[DataModel]) -> dict[str, int]:
    """Model key to the line of a delete whose target is that model's rows."""
    found: dict[str, int] = {}
    if isinstance(fn, ast.AST):
        assigned = {
            t.id: ast.unparse(n.value)
            for n in ast.walk(fn)
            if isinstance(n, ast.Assign)
            for t in n.targets
            if isinstance(t, ast.Name)
        }
        for call in [c for c in ast.walk(fn) if isinstance(c, ast.Call)]:
            name = pyast.dotted(call.func) or ""
            if not DELETE_CALL.search(name):
                continue
            target = " ".join(ast.unparse(a) for a in call.args) + " " + name
            for arg in call.args:
                if isinstance(arg, ast.Name):
                    target += " " + _origin(arg.id, assigned)
            for model in models:
                if _mentions(target, model):
                    found.setdefault(_key(model), call.lineno)
        for node in ast.walk(fn):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                for match in SQL_DELETE.finditer(node.value):
                    for model in models:
                        if match.group(1).lower() == model.table.split(".")[-1].lower():
                            found.setdefault(_key(model), node.lineno)
        return found
    for call in jsts.walk(fn, {"call_expression"}):
        callee = jsts.callee(call)
        if DELETE_CALL.search(callee):
            for model in models:
                if _mentions(callee, model) or re.search(
                    rf"\.{re.escape(model.name[:1].lower() + model.name[1:])}\.", callee
                ):
                    found.setdefault(_key(model), jsts.line(tree, call))
    return found


def _mentions(text: str, model: DataModel) -> bool:
    table = model.table.split(".")[-1]
    return bool(re.search(rf"\b{re.escape(model.name)}\b|\b{re.escape(table)}\b", text))


def deletion_paths(ctx: Context) -> dict[str, list[Location]]:
    """Model key to lines that hard-delete its rows."""
    if "deletion_paths" not in ctx.facts:
        paths: dict[str, list[Location]] = {}
        models = ctx.detection.models
        for rel, fn, tree, text in _functions(ctx):
            if not re.search(r"(?i)delete|destroy|remove|purge", text):
                continue
            for key, line in _deleted_models(fn, tree, models).items():
                paths.setdefault(key, []).append(Location(rel, line))
        ctx.facts["deletion_paths"] = paths
    return ctx.facts["deletion_paths"]


def _key(model: DataModel) -> str:
    return f"{model.location.file}:{model.name}"


def soft_delete(ctx: Context, model: DataModel) -> bool:
    if {f.name.lower() for f in model.fields} & SOFT_FIELDS:
        return True
    text = ctx.index.text(model.location.file)
    return bool(re.search(rf"class\s+{re.escape(model.name)}\s*\([^)]*SoftDelete", text))


def retention_text(ctx: Context, model: DataModel) -> str:
    paths = deletion_paths(ctx).get(_key(model), [])
    if paths:
        return f"hard delete available (`{paths[0]}`)"
    if soft_delete(ctx, model):
        return "soft delete flag only, rows kept; retained indefinitely"
    return "retained indefinitely, no deletion path found"


def iac_retention(ctx: Context) -> list[tuple[str, str, Location]]:
    """Backup and log retention settings from Terraform: (resource, setting = value, location)."""
    found = []
    for entry in ctx.index.with_suffix(".tf"):
        text = ctx.index.text(entry.rel)
        for block in hcl.blocks(text):
            if block.kind != "resource" or len(block.labels) != 2:
                continue
            for match in RETENTION_ATTRS.finditer(block.body):
                line = block.body_line + block.body[: match.start(1)].count("\n")
                found.append(
                    (
                        f"{block.labels[0]} {block.labels[1]}",
                        f"{match.group(1)} = {match.group(2)}",
                        Location(entry.rel, line),
                    )
                )
    return found


def readers(ctx: Context, model: DataModel) -> str:
    """Route access levels and auth dependencies of routes whose handler names the model."""
    levels: dict[str, set[str]] = {}
    for route in ctx.detection.routes:
        if route.method not in ("GET", "ANY") or route.handler is None or is_test(route.file):
            continue
        handler_text = (
            ast.unparse(route.handler)
            if isinstance(route.handler, ast.AST)
            else jsts.node_text(route.handler)
        )
        tree_text = ctx.index.text(route.file)
        if not (
            _mentions(handler_text, model)
            or (_mentions(tree_text, model) and model.name in tree_text)
        ):
            continue
        level = access(ctx, route)
        levels.setdefault(level.level, set()).add(level.evidence)
    if not levels:
        return "no read route names this model; database administrators UNKNOWN"
    parts = [
        f"{name}: {', '.join(sorted(e for e in evidence if e))}"
        for name, evidence in sorted(levels.items())
    ]
    return "; ".join(parts) + "; database administrators UNKNOWN"


@rule("INV-NO-DELETION-PATH", review="inventory", severity="medium", exploitability="low")
def no_deletion_path(ctx: Context) -> Iterator[Finding]:
    people = {_key(p.model): p.model for p in personal_fields(ctx)}
    by_root: dict[str, list[DataModel]] = {}
    for key, model in sorted(people.items()):
        if deletion_paths(ctx).get(key) or is_test(model.location.file):
            continue
        home = root_of(ctx.detection.app_roots, model.location.file)
        by_root.setdefault(home.path if home else "", []).append(model)
    schedules = any(
        SCHEDULE.search(ctx.index.text(f.rel))
        for f in ctx.index.named("vercel.json", "*.yml", "*.yaml", "celery*.py", "scheduler*.py")
    )
    for root, models in by_root.items():
        soft = [m.name for m in models if soft_delete(ctx, m)]
        what = f"No code path hard-deletes rows of {', '.join(m.name for m in models)}."
        if soft:
            what += f" {', '.join(soft)} only set a soft delete flag, so the rows stay."
        if schedules:
            what += " Scheduled jobs exist; none of them was found deleting these tables."
        yield make_finding(
            "INV-NO-DELETION-PATH",
            tag=Tag.INFERRED,
            locations=[m.location for m in models][:10],
            app=root or "this repository",
            what=what,
        )
