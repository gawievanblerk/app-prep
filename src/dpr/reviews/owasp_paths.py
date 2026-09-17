"""Review 5, OWASP A01: request values that reach a file write path (path traversal)."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from dataclasses import dataclass

from dpr.model import Finding, Location, Route, Tag
from dpr.parsing import jsts, pyast
from dpr.parsing.routes_py import top_level_defs
from dpr.redact import snippet
from dpr.reviews.access import fastapi_aliases, path_params
from dpr.reviews.lookups import helper_index
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule

WRITE_MODE = re.compile(r"[wax+]")
SANITIZERS = re.compile(r"(?:^|\.)(secure_filename|basename|uuid4|uuid1|token_hex|token_urlsafe)$")
SAFE_ATTRIBUTES = {"name", "stem", "suffix", "hex"}
SCALAR_TYPES = frozenset({"int", "float", "bool", "UUID", "Decimal", "date", "datetime"})
NOT_REQUEST = re.compile(r"Depends|Security|Request|Session|BackgroundTasks|Response|WebSocket")
REQUEST_DATA = re.compile(r"^request\.(?:files|form|args|values|data|json|FILES|POST|GET)\b")
JS_WRITE = re.compile(
    r"(?:fs\.|fsp\.|promises\.|fs\.promises\.)?(writeFile|writeFileSync|createWriteStream|appendFile"
    r"|appendFileSync|rename|renameSync)"
)
JS_SOURCE = re.compile(
    r"req\.(?:body|query|params|file|files)|\.originalname|formData\.get\(|\bfile\.name\b|params\.\w+"
)


@dataclass(frozen=True)
class Reach:
    sink: Location
    via_helper: bool
    unique: bool


def _params(fn: ast.AST) -> list[str]:
    args = [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
    return [a.arg for a in args if a.arg not in ("self", "cls")]


def _taint_of(node: ast.AST | None, taint: dict[str, set[str]]) -> set[str]:
    if node is None:
        return set()
    if isinstance(node, ast.Name):
        return set(taint.get(node.id, set()))
    text = ast.unparse(node)
    request_data = REQUEST_DATA.match(text)
    if request_data:
        return {request_data.group(0)}
    if isinstance(node, ast.Attribute):
        return set() if node.attr in SAFE_ATTRIBUTES else _taint_of(node.value, taint)
    if isinstance(node, ast.Call):
        if SANITIZERS.search(pyast.dotted(node.func) or ""):
            return set()
        found = set()
        for part in [*node.args, *(k.value for k in node.keywords)]:
            found |= _taint_of(part, taint)
        if isinstance(node.func, ast.Attribute):
            found |= _taint_of(node.func.value, taint)
        return found
    found = set()
    for child in ast.iter_child_nodes(node):
        found |= _taint_of(child, taint)
    return found


def _sink_path(call: ast.Call) -> ast.AST | None:
    name = pyast.dotted(call.func) or ""
    last = name.split(".")[-1]
    mode = pyast.constant(call.args[1], "") if len(call.args) > 1 else ""
    mode = pyast.constant(pyast.kwarg(call, "mode"), mode)
    if last == "open" and isinstance(call.func, ast.Name | ast.Attribute) and call.args:
        if name in ("open", "aiofiles.open", "io.open") and WRITE_MODE.search(str(mode)):
            return call.args[0]
    if isinstance(call.func, ast.Attribute):
        if last in ("write_bytes", "write_text"):
            return call.func.value
        if (
            last == "open"
            and call.args
            and WRITE_MODE.search(str(pyast.constant(call.args[0], "")))
        ):
            return call.func.value
        if last == "save" and len(call.args) == 1:
            return call.args[0]
    if name in ("os.rename", "os.replace", "shutil.move", "shutil.copy", "shutil.copyfile"):
        return call.args[1] if len(call.args) > 1 else None
    return None


def _guarded(fn: ast.AST) -> bool:
    text = ast.unparse(fn)
    return "is_relative_to(" in text or bool(re.search(r"resolve\(\).*startswith\(", text))


def _allowlist_exit(node: ast.If) -> bool:
    """`if name not in ALLOWED: raise` (or return) leaves `name` as one of the allowed values."""
    test = node.test
    return (
        isinstance(test, ast.Compare)
        and isinstance(test.left, ast.Name)
        and len(test.ops) == 1
        and isinstance(test.ops[0], ast.NotIn)
        and any(isinstance(stmt, ast.Raise | ast.Return) for stmt in node.body)
    )


def reaches(
    ctx: Context, rel: str, fn: ast.AST, seeds: dict[str, set[str]], depth: int = 0
) -> dict[str, Reach]:
    """Seed names (usually parameters) that reach a file write path, with the sink location."""
    if _guarded(fn):
        return {}
    taint = {name: set(sources) for name, sources in seeds.items()}
    found: dict[str, Reach] = {}
    nodes = sorted(
        (n for n in ast.walk(fn) if hasattr(n, "lineno")), key=lambda n: (n.lineno, n.col_offset)
    )
    for node in nodes:
        if isinstance(node, ast.If) and _allowlist_exit(node):
            taint[node.test.left.id] = set()
        if isinstance(node, ast.Assign | ast.AnnAssign) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    taint[target.id] = _taint_of(node.value, taint)
        if isinstance(node, ast.withitem) and isinstance(node.optional_vars, ast.Name):
            taint[node.optional_vars.id] = _taint_of(node.context_expr, taint)
        if not isinstance(node, ast.Call):
            continue
        path = _sink_path(node)
        if path is not None:
            for source in _taint_of(path, taint):
                found.setdefault(source, Reach(Location(rel, node.lineno), False, True))
            continue
        if depth >= 3:
            continue
        name = (pyast.dotted(node.func) or "").split(".")[-1]
        defs = [d for d in helper_index(ctx).get(name, []) if d[1] is not fn]
        if not defs:
            continue
        helper_rel, helper = max(defs, key=lambda d: _shared(rel, d[0]))
        params = _params(helper)
        inner_seeds = {p: {p} for p in params}
        inner = reaches(ctx, helper_rel, helper, inner_seeds, depth + 1)
        arguments = dict(zip(params, node.args, strict=False))
        arguments.update({k.arg: k.value for k in node.keywords if k.arg})
        for param, reach in inner.items():
            for source in _taint_of(arguments.get(param), taint):
                found.setdefault(source, Reach(reach.sink, True, len(defs) == 1 and reach.unique))
    return found


def _shared(a: str, b: str) -> int:
    count = 0
    for left, right in zip(a.split("/"), b.split("/"), strict=False):
        if left != right:
            break
        count += 1
    return count


def _is_enum(ctx: Context, name: str) -> bool:
    return any(
        isinstance(node, ast.ClassDef) and any(b.endswith("Enum") for b in pyast.base_names(node))
        for _rel, node, _tree in top_level_defs(ctx.index).get(name, [])
    )


def scalar_annotation(ctx: Context, node: ast.AST | None) -> bool:
    """int, float, bool, UUID, Decimal, date, datetime, an Enum or a Literal, also inside
    Optional, Annotated or a union with None. The framework rejects any other value, so a
    parameter annotated this way cannot carry a path."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        parts = [node.left, node.right]
        return all(scalar_annotation(ctx, p) or pyast.constant(p, 0) is None for p in parts)
    if isinstance(node, ast.Subscript):
        base = (pyast.dotted(node.value) or "").split(".")[-1]
        items = node.slice.elts if isinstance(node.slice, ast.Tuple) else [node.slice]
        if base == "Literal":
            return True
        if base == "Annotated":
            return scalar_annotation(ctx, items[0])
        if base in ("Optional", "Union"):
            return all(scalar_annotation(ctx, i) or pyast.constant(i, 0) is None for i in items)
        return False
    name = (pyast.dotted(node) or "").split(".")[-1]
    return name in SCALAR_TYPES or (bool(name) and _is_enum(ctx, name))


def request_params(ctx: Context, route: Route) -> dict[str, set[str]]:
    fn = route.handler
    aliases = fastapi_aliases(ctx)
    seeds: dict[str, set[str]] = {"request": {"request"}} if route.framework != "fastapi" else {}
    converted = set(re.findall(r"<(?:int|float|uuid):(\w+)>", route.path))
    params = [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
    defaults = [None] * (len(fn.args.posonlyargs) + len(fn.args.args) - len(fn.args.defaults))
    defaults += [*fn.args.defaults, *fn.args.kw_defaults]
    for param, default in zip(params, defaults, strict=True):
        annotation = ast.unparse(param.annotation) if param.annotation is not None else ""
        text = annotation + " " + (ast.unparse(default) if default is not None else "")
        if param.arg in ("self", "request") or NOT_REQUEST.search(text):
            continue
        if any(re.search(rf"\b{re.escape(alias)}\b", annotation) for alias in aliases):
            continue
        if param.arg in converted or scalar_annotation(ctx, param.annotation):
            continue
        if route.framework == "fastapi" or param.arg in path_params(route):
            seeds[param.arg] = {param.arg}
    return seeds


def _js_findings(ctx: Context, route: Route) -> Iterator[Finding]:
    for call in jsts.calls(route.tree, JS_WRITE, route.handler):
        args = jsts.arguments(call)
        if not args:
            continue
        target = jsts.unwrap(args[0])
        text = jsts.node_text(target)
        if target is not None and target.type == "identifier":
            resolved = jsts.resolve_identifier(target)
            text = jsts.node_text(resolved) if resolved is not None else text
        if JS_SOURCE.search(text) and "basename(" not in text:
            line = jsts.line(route.tree, call)
            yield make_finding(
                "OWASP-A01-PATH-TRAVERSAL",
                tag=Tag.CONFIRMED,
                locations=[Location(route.file, line)],
                snippet=snippet(ctx.index.text(route.file), line),
                method=route.method,
                path=route.path,
                source="a request value",
            )


@rule(
    "OWASP-A01-PATH-TRAVERSAL",
    review="owasp",
    severity="high",
    exploitability="medium",
    owasp="A01",
)
def path_traversal(ctx: Context) -> Iterator[Finding]:
    for route in ctx.detection.routes:
        if is_test(route.file) or route.handler is None:
            continue
        if route.tree is not None and hasattr(route.handler, "type"):
            if route.handler.type in jsts.FUNCTION_TYPES:
                yield from _js_findings(ctx, route)
            continue
        if not isinstance(route.handler, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        found = reaches(ctx, route.file, route.handler, request_params(ctx, route))
        if not found:
            continue
        sinks = list(dict.fromkeys(reach.sink for _, reach in sorted(found.items())))
        confirmed = all(not r.via_helper or r.unique for r in found.values())
        names = sorted(found)
        source = "the request value" + ("s " if len(names) > 1 else " ") + " and ".join(names)
        yield make_finding(
            "OWASP-A01-PATH-TRAVERSAL",
            tag=Tag.CONFIRMED if confirmed else Tag.INFERRED,
            locations=[Location(route.file, route.line), *sinks],
            snippet=snippet(ctx.index.text(sinks[0].file), sinks[0].line),
            method=route.method,
            path=route.path,
            source=source,
        )
