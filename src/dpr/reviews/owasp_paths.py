"""Review 5, OWASP A01: request values that reach a file path (path traversal).

A sink is a call that touches the file system at a path: `open()`, `Path.write_bytes()` and
friends, `shutil` and `os` file operations, a Django storage's `save`, `open` or `delete`, an
uploaded file's own `save(path)`, and `send_file` / `FileResponse(path)`. Django `form.save()`
and model `.save()` are never sinks: FileField names are cleaned by the storage. Helpers are
followed through the calling file's own definitions and imports only.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from dataclasses import dataclass

from dpr.model import Finding, Location, Route, Tag
from dpr.parsing import imports, jsts, pyast
from dpr.parsing.routes_py import top_level_defs
from dpr.redact import snippet
from dpr.reviews.access import fastapi_aliases, path_params
from dpr.reviews.paid_targets import py_target
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule

WRITE_MODE = re.compile(r"[wax+]")
SANITIZERS = re.compile(
    r"(?:^|\.)(secure_filename|basename|uuid4|uuid1|token_hex|token_urlsafe|safe_join"
    r"|get_valid_filename|get_valid_name|get_available_name|slugify)$"
)
SAFE_ATTRIBUTES = {"name", "stem", "suffix", "hex"}
SCALAR_TYPES = frozenset({"int", "float", "bool", "UUID", "Decimal", "date", "datetime"})
# Parts of the Django or Flask request object that the caller cannot turn into a path.
SAFE_REQUEST = {"user", "method", "session", "auth", "site", "resolver_match", "LANGUAGE_CODE"}
# Calls that build a path or string from their arguments: taint passes through them exactly.
# Any other call passes taint on too, but the flow is then no longer read end to end.
PATH_BUILDERS = re.compile(
    r"^(?:os\.path\.(?:join|normpath|abspath|realpath|expanduser)|posixpath\.join"
    r"|(?:pathlib\.)?(?:Pure(?:Posix|Windows)?)?Path|str)$"
)
STR_METHODS = {
    "format", "join", "replace", "lower", "upper", "strip", "lstrip", "rstrip", "get",
    "getlist", "joinpath", "with_name", "with_suffix", "encode", "decode",
}  # fmt: skip
# Database lookups return stored records, not the request value that selected them.
ORM_CALL = re.compile(r"\.objects\.|(?:^|\.)get_(?:object|list)_or_404$|\.query\.")
STORAGE = re.compile(r"(?:^|\.)(?:default_storage|storage|\w+_storage)$")
STORAGE_CLASS = re.compile(r"(?:^|\.)(?:FileSystemStorage|get_storage_class)$")
UPLOAD_NAME = re.compile(r"(?i)(?:^|_)(?:file|upload|attachment)s?$")
COPY_CALLS = {"os.rename", "os.replace", "shutil.move", "shutil.copy", "shutil.copy2",
              "shutil.copyfile", "shutil.copytree"}  # fmt: skip
DELETE_CALLS = {"os.remove", "os.unlink", "shutil.rmtree"}
# Calls that read a file from a path argument. Django's FileResponse takes an open file, not a
# path, so it counts only when imported from FastAPI or Starlette.
READ_CALLS = {"send_file", "flask.send_file", "FileResponse", "responses.FileResponse"}
PATH_RESPONSE_MODULES = re.compile(r"^(?:fastapi|starlette|flask)\b")
ACTIONS = {"write": "writes a file to", "delete": "deletes a file at", "read": "reads a file from"}
NOT_REQUEST = re.compile(r"Depends|Security|Request|Session|BackgroundTasks|Response|WebSocket")
REQUEST_DATA = re.compile(r"^request\.(?:files|form|args|values|data|json|FILES|POST|GET)\b")
JS_WRITE = re.compile(
    r"(?:fs\.|fsp\.|promises\.|fs\.promises\.)?(writeFile|writeFileSync|createWriteStream|appendFile"
    r"|appendFileSync|rename|renameSync)"
)
JS_SOURCE = re.compile(
    r"req\.(?:body|query|params|file|files)|\.originalname|formData\.get\(|\bfile\.name\b|params\.\w+"
)

# A taint maps each request source to True when every step from the request to here was read
# exactly (assignments, path builders, string methods), or False when it passed through a
# call whose effect on the value is not known.
Taint = dict[str, bool]


@dataclass(frozen=True)
class Reach:
    sink: Location
    exact: bool
    action: str


def _params(fn: ast.AST) -> list[str]:
    args = [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
    return [a.arg for a in args if a.arg not in ("self", "cls")]


def _merge(into: Taint, more: Taint) -> Taint:
    for source, exact in more.items():
        into[source] = into.get(source, False) or exact
    return into


def _taint_of(node: ast.AST | None, taint: dict[str, Taint]) -> Taint:
    if node is None:
        return {}
    if isinstance(node, ast.Name):
        return dict(taint.get(node.id, {}))
    request_data = REQUEST_DATA.match(ast.unparse(node))
    if request_data:
        return {request_data.group(0): True}
    if isinstance(node, ast.Attribute):
        value = node.value
        if isinstance(value, ast.Name) and value.id == "request" and node.attr in SAFE_REQUEST:
            return {}
        return {} if node.attr in SAFE_ATTRIBUTES else _taint_of(value, taint)
    if isinstance(node, ast.Call):
        name = pyast.dotted(node.func) or ""
        if SANITIZERS.search(name) or ORM_CALL.search(name):
            return {}
        found: Taint = {}
        for part in [*node.args, *(k.value for k in node.keywords)]:
            _merge(found, _taint_of(part, taint))
        method = isinstance(node.func, ast.Attribute)
        if method:
            _merge(found, _taint_of(node.func.value, taint))
        if PATH_BUILDERS.match(name) or (method and node.func.attr in STR_METHODS):
            return found
        return dict.fromkeys(found, False)
    found = {}
    for child in ast.iter_child_nodes(node):
        _merge(found, _taint_of(child, taint))
    return found


def _mode(call: ast.Call, position: int, default: str) -> str:
    mode = pyast.constant(call.args[position], default) if len(call.args) > position else default
    return str(pyast.constant(pyast.kwarg(call, "mode"), mode))


def _storage(node: ast.AST, storages: set[str]) -> bool:
    name = pyast.dotted(node) or ""
    built = name.replace("()", "")
    return name in storages or bool(STORAGE.search(name) or STORAGE_CLASS.search(built))


def _path_responses(ctx: Context, rel: str) -> bool:
    """The file takes send_file or FileResponse from a framework whose version reads a path."""
    names = imports.py_imports(ctx.index, rel, pyast.parse_file(ctx.index, rel))
    return any(
        PATH_RESPONSE_MODULES.match(names.get(n, (None, "", ""))[2].lstrip("."))
        for n in ("send_file", "FileResponse", "responses")
    )


def _sink(
    call: ast.Call, taint: dict[str, Taint], storages: set[str], path_responses: bool
) -> tuple[ast.AST, str] | None:
    """The path argument of a file system call and what the call does there."""
    name = pyast.dotted(call.func) or ""
    last = name.split(".")[-1]
    if name in ("open", "io.open", "aiofiles.open", "codecs.open") and call.args:
        return call.args[0], "write" if WRITE_MODE.search(_mode(call, 1, "r")) else "read"
    if name in COPY_CALLS:
        return (call.args[1], "write") if len(call.args) > 1 else None
    if name in DELETE_CALLS and call.args:
        return call.args[0], "delete"
    if name in READ_CALLS and call.args and path_responses:
        return call.args[0], "read"
    if not isinstance(call.func, ast.Attribute):
        return None
    receiver = call.func.value
    if last in ("write_bytes", "write_text"):
        return receiver, "write"
    if last in ("read_bytes", "read_text"):
        return receiver, "read"
    if last in ("unlink", "rmdir") and not call.args:
        return receiver, "delete"
    if _storage(receiver, storages):
        if last == "save" and call.args:
            return call.args[0], "write"
        if last == "open" and call.args:
            return call.args[0], "write" if WRITE_MODE.search(_mode(call, 1, "rb")) else "read"
        if last == "delete" and call.args:
            return call.args[0], "delete"
        return None
    if last == "open" and call.args:
        mode = str(pyast.constant(call.args[0], ""))
        return (receiver, "write") if WRITE_MODE.search(mode) else None
    if last == "save" and len(call.args) == 1:
        # An uploaded file's own save(path) (Flask / Werkzeug FileStorage), never a form or
        # a model: those take a user, a commit flag or nothing, and name files themselves.
        upload = "request.files" in _taint_of(receiver, taint)
        if upload or UPLOAD_NAME.search((pyast.dotted(receiver) or "").split(".")[-1]):
            return call.args[0], "write"
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


def _callee(
    ctx: Context, rel: str, call: ast.Call, fn: ast.AST
) -> tuple[str, ast.AST, bool] | None:
    """The definition this file's own names and imports give the call, or a method of the
    calling class for `self.x()`. A same-named function elsewhere is never used."""
    func = call.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        if func.value.id in ("self", "cls"):
            tree = pyast.parse_file(ctx.index, rel)
            for cls in pyast.class_defs(tree) if tree else []:
                if fn in cls.body:
                    for item in cls.body:
                        if isinstance(item, pyast.FunctionNode) and item.name == func.attr:
                            return rel, item, True
            return None
    return py_target(ctx, rel, call, fn)


def reaches(
    ctx: Context, rel: str, fn: ast.AST, seeds: dict[str, Taint], depth: int = 0
) -> dict[str, Reach]:
    """Seed names (usually parameters) that reach a file path, with the sink location."""
    if _guarded(fn):
        return {}
    taint = {name: dict(sources) for name, sources in seeds.items()}
    storages: set[str] = set()
    path_responses = _path_responses(ctx, rel)
    found: dict[str, Reach] = {}

    def record(source: str, reach: Reach) -> None:
        if source not in found or (reach.exact and not found[source].exact):
            found[source] = reach

    nodes = sorted(
        (n for n in ast.walk(fn) if hasattr(n, "lineno")), key=lambda n: (n.lineno, n.col_offset)
    )
    for node in nodes:
        if isinstance(node, ast.If) and _allowlist_exit(node):
            taint[node.test.left.id] = {}
        if isinstance(node, ast.Assign | ast.AnnAssign) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    taint[target.id] = _taint_of(node.value, taint)
                    value = node.value
                    if isinstance(value, ast.Call) and _storage(value.func, set()):
                        storages.add(target.id)
        if isinstance(node, ast.withitem) and isinstance(node.optional_vars, ast.Name):
            taint[node.optional_vars.id] = _taint_of(node.context_expr, taint)
        if not isinstance(node, ast.Call):
            continue
        sink = _sink(node, taint, storages, path_responses)
        if sink is not None:
            path, action = sink
            for source, exact in _taint_of(path, taint).items():
                record(source, Reach(Location(rel, node.lineno), exact, action))
            continue
        if depth >= 3:
            continue
        target = _callee(ctx, rel, node, fn)
        if target is None or target[1] is fn:
            continue
        helper_rel, helper, exact_call = target
        params = _params(helper)
        inner = reaches(ctx, helper_rel, helper, {p: {p: True} for p in params}, depth + 1)
        arguments = dict(zip(params, node.args, strict=False))
        arguments.update({k.arg: k.value for k in node.keywords if k.arg})
        for param, reach in inner.items():
            for source, exact in _taint_of(arguments.get(param), taint).items():
                record(
                    source, Reach(reach.sink, exact and exact_call and reach.exact, reach.action)
                )
    return found


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
                action=ACTIONS["write"],
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
        seeds = {
            name: dict.fromkeys(sources, True)
            for name, sources in request_params(ctx, route).items()
        }
        found = reaches(ctx, route.file, route.handler, seeds)
        if not found:
            continue
        sinks = list(dict.fromkeys(reach.sink for _, reach in sorted(found.items())))
        confirmed = all(r.exact for r in found.values())
        done = {r.action for r in found.values()}
        action = next(a for a in ("write", "delete", "read") if a in done)
        names = sorted(found)
        source = "the request value" + ("s " if len(names) > 1 else " ") + " and ".join(names)
        yield make_finding(
            "OWASP-A01-PATH-TRAVERSAL",
            tag=Tag.CONFIRMED if confirmed else Tag.INFERRED,
            locations=[Location(route.file, route.line), *sinks],
            snippet=snippet(ctx.index.text(sinks[0].file), sinks[0].line),
            method=route.method,
            path=route.path,
            action=ACTIONS[action],
            source=source,
        )
