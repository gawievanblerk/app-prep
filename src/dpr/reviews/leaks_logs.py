"""Review 6, leak hunt: personal data written to logs, and where those logs go."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from pathlib import PurePosixPath

from dpr.discovery.approots import root_of
from dpr.facts import fact
from dpr.model import Finding, Location, Tag
from dpr.parsing import jsts, pyast
from dpr.redact import snippet
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule

LOG_CALL = re.compile(
    r"console\.(?:log|error|warn|info|debug)|(?:logger|log)\.(?:info|error|warn|debug|log|fatal)"
)
PY_LOG_CALL = re.compile(
    r"print|logging\.(?:debug|info|warning|error|exception|critical)"
    r"|(?:logger|log|LOGGER|\w+_logger)\.(?:debug|info|warning|error|exception|critical)"
)
WHOLE = frozenset(
    {"req", "request", "body", "user", "current_user", "payload", "headers", "session", "token"}
)
WHOLE_ATTRS = frozenset(
    {
        "body",
        "json",
        "data",
        "headers",
        "cookies",
        "form",
        "query_params",
        "POST",
        "GET",
        "__dict__",
    }
)
PII_WORDS = frozenset(
    {"email", "emails", "recipient", "recipients", "phone", "mobile", "address", "ip", "dob",
     "birth", "password", "passwd", "ssn", "passport", "surname", "firstname", "lastname",
     "fullname", "username", "addr"}
)  # fmt: skip
NAME_WORDS = frozenset({"name", "names"})
PERSON_ROOTS = re.compile(
    r"(?i)user|client|customer|member|contact|recipient|profile|account|person|owner|patient"
    r"|student|employee|insured|producer|lead|subscriber|applicant|guest|staff|agent"
)
CONFIG_ROOTS = re.compile(r"(?i)settings|config|conf\b|environ|options")
ERROR_NAMES = frozenset({"err", "error", "e", "exc", "exception", "ex"})
JS_DB = re.compile(r"prisma\.|supabase\.|\bdb\.|\.query\(|\.execute\(|knex|sequelize|mongoose")
PY_DB = re.compile(r"\.objects\.|session\.|cursor\.|\.execute\(|\.query\(|\bdb\.")
HEALTH_QUERY = re.compile(r"(?i)select\s+1\b")
SCRIPT_PATH = re.compile(
    r"(?:^|/)(?:scripts?|bin|tools|management/commands)/|(?:^|/)(?:smoke|manage|cli)[\w-]*\.py$"
)
EXPORTERS = ("monitoring", "error-tracking", "session-replay")
OBJECT_LOGGED = "A request, user, token or database error object is written to the log."
VALUE_LOGGED = (
    "A personal value such as an email address, name or IP address is written to the log."
)
TRACEBACK_LOGGED = "A full traceback, with local values in the message, is printed to the log."
CONSOLE = " It goes to the console of whoever runs this script."


def words(name: str) -> list[str]:
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    return [w for w in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if w]


def personal_name(name: str, root: str | None = None) -> bool:
    parts = words(name)
    if not parts or (root and CONFIG_ROOTS.search(root)):
        return False
    if parts[-1] in PII_WORDS or "".join(parts) in PII_WORDS:
        return True
    if parts[-1] in NAME_WORDS:
        return bool(PERSON_ROOTS.search(root or name))
    return False


def _chain(node: ast.AST) -> list[str]:
    parts = []
    while isinstance(node, ast.Attribute | ast.Subscript):
        if isinstance(node, ast.Attribute):
            parts.append(node.attr)
        else:
            key = pyast.constant(node.slice, None)
            parts.append(key if isinstance(key, str) else "")
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return list(reversed(parts))


def _py_kind(node: ast.AST) -> str | None:
    """'object' for whole request or user objects, 'value' for personal values, else None."""
    if isinstance(node, ast.JoinedStr):
        kinds = [_py_kind(v.value) for v in node.values if isinstance(v, ast.FormattedValue)]
        return next((k for k in kinds if k), None)
    if isinstance(node, ast.Call):
        name = pyast.dotted(node.func) or ""
        if name in ("json.dumps", "str", "repr", "dict", "vars"):
            return next((k for k in map(_py_kind, node.args) if k), None)
        return None
    if isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values, strict=True):
            label = pyast.constant(key, None)
            if isinstance(label, str) and personal_name(label):
                return "value"
            if _py_kind(value):
                return _py_kind(value)
        return None
    chain = _chain(node)
    if not chain:
        return None
    if len(chain) == 1:
        if chain[0] in WHOLE:
            return "object"
        return "value" if personal_name(chain[0]) else None
    if chain[-1] in WHOLE_ATTRS or chain[-2:] == ["client", "host"]:
        return "object" if chain[-1] in WHOLE_ATTRS else "value"
    leaf = chain[-1]
    return "value" if personal_name(leaf, ".".join(chain[:-1])) else None


HandlerScope = tuple[int, int, ast.ExceptHandler, ast.Try]


def _handler_scopes(ctx: Context, rel: str, tree: ast.Module) -> list[HandlerScope]:
    """(first line, last line, handler, try block) for every except handler, once per file."""
    key = ("py-except-scopes", rel)
    if key not in ctx.index.cache:
        found = []
        for block in ast.walk(tree):
            if isinstance(block, ast.Try):
                for handler in block.handlers:
                    found.append(
                        (handler.lineno, handler.end_lineno or handler.lineno, handler, block)
                    )
        ctx.index.cache[key] = found
    return ctx.index.cache[key]


def _handler_scope(
    ctx: Context, rel: str, tree: ast.Module, line: int
) -> tuple[ast.ExceptHandler | None, ast.Try | None]:
    for first, last, handler, block in _handler_scopes(ctx, rel, tree):
        if first <= line <= last:
            return handler, block
    return None, None


def _catch_all(handler: ast.ExceptHandler | None) -> bool:
    return handler is not None and (
        handler.type is None or pyast.dotted(handler.type) in ("Exception", "BaseException")
    )


def _functions(ctx: Context, rel: str, tree: ast.Module) -> list[pyast.FunctionNode]:
    """Every function in the file, once per file."""
    key = ("py-functions", rel)
    if key not in ctx.index.cache:
        ctx.index.cache[key] = pyast.functions(tree)
    return ctx.index.cache[key]


def _function_at(ctx: Context, rel: str, tree: ast.Module, line: int) -> pyast.FunctionNode | None:
    best = None
    for fn in _functions(ctx, rel, tree):
        end = fn.end_lineno or fn.lineno
        if fn.lineno <= line <= end and (best is None or fn.lineno >= best.lineno):
            best = fn
    return best


def _py_error(ctx: Context, rel: str, tree: ast.Module, call: ast.Call, arg: ast.AST) -> bool:
    if isinstance(arg, ast.JoinedStr):
        values = [v.value for v in arg.values if isinstance(v, ast.FormattedValue)]
        return any(_py_error(ctx, rel, tree, call, v) for v in values)
    if isinstance(arg, ast.Call) and pyast.dotted(arg.func) in ("str", "repr") and arg.args:
        return _py_error(ctx, rel, tree, call, arg.args[0])
    root = pyast.name_root(arg)
    if root not in ERROR_NAMES:
        return False
    handler, block = _handler_scope(ctx, rel, tree, call.lineno)
    if handler is not None and handler.name == root:
        body = "\n".join(ast.unparse(s) for s in block.body)
        if PY_DB.search(body) and not HEALTH_QUERY.search(body):
            return True
    traced = pyast.constant(pyast.kwarg(call, "exc_info")) is True
    fn = _function_at(ctx, rel, tree, call.lineno)
    decorated = fn is not None and any(
        "exception_handler" in ast.unparse(d) for d in fn.decorator_list
    )
    return traced and (decorated or (_catch_all(handler) and handler.name == root))


Hit = tuple[int, str, bool]


def _python(ctx: Context, rel: str) -> Iterator[Hit]:
    tree = pyast.parse_file(ctx.index, rel)
    if tree is None:
        return
    script = bool(SCRIPT_PATH.search(rel)) or "__main__" in ctx.index.text(rel)
    for call in pyast.calls(tree, PY_LOG_CALL):
        values = [*call.args, *(k.value for k in call.keywords if k.arg == "extra")]
        kinds = [_py_kind(a) for a in values]
        if any(_py_error(ctx, rel, tree, call, a) for a in call.args):
            kinds.append("object")
        kind = "object" if "object" in kinds else ("value" if "value" in kinds else None)
        if kind is None:
            continue
        console = script and pyast.dotted(call.func) == "print"
        yield call.lineno, OBJECT_LOGGED if kind == "object" else VALUE_LOGGED, console
    for call in pyast.calls(tree, r"traceback\.print_exc"):
        yield call.lineno, TRACEBACK_LOGGED, script


def _catch_has_db(ident) -> bool:
    name = jsts.node_text(ident)
    node = ident.parent
    while node is not None:
        if node.type == "catch_clause":
            param = node.child_by_field_name("parameter")
            if param is not None and jsts.node_text(param) == name:
                body = node.parent.child_by_field_name("body") if node.parent else None
                text = jsts.node_text(body)
                return bool(JS_DB.search(text)) and not HEALTH_QUERY.search(text)
        node = node.parent
    return False


def _error_middleware(ident) -> bool:
    """The identifier is the first of four parameters of an Express error handler."""
    fn = jsts.enclosing_function(ident)
    params = fn.child_by_field_name("parameters") if fn is not None else None
    names = [jsts.node_text(p) for p in params.named_children] if params is not None else []
    return len(names) == 4 and names[0].split(":")[0].strip() == jsts.node_text(ident)


def _js_kind(arg) -> str | None:
    arg = jsts.unwrap(arg)
    if arg is None:
        return None
    if arg.type in ("identifier", "shorthand_property_identifier"):
        name = jsts.node_text(arg)
        if name in WHOLE:
            return "object"
        if name in ERROR_NAMES and (_catch_has_db(arg) or _error_middleware(arg)):
            return "object"
        return "value" if personal_name(name) else None
    if arg.type in ("call_expression", "new_expression"):
        callee = jsts.callee(arg) if arg.type == "call_expression" else ""
        if callee.startswith(("JSON.stringify", "String")):
            return next((k for k in map(_js_kind, jsts.arguments(arg)) if k), None)
        return None
    if arg.type == "object":
        for key, value in jsts.object_pairs(arg).items():
            if value is not None and value.type != "shorthand_property_identifier":
                if personal_name(key):
                    return "value"
            kind = _js_kind(value)
            if kind:
                return kind
        return None
    if arg.type == "template_string":
        subs = [
            s.named_children[0] for s in arg.named_children if s.type == "template_substitution"
        ]
        return next((k for k in map(_js_kind, subs) if k), None)
    if arg.type == "member_expression":
        text = jsts.node_text(arg)
        parts = [p for p in re.split(r"\?\.|\.", text) if p]
        if parts[-1] in WHOLE_ATTRS or parts[-1] in ("query", "params"):
            return "object"
        return "value" if personal_name(parts[-1], ".".join(parts[:-1])) else None
    return None


def _javascript(ctx: Context, rel: str) -> Iterator[Hit]:
    for tree in jsts.parse_file(ctx.index, rel):
        for call in jsts.calls(tree, LOG_CALL):
            kinds = [_js_kind(a) for a in jsts.arguments(call)]
            if any(kinds):
                yield (
                    jsts.line(tree, call),
                    OBJECT_LOGGED if "object" in kinds else VALUE_LOGGED,
                    False,
                )


def destinations(ctx: Context, rel: str) -> list[str]:
    """Monitoring and error tracking SDKs set up in the same app root as the file."""
    home = root_of(ctx.detection.app_roots, rel)
    prefix = f"{home.path}/" if home is not None and home.path else ""
    return sorted(
        {
            sdk.name
            for sdk in ctx.detection.sdks
            if sdk.category in EXPORTERS
            and any(loc.file.startswith(prefix) for loc in sdk.locations)
        }
    )


def _logged(ctx: Context, rel: str, hits: list[Hit], console: bool) -> Finding:
    lines = sorted({line for line, _, _ in hits})
    what = " ".join(dict.fromkeys(w for _, w, _ in sorted(hits)))
    if len(lines) > 1:
        what = f"{len(lines)} log calls in this file. " + what
    if console:
        what += CONSOLE
    else:
        exported = destinations(ctx, rel)
        if exported:
            what += f" Log records from this app are exported to {', '.join(exported)}."
    return make_finding(
        "LEAK-LOGGED-PII",
        tag=Tag.INFERRED,
        locations=[Location(rel, n) for n in lines[:10]],
        severity="low" if console else None,
        snippet=snippet(ctx.index.text(rel), lines[0]),
        what=what,
    )


def _per_file(ctx: Context, rel: str, hits: list[Hit]) -> Iterator[Finding]:
    """One finding for the log calls in a file, and one for its console-only prints."""
    for console in (False, True):
        group = [h for h in hits if h[2] is console]
        if group:
            yield _logged(ctx, rel, group, console)


def _all_hits(ctx: Context) -> dict[str, list[Hit]]:
    found: dict[str, list[Hit]] = {}
    for entry in ctx.index.js_files:
        if not is_test(entry.rel):
            found[entry.rel] = list(_javascript(ctx, entry.rel))
    for entry in ctx.index.py_files:
        if not is_test(entry.rel) and PurePosixPath(entry.rel).name != "conftest.py":
            found[entry.rel] = list(_python(ctx, entry.rel))
    return {rel: hits for rel, hits in found.items() if hits}


def logged_hits(ctx: Context) -> dict[str, list[Hit]]:
    """Log calls that write personal data, per file. Shared with the inventory review."""
    return fact(ctx, "logged_pii_hits", _all_hits)


def logged_locations(ctx: Context) -> list[Location]:
    return [Location(rel, line) for rel, hits in logged_hits(ctx).items() for line, _, _ in hits]


@rule("LEAK-LOGGED-PII", review="leaks", severity="medium", exploitability="low")
def logged_pii(ctx: Context) -> Iterator[Finding]:
    for rel, hits in logged_hits(ctx).items():
        yield from _per_file(ctx, rel, hits)
