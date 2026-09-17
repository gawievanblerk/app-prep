"""Review 6, leak hunt: git history, over-broad responses and personal data in logs."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from pathlib import PurePosixPath

from dpr.data import load
from dpr.gitutil import run_git, tracked_files
from dpr.model import Finding, Location, Tag
from dpr.parsing import jsts, pyast
from dpr.parsing.routes_js import response_calls
from dpr.parsing.schemas import find_model
from dpr.redact import is_secret_name, public_prefix, snippet
from dpr.rules import Context, make_finding, rule
from dpr.walk import SourceFile

ENV_NAME = re.compile(r"^\.env(\..+)?$")
ENV_EXAMPLE = re.compile(r"\.(example|sample|template)$")
ORM_READ = re.compile(
    r"(?:prisma|db|tx)\.(\w+)\.(findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow|findMany)"
)
SUPABASE_ALL = re.compile(r"\.select\(\s*(?:['\"`]\*['\"`])?\s*\)")
SUPABASE_TABLE = re.compile(r"\.from\(\s*['\"`](\w+)['\"`]\s*\)")
SELECT_STAR = re.compile(r"select\s+\*", re.IGNORECASE)
JS_ROUTE_FRAMEWORKS = ("next-app", "next-pages", "next-action", "express", "fastify")
PY_ROUTE_FRAMEWORKS = ("django", "drf", "fastapi", "flask")
LOG_CALL = re.compile(
    r"console\.(?:log|error|warn|info|debug)|(?:logger|log)\.(?:info|error|warn|debug|log|fatal)"
)
PY_LOG_CALL = re.compile(
    r"print|logging\.(?:debug|info|warning|error|exception|critical)"
    r"|(?:logger|log|LOGGER)\.(?:debug|info|warning|error|exception|critical)"
)
SENSITIVE_ROOTS = frozenset(
    {"req", "request", "body", "user", "token", "payload", "headers", "session", "password"}
)
ERROR_NAMES = frozenset({"err", "error", "e", "exc"})
OBJECT_LOGGED = "A request, user, token or database error object is written to the log."
TRACEBACK_LOGGED = "A full traceback, with local values in the message, is printed to the log."
JS_DB = re.compile(r"prisma\.|supabase\.|\bdb\.|\.query\(|\.execute\(|knex|sequelize|mongoose")
PY_DB = re.compile(r"\.objects\.|session\.|cursor\.|\.execute\(|\.query\(")
PUBLIC_ENV_DETAIL = (
    "Only public-prefixed, non-secret names are tracked; "
    "frameworks such as Next.js commit these on purpose."
)
PUBLIC_ENV_FIX = (
    "Keep {path} for public values only. Put any secret in an untracked file such as "
    ".env.local and list that file in .gitignore."
)
PUBLIC_ENV_BLAST = "Values that already ship to the browser."


def _is_real_env(path: str) -> bool:
    name = PurePosixPath(path).name
    return bool(ENV_NAME.match(name)) and not ENV_EXAMPLE.search(name)


def _only_public_names(ctx: Context, path: str) -> bool:
    """True when every variable name in the file is public-prefixed and not secret-like.

    Names only; values are never read. A file that cannot be read counts as not public.
    """
    full = ctx.index.root / path
    if full.is_symlink() or not full.is_file():
        return False
    entry = next((e for e in ctx.index.env_files if e.rel == path), None)
    try:
        names = [name for name, _ in ctx.index.env_names(entry or SourceFile(path, full, 0))]
    except OSError:
        return False
    return not any(public_prefix(n) is None or is_secret_name(n) for n in names)


@rule("LEAK-ENV-TRACKED", review="leaks", severity="critical", exploitability="high")
def env_tracked(ctx: Context) -> Iterator[Finding]:
    tracked = tracked_files(ctx.index.root)
    if tracked is None:
        ctx.not_covered.append("git checks skipped: not a git repository or git is unavailable")
        return
    for path in tracked:
        if not _is_real_env(path):
            continue
        public = _only_public_names(ctx, path)
        yield make_finding(
            "LEAK-ENV-TRACKED",
            tag=Tag.CONFIRMED,
            locations=[Location(path, 1)],
            severity="low" if public else None,
            detail=PUBLIC_ENV_DETAIL if public else None,
            fix=PUBLIC_ENV_FIX.format(path=path) if public else None,
            blast=PUBLIC_ENV_BLAST if public else None,
            path=path,
        )


@rule("LEAK-ENV-IN-HISTORY", review="leaks", severity="high", exploitability="medium")
def env_in_history(ctx: Context) -> Iterator[Finding]:
    root = ctx.index.root
    output = run_git(
        root,
        "log",
        "--all",
        "--diff-filter=A",
        "--name-only",
        "--format=commit %h",
        "--",
        ":(glob)**/.env",
        ":(glob)**/.env.*",
    )
    if output is None:
        return
    prefix = (run_git(root, "rev-parse", "--show-prefix") or "").strip()
    tracked = set(tracked_files(root) or [])
    first_seen: dict[str, str] = {}
    commit = ""
    for line in output.splitlines():
        if line.startswith("commit "):
            commit = line.split(" ", 1)[1].strip()
            continue
        path = line.strip()
        if not path.startswith(prefix):
            continue
        path = path[len(prefix) :]
        if path and _is_real_env(path) and path not in tracked:
            first_seen.setdefault(path, commit)
    for path, sha in first_seen.items():
        yield make_finding(
            "LEAK-ENV-IN-HISTORY",
            tag=Tag.CONFIRMED,
            locations=[Location(path, 1)],
            path=path,
            commit=sha,
        )


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def _severity(ctx: Context, name: str | None) -> str:
    model = find_model(ctx.detection.models, name) if name else None
    words = load("pii_terms.yaml")["sensitive_columns"]
    if model and any(word in _snake(f.name) for f in model.fields for word in words):
        return "high"
    return "medium"


def _destructured(ident) -> object | None:
    name = jsts.node_text(ident)
    scope = jsts.enclosing_function(ident)
    if scope is None:
        return None
    for decl in jsts.walk(scope, {"variable_declarator"}):
        pattern = decl.child_by_field_name("name")
        if pattern is None or pattern.type != "object_pattern":
            continue
        if decl.start_byte > ident.start_byte:
            continue
        shorthand = jsts.walk(pattern, {"shorthand_property_identifier_pattern"})
        names = {jsts.node_text(n) for n in shorthand}
        for pair in jsts.walk(pattern, {"pair_pattern"}):
            names.add(jsts.node_text(pair.child_by_field_name("value")))
        if name in names:
            return jsts.unwrap(decl.child_by_field_name("value"))
    return None


def _record_source(node) -> tuple[str | None, str | None]:
    node = jsts.unwrap(node)
    if node is not None and node.type in ("identifier", "shorthand_property_identifier"):
        node = jsts.resolve_identifier(node) or _destructured(node)
    if node is None:
        return None, None
    if node.type == "call_expression":
        match = ORM_READ.fullmatch(jsts.callee(node))
        if match:
            args = jsts.arguments(node)
            if args and "select" in jsts.object_pairs(args[0]):
                return None, None
            return "Prisma", match.group(1)
    text = jsts.node_text(node)
    if SUPABASE_ALL.search(text):
        table = SUPABASE_TABLE.search(text)
        return "Supabase", table.group(1) if table else None
    if SELECT_STAR.search(text):
        return "SQL", None
    return None, None


def _broad(
    ctx: Context,
    rel: str,
    line: int,
    source: str,
    name: str | None,
    rule_id: str = "LEAK-BROAD-RESPONSE",
) -> Finding:
    what = (
        f"This response sends every field of the {name or 'queried'} record, "
        "not only the ones the client needs."
    )
    return make_finding(
        rule_id,
        tag=Tag.INFERRED,
        locations=[Location(rel, line)],
        severity=_severity(ctx, name),
        snippet=snippet(ctx.index.text(rel), line),
        source=source,
        what=what,
    )


def _js_responses(ctx: Context) -> Iterator[Finding]:
    for route in ctx.detection.routes:
        handler = route.handler
        if route.framework not in JS_ROUTE_FRAMEWORKS or handler is None:
            continue
        if handler.type not in jsts.FUNCTION_TYPES:
            continue
        candidates = [jsts.arguments(c)[0] for c in response_calls(handler) if jsts.arguments(c)]
        if route.framework == "next-action":
            candidates += [
                r.named_children[0]
                for r in jsts.walk(handler, {"return_statement"})
                if r.named_children
            ]
        for node in candidates:
            source, name = _record_source(node)
            if source:
                yield _broad(ctx, route.file, jsts.line(route.tree, node), source, name)


def _py_responses(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.py_files:
        if "ModelSerializer" not in ctx.index.text(entry.rel):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for cls in pyast.class_defs(tree) if tree else []:
            if not any(b.endswith("ModelSerializer") for b in pyast.base_names(cls)):
                continue
            metas = [n for n in cls.body if isinstance(n, ast.ClassDef) and n.name == "Meta"]
            meta = metas[0] if metas else None
            values = pyast.assignments(meta.body) if meta else {}
            if pyast.constant(values.get("fields")) == "__all__":
                model = (pyast.dotted(values.get("model")) or "").split(".")[-1] or None
                yield _broad(ctx, entry.rel, values["fields"].lineno, "Django", model)
    for route in ctx.detection.routes:
        if route.framework not in PY_ROUTE_FRAMEWORKS or route.handler is None:
            continue
        for node in ast.walk(route.handler):
            dumps_all = isinstance(node, ast.Call) and pyast.dotted(node.func) in (
                "model_to_dict",
                "vars",
            )
            whole = dumps_all or (isinstance(node, ast.Attribute) and node.attr == "__dict__")
            if whole:
                yield _broad(ctx, route.file, node.lineno, "Django", None)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                if SELECT_STAR.search(node.value):
                    yield _broad(ctx, route.file, node.lineno, "SQL", None)


@rule("LEAK-BROAD-RESPONSE", review="leaks", severity="medium", exploitability="medium")
def broad_response(ctx: Context) -> Iterator[Finding]:
    yield from _js_responses(ctx)
    yield from _py_responses(ctx)


@rule("LEAK-SSR-PROPS", review="leaks", severity="medium", exploitability="medium")
def ssr_props(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.js_files:
        text = ctx.index.text(entry.rel)
        if not re.search(r"getServerSideProps|getStaticProps|\bloader\b", text):
            continue
        for tree in jsts.parse_file(ctx.index, entry.rel):
            exported = jsts.exported_functions(tree)
            for name in ("getServerSideProps", "getStaticProps", "loader"):
                fn = exported.get(name)
                for ret in jsts.walk(fn, {"return_statement"}) if fn is not None else []:
                    value = jsts.unwrap(ret.named_children[0]) if ret.named_children else None
                    if value is None:
                        continue
                    if value.type == "call_expression" and jsts.callee(value) == "json":
                        values = jsts.arguments(value)[:1]
                    elif value.type == "object":
                        props = jsts.object_pairs(value).get("props")
                        values = list(jsts.object_pairs(props).values()) if props else []
                    else:
                        values = [value]
                    for item in values:
                        source, model = _record_source(item)
                        if source:
                            yield _broad(
                                ctx,
                                entry.rel,
                                jsts.line(tree, ret),
                                source,
                                model,
                                rule_id="LEAK-SSR-PROPS",
                            )


def _catch_has_db(ident) -> bool:
    name = jsts.node_text(ident)
    node = ident.parent
    while node is not None:
        if node.type == "catch_clause":
            param = node.child_by_field_name("parameter")
            if param is not None and jsts.node_text(param) == name:
                body = node.parent.child_by_field_name("body") if node.parent else None
                return body is not None and bool(JS_DB.search(jsts.node_text(body)))
        node = node.parent
    return False


def _js_sensitive(arg) -> bool:
    arg = jsts.unwrap(arg)
    if arg is None:
        return False
    if arg.type == "shorthand_property_identifier":
        return jsts.node_text(arg) in SENSITIVE_ROOTS
    if arg.type in ("call_expression", "new_expression"):
        return any(_js_sensitive(a) for a in jsts.arguments(arg))
    if arg.type == "object":
        return any(_js_sensitive(v) for v in jsts.object_pairs(arg).values())
    if arg.type == "template_string":
        return any(
            _js_sensitive(s.named_children[0])
            for s in arg.named_children
            if s.type == "template_substitution" and s.named_children
        )
    root = jsts.member_root(arg)
    if root in SENSITIVE_ROOTS:
        return True
    if root in ERROR_NAMES:
        base = arg
        while base.type in ("member_expression", "subscript_expression"):
            base = jsts.unwrap(base.child_by_field_name("object"))
        return _catch_has_db(base)
    return False


def _except_handlers(ctx: Context, rel: str, tree: ast.Module) -> list[tuple[str, int, int, bool]]:
    """(error name, first line, last line, try body touches the database) per except handler."""
    key = ("py-except", rel)
    if key not in ctx.index.cache:
        found = []
        for block in ast.walk(tree):
            if not isinstance(block, ast.Try):
                continue
            named = [h for h in block.handlers if h.name in ERROR_NAMES]
            if not named:
                continue
            db = bool(PY_DB.search("\n".join(ast.unparse(s) for s in block.body)))
            found += [(h.name, h.lineno, h.end_lineno or h.lineno, db) for h in named]
        ctx.index.cache[key] = found
    return ctx.index.cache[key]


def _py_sensitive(node: ast.AST, handlers: list[tuple[str, int, int, bool]], line: int) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(
            _py_sensitive(v.value, handlers, line)
            for v in node.values
            if isinstance(v, ast.FormattedValue)
        )
    if isinstance(node, ast.Call) and pyast.dotted(node.func) in ("json.dumps", "str", "repr"):
        return any(_py_sensitive(a, handlers, line) for a in node.args)
    root = pyast.name_root(node)
    if root in SENSITIVE_ROOTS:
        return True
    if root in ERROR_NAMES:
        for name, first, last, db in handlers:
            if name == root and first <= line <= last:
                return db
    return False


def _logged(ctx: Context, rel: str, line: int, what: str) -> Finding:
    ctx.facts.setdefault("logged_pii", []).append(Location(rel, line))
    return make_finding(
        "LEAK-LOGGED-PII",
        tag=Tag.INFERRED,
        locations=[Location(rel, line)],
        snippet=snippet(ctx.index.text(rel), line),
        what=what,
    )


@rule("LEAK-LOGGED-PII", review="leaks", severity="medium", exploitability="low")
def logged_pii(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.js_files:
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for call in jsts.calls(tree, LOG_CALL):
                if any(_js_sensitive(a) for a in jsts.arguments(call)):
                    yield _logged(ctx, entry.rel, jsts.line(tree, call), OBJECT_LOGGED)
    for entry in ctx.index.py_files:
        tree = pyast.parse_file(ctx.index, entry.rel)
        if tree is None:
            continue
        for call in pyast.calls(tree, PY_LOG_CALL):
            handlers = _except_handlers(ctx, entry.rel, tree)
            if any(_py_sensitive(a, handlers, call.lineno) for a in call.args):
                yield _logged(ctx, entry.rel, call.lineno, OBJECT_LOGGED)
        for call in pyast.calls(tree, r"traceback\.print_exc"):
            yield _logged(ctx, entry.rel, call.lineno, TRACEBACK_LOGGED)
