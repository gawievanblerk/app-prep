"""Review 6, leak hunt: git history and over-broad responses."""

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
from dpr.redact import has_token_phrase, is_public_value, is_secret_name, public_prefix, snippet
from dpr.reviews.personal import personal_fields
from dpr.rules import Context, make_finding, rule
from dpr.walk import SourceFile

ENV_NAME = re.compile(r"^\.env(\..+)?$")
ENV_EXAMPLE = re.compile(r"\.(example|sample|template)$")
TEST_ENV = re.compile(r"^\.env\.(?:test|testing)(?:\.local)?$")
TEST_ENV_DETAIL = (
    "Commit {commit} added {path}. It is no longer tracked, but every clone still has it in "
    "history. Its name marks it as a test environment file, which usually holds local test "
    "values; confirm no real credential was in it."
)
TEST_ENV_FIX = (
    "Check the values that were in {path}. Rotate any that worked against a real service; "
    "local test values need no action."
)
ORM_READ = re.compile(
    r"(?:prisma|db|tx)\.(\w+)\.(findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow|findMany)"
)
SUPABASE_ALL = re.compile(r"\.select\(\s*(?:['\"`]\*['\"`])?\s*\)")
SUPABASE_TABLE = re.compile(r"\.from\(\s*['\"`](\w+)['\"`]\s*\)")
SELECT_STAR = re.compile(r"select\s+\*", re.IGNORECASE)
RESPONSE_CALLS = re.compile(
    r"(?:^|\.)(?:JsonResponse|JSONResponse|Response|HttpResponse|StreamingHttpResponse|jsonify"
    r"|make_response|ORJSONResponse|UJSONResponse)$"
)
JS_ROUTE_FRAMEWORKS = ("next-app", "next-pages", "next-action", "express", "fastify")
PY_ROUTE_FRAMEWORKS = ("django", "drf", "fastapi", "flask")
PUBLIC_ENV_DETAIL = (
    "Nothing secret is tracked here: every name is public-prefixed, or its value is public by "
    "design, such as a publishable key; frameworks such as Next.js commit these on purpose."
)
PUBLIC_ENV_FIX = (
    "Keep {path} for public values only. Put any secret in an untracked file such as "
    ".env.local and list that file in .gitignore."
)
PUBLIC_ENV_BLAST = "Values that already ship to the browser."
UNREADABLE_ENV_DETAIL = (
    "This file's contents could not be checked (empty, unreadable, or not NAME=value "
    "lines), so it is treated as critical until it is reviewed by hand."
)


def _is_real_env(path: str) -> bool:
    name = PurePosixPath(path).name
    return bool(ENV_NAME.match(name)) and not ENV_EXAMPLE.search(name)


def _env_pairs(ctx: Context, path: str) -> list[tuple[str, str]] | None:
    """Parsed NAME and value pairs, or None when the file's contents could not be checked.
    A value is only ever tested here; no value leaves this module."""
    full = ctx.index.root / path
    if full.is_symlink() or not full.is_file():
        return None
    entry = next((e for e in ctx.index.env_files if e.rel == path), None)
    try:
        pairs = [(n, v) for n, v, _ in ctx.index.env_pairs(entry or SourceFile(path, full, 0))]
    except OSError:
        return None
    return pairs or None


def _public_name(name: str) -> bool:
    return public_prefix(name) is not None and not is_secret_name(name)


def _only_public_values(pairs: list[tuple[str, str]]) -> bool:
    """True when nothing in the file is a secret: every variable is either public-prefixed and
    not secret-like, holds a value that is public by design, or repeats a value the file already
    exports to the browser under a public-prefixed name."""
    exported = {value for name, value in pairs if value and _public_name(name)}
    return all(
        _public_name(name) or (bool(value) and (is_public_value(value) or value in exported))
        for name, value in pairs
    )


@rule("LEAK-ENV-TRACKED", review="leaks", severity="critical", exploitability="high")
def env_tracked(ctx: Context) -> Iterator[Finding]:
    tracked = tracked_files(ctx.index.root, notes=ctx.not_covered)
    if tracked is None:
        ctx.not_covered.append("git checks skipped: not a git repository or git is unavailable")
        return
    for path in tracked:
        if not _is_real_env(path):
            continue
        pairs = _env_pairs(ctx, path)
        public = pairs is not None and _only_public_values(pairs)
        detail = PUBLIC_ENV_DETAIL if public else None
        if detail is None and pairs is None:
            detail = UNREADABLE_ENV_DETAIL
        yield make_finding(
            "LEAK-ENV-TRACKED",
            tag=Tag.CONFIRMED,
            locations=[Location(path, 1)],
            severity="low" if public else None,
            detail=detail,
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
        notes=ctx.not_covered,
    )
    if output is None:
        return
    prefix = (run_git(root, "rev-parse", "--show-prefix") or "").strip()
    tracked_names = tracked_files(root, notes=ctx.not_covered)
    if tracked_names is None:
        return
    tracked = set(tracked_names)
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
        test = bool(TEST_ENV.match(PurePosixPath(path).name))
        yield make_finding(
            "LEAK-ENV-IN-HISTORY",
            tag=Tag.CONFIRMED,
            locations=[Location(path, 1)],
            severity="low" if test else None,
            detail=TEST_ENV_DETAIL.format(commit=sha, path=path) if test else None,
            fix=TEST_ENV_FIX.format(path=path) if test else None,
            path=path,
            commit=sha,
        )


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def _severity(ctx: Context, name: str | None) -> str:
    model = find_model(ctx.detection.models, name) if name else None
    words = load("pii_terms.yaml")["sensitive_columns"]
    for field in model.fields if model else []:
        if any(has_token_phrase(_snake(field.name), word) for word in words):
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


def _without_personal_data(ctx: Context, name: str | None) -> bool:
    """The serializer's model is read and the classifier finds no personal field on it, such
    as a lookup table. An unknown model (Django's User, a model the parser cannot read) is
    still reported."""
    model = find_model(ctx.detection.models, name) if name else None
    if model is None:
        return False
    return not any(p.model is model for p in personal_fields(ctx))


def _selects(value: ast.AST) -> bool:
    """A comprehension with a condition, also wrapped in dict() or list()."""
    if isinstance(value, ast.Call) and len(value.args) == 1:
        value = value.args[0]
    comprehensions = ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp
    return isinstance(value, comprehensions) and any(g.ifs for g in value.generators)


def sent(handler: ast.AST, node: ast.AST) -> bool:
    """`node` is part of the handler's HTTP response: returned by it, passed to a response call,
    or assigned to a name that is. A value kept for a diff, a log or a template is not, and
    neither is a filtered comprehension over it, which picks some keys only."""
    names: set[str] = set()
    for stmt in ast.walk(handler):
        if isinstance(stmt, ast.Assign) and any(n is node for n in ast.walk(stmt.value)):
            names |= {t.id for t in stmt.targets if isinstance(t, ast.Name)}
    changed = True
    while changed:
        changed = False
        for stmt in ast.walk(handler):
            if isinstance(stmt, ast.Assign) and _selects(stmt.value):
                continue
            if isinstance(stmt, ast.Assign) and pyast.names_in(stmt.value) & names:
                targets = {t.id for t in stmt.targets if isinstance(t, ast.Name)}
                changed = changed or not targets <= names
                names |= targets

    def carries(value: ast.AST) -> bool:
        return any(n is node for n in ast.walk(value)) or bool(pyast.names_in(value) & names)

    for item in ast.walk(handler):
        if isinstance(item, ast.Call) and RESPONSE_CALLS.search(pyast.dotted(item.func) or ""):
            if any(carries(a) for a in [*item.args, *(k.value for k in item.keywords)]):
                return True
        if isinstance(item, ast.Return) and item.value is not None:
            value = item.value
            # A returned render(...) or helper call sends a page, not the dump itself.
            if value is node or (not isinstance(value, ast.Call) and carries(value)):
                return True
    return False


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
                if _without_personal_data(ctx, model):
                    continue
                yield _broad(ctx, entry.rel, values["fields"].lineno, "Django", model)
    for route in ctx.detection.routes:
        if route.framework not in PY_ROUTE_FRAMEWORKS or route.handler is None:
            continue
        if not isinstance(route.handler, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for node in ast.walk(route.handler):
            dumps_all = isinstance(node, ast.Call) and pyast.dotted(node.func) in (
                "model_to_dict",
                "vars",
            )
            whole = dumps_all or (isinstance(node, ast.Attribute) and node.attr == "__dict__")
            if whole and sent(route.handler, node):
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
