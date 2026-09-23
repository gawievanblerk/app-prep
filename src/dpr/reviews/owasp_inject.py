"""Review 5, OWASP A03: raw SQL, XSS sinks, command execution and HTML built into emails."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Tag
from dpr.parsing import jsts, pyast
from dpr.redact import snippet
from dpr.reviews.paths import is_test
from dpr.reviews.sql_constants import js_constant, py_constant
from dpr.rules import Context, make_finding, rule
from dpr.vendored import is_vendored
from dpr.walk import line_of

REQUEST_VALUE = re.compile(
    r"\breq\.(?:body|query|params)|\brequest\.(?:GET|POST|args|form|json|data|query_params|body)"
    r"|searchParams\.get\(|\bparams\.\w+"
)
JS_SQL = re.compile(
    r"(?:\w+\.)?(?:\$queryRawUnsafe|\$executeRawUnsafe)|\w+\.(?:query|execute|raw|unsafe)"
)
PY_SQL = re.compile(
    r"(?:[\w.()]+\.)?(?:execute|executemany|executescript|raw)|text|(?:sqlalchemy|sa)\.text"
)
MIGRATIONS = re.compile(r"(?:^|/)(?:alembic|migrations)/")
JS_COMMAND = re.compile(r"(?:child_process\.|cp\.)?(exec|execSync)$|^eval$")
PY_COMMAND = re.compile(r"(?:os\.system|os\.popen|eval|exec)$")
PY_SUBPROCESS = re.compile(r"subprocess\.(?:run|call|check_call|check_output|Popen)$")
HTML_TAG = re.compile(r"<(?:p|div|h[1-6]|a|td|tr|table|span|strong|em|li|ul|br|body|html)\b", re.I)
MAIL_CONTEXT = re.compile(r"(?i)e?mail|notif|smtp|sendgrid|postmark|resend")
ESCAPES = re.compile(r"(?:^|\.)(?:escape|quote|bleach\.clean|clean)$")


def _dynamic_string(node) -> bool:
    node = jsts.unwrap(node)
    if node is None:
        return False
    if node.type == "template_string":
        return any(c.type == "template_substitution" for c in node.named_children)
    if node.type == "binary_expression":
        return "+" in jsts.node_text(node) and any(
            c.type in ("identifier", "member_expression", "call_expression")
            for c in node.named_children
        )
    return node.type in ("identifier", "member_expression", "call_expression")


def _py_dynamic(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
        return True
    return isinstance(node, ast.Call) and (pyast.dotted(node.func) or "").endswith(".format")


def _js_parts(node) -> list:
    """The runtime parts of a JS string: template substitutions and non-literal operands."""
    node = jsts.unwrap(node)
    if node is None or node.type == "string":
        return []
    if node.type == "template_string":
        return [c for c in node.named_children if c.type == "template_substitution"]
    if node.type == "binary_expression":
        return [p for child in node.named_children for p in _js_parts(child)]
    return [node]


def _js_bound(fn, name: str) -> list[str]:
    """Values assigned to `name` in the function, including destructuring declarations."""
    values = []
    for decl in jsts.walk(fn, {"variable_declarator"}) if fn is not None else []:
        target = decl.child_by_field_name("name")
        bound = {
            jsts.node_text(n)
            for n in jsts.walk(target, {"identifier", "shorthand_property_identifier_pattern"})
        }
        if name in bound:
            values.append(jsts.node_text(decl.child_by_field_name("value")))
    return values


def _js_from_request(call, first) -> bool:
    """A request value, or a name assigned from one, is inside the SQL string's parts."""
    fn = jsts.enclosing_function(call)
    parts = _js_parts(first)
    if first is not None and first.type == "identifier":
        resolved = jsts.resolve_identifier(first)
        parts = _js_parts(resolved) if resolved is not None else parts
    for part in parts:
        text = jsts.node_text(part)
        if REQUEST_VALUE.search(text):
            return True
        for ident in jsts.walk(part, {"identifier"}):
            if any(REQUEST_VALUE.search(v) for v in _js_bound(fn, jsts.node_text(ident))):
                return True
    return False


def _py_parts(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, ast.JoinedStr):
        return [v.value for v in node.values if isinstance(v, ast.FormattedValue)]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return [*_py_parts(node.left), *_py_parts(node.right)]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return [node.right]
    if isinstance(node, ast.Call) and (pyast.dotted(node.func) or "").endswith(".format"):
        return [*node.args, *(k.value for k in node.keywords)]
    return [] if isinstance(node, ast.Constant) else [node]


def _py_from_request(fn: ast.AST | None, first: ast.AST) -> bool:
    assigned: dict[str, list[str]] = {}
    for node in ast.walk(fn) if fn is not None else []:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                for name in pyast.names_in(target):
                    assigned.setdefault(name, []).append(ast.unparse(node.value))
    for part in _py_parts(first):
        if REQUEST_VALUE.search(ast.unparse(part)):
            return True
        for name in pyast.names_in(part):
            if any(REQUEST_VALUE.search(value) for value in assigned.get(name, [])):
                return True
    return False


def _sql(ctx: Context, rel: str, line: int, from_request: bool, what: str) -> Finding:
    return make_finding(
        "OWASP-A03-RAW-SQL",
        tag=Tag.CONFIRMED if from_request else Tag.INFERRED,
        locations=[Location(rel, line)],
        snippet=snippet(ctx.index.text(rel), line),
        what=what,
    )


@rule("OWASP-A03-RAW-SQL", review="owasp", severity="high", exploitability="high", owasp="A03")
def raw_sql(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.js_files:
        if is_test(entry.rel) or is_vendored(ctx.index, entry.rel):
            continue
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for call in jsts.calls(tree, JS_SQL):
                args = jsts.arguments(call)
                name = jsts.callee(call)
                first = jsts.unwrap(args[0]) if args else None
                unsafe = "Unsafe" in name and first is not None and jsts.string_value(first) is None
                built = (
                    first is not None
                    and first.type in ("template_string", "binary_expression")
                    and _dynamic_string(first)
                )
                if not (unsafe or built):
                    continue
                if built and all(js_constant(p) for p in _js_parts(first)):
                    continue
                what = f"{name} receives SQL built from values at runtime."
                from_request = _js_from_request(call, first)
                yield _sql(ctx, entry.rel, jsts.line(tree, call), from_request, what)
    for entry in ctx.index.py_files:
        if is_test(entry.rel) or MIGRATIONS.search(entry.rel) or is_vendored(ctx.index, entry.rel):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for call in pyast.calls(tree, PY_SQL) if tree else []:
            if not call.args or not _py_dynamic(call.args[0]):
                continue
            fn = pyast.function_at(tree, call.lineno)
            module = pyast.assignments(tree.body)
            if all(py_constant(p, fn, module) for p in _py_parts(call.args[0])):
                continue
            name = pyast.dotted(call.func) or "execute"
            what = f"{name} receives SQL built with string formatting."
            from_request = _py_from_request(fn, call.args[0])
            yield _sql(ctx, entry.rel, call.lineno, from_request, what)


def _xss(ctx: Context, rel: str, line: int, sink: str) -> Finding:
    return make_finding(
        "OWASP-A03-XSS-SINK",
        tag=Tag.INFERRED,
        locations=[Location(rel, line)],
        snippet=snippet(ctx.index.text(rel), line),
        sink=sink,
    )


@rule("OWASP-A03-XSS-SINK", review="owasp", severity="high", exploitability="medium", owasp="A03")
def xss_sink(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.js_files:
        if is_test(entry.rel) or is_vendored(ctx.index, entry.rel):
            continue
        text = ctx.index.text(entry.rel)
        for match in re.finditer(
            r"dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*([^}]+)\}\}", text
        ):
            value = match.group(1).strip()
            if not re.fullmatch(r"""(['"`])[^'"`$]*\1""", value):
                yield _xss(ctx, entry.rel, line_of(text, match.start()), "dangerouslySetInnerHTML")
        for match in re.finditer(r"\bv-html\s*=|\{@html\s", text):
            yield _xss(ctx, entry.rel, line_of(text, match.start()), match.group(0).strip(" ={"))
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for node in jsts.walk(tree.root, {"assignment_expression"}):
                left = jsts.node_text(node.child_by_field_name("left"))
                right = node.child_by_field_name("right")
                if left.endswith((".innerHTML", ".outerHTML")) and _dynamic_string(right):
                    yield _xss(ctx, entry.rel, jsts.line(tree, node), "innerHTML")
    for entry in ctx.index.py_files:
        if is_test(entry.rel) or is_vendored(ctx.index, entry.rel):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for call in pyast.calls(tree, r"(?:\w+\.)*(mark_safe|Markup)") if tree else []:
            if call.args and not isinstance(call.args[0], ast.Constant):
                yield _xss(ctx, entry.rel, call.lineno, pyast.dotted(call.func))


@rule("OWASP-A03-COMMAND", review="owasp", severity="high", exploitability="high", owasp="A03")
def command(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.js_files:
        if is_test(entry.rel) or is_vendored(ctx.index, entry.rel):
            continue
        for tree in jsts.parse_file(ctx.index, entry.rel):
            for call in jsts.calls(tree, JS_COMMAND):
                args = jsts.arguments(call)
                if args and _dynamic_string(args[0]):
                    line = jsts.line(tree, call)
                    yield make_finding(
                        "OWASP-A03-COMMAND",
                        tag=Tag.INFERRED,
                        locations=[Location(entry.rel, line)],
                        snippet=snippet(ctx.index.text(entry.rel), line),
                        call=jsts.callee(call),
                    )
            for node in jsts.walk(tree.root, {"new_expression"}):
                if jsts.node_text(node.child_by_field_name("constructor")) == "Function":
                    line = jsts.line(tree, node)
                    yield make_finding(
                        "OWASP-A03-COMMAND",
                        tag=Tag.INFERRED,
                        locations=[Location(entry.rel, line)],
                        snippet=snippet(ctx.index.text(entry.rel), line),
                        call="new Function",
                    )
    for entry in ctx.index.py_files:
        if is_test(entry.rel) or is_vendored(ctx.index, entry.rel):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for call in pyast.calls(tree, r"[\w.]+") if tree else []:
            name = pyast.dotted(call.func) or ""
            if not call.args or isinstance(call.args[0], ast.Constant | ast.List):
                continue
            shell = pyast.constant(pyast.kwarg(call, "shell")) is True
            if PY_COMMAND.fullmatch(name) or (PY_SUBPROCESS.fullmatch(name) and shell):
                yield make_finding(
                    "OWASP-A03-COMMAND",
                    tag=Tag.INFERRED,
                    locations=[Location(entry.rel, call.lineno)],
                    snippet=snippet(ctx.index.text(entry.rel), call.lineno),
                    call=name,
                )


TRUSTED = re.compile(r"(?i)settings|config")
MARKUP_NAME = re.compile(r"(?i)^(?:content|body|html|template|rows|\w+_html|html_\w+|\w+_rows)$")


def _safe_value(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) or (isinstance(node, ast.Name) and node.id.isupper()):
        return True
    if isinstance(node, ast.Call) and ESCAPES.search(pyast.dotted(node.func) or ""):
        return True
    return isinstance(node, ast.Attribute) and bool(TRUSTED.search(ast.unparse(node)))


def _constant_loop_names(fn: ast.AST) -> set[str]:
    """Loop targets that take constant values from a literal list of tuples."""
    literals = {
        node.targets[0].id: node.value
        for node in ast.walk(fn)
        if isinstance(node, ast.Assign)
        and isinstance(node.targets[0], ast.Name)
        and isinstance(node.value, ast.List | ast.Tuple)
    }
    names = set()
    for node in ast.walk(fn):
        if not isinstance(node, ast.comprehension | ast.For) or not isinstance(
            node.target, ast.Tuple
        ):
            continue
        rows = literals.get(node.iter.id) if isinstance(node.iter, ast.Name) else None
        if rows is None or not all(isinstance(r, ast.Tuple) for r in rows.elts):
            continue
        for position, target in enumerate(node.target.elts):
            if isinstance(target, ast.Name) and all(
                len(r.elts) > position and isinstance(r.elts[position], ast.Constant)
                for r in rows.elts
            ):
                names.add(target.id)
    return names


NUMERIC = re.compile(r"^(?:int|float|bool|Decimal|date|datetime|UUID)(?:\s*\|\s*None)?$")


def _markup_safe(node: ast.AST, escaped: set[str]) -> bool:
    """Constants, escaped values, and strings built only from them, including joined loops."""
    if _safe_value(node) or (isinstance(node, ast.Name) and node.id in escaped):
        return True
    if isinstance(node, ast.JoinedStr):
        values = [v.value for v in node.values if isinstance(v, ast.FormattedValue)]
        return all(_markup_safe(v, escaped) for v in values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _markup_safe(node.left, escaped) and _markup_safe(node.right, escaped)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "join" and len(node.args) == 1:
            arg = node.args[0]
            if isinstance(arg, ast.GeneratorExp | ast.ListComp):
                return _markup_safe(arg.elt, escaped)
            return _markup_safe(arg, escaped)
    return False


def _escaped_names(fn: ast.AST) -> set[str]:
    names = {a.arg for a in fn.args.args if MARKUP_NAME.match(a.arg)} | _constant_loop_names(fn)
    names |= {
        a.arg
        for a in [*fn.args.args, *fn.args.kwonlyargs]
        if a.annotation is not None and NUMERIC.match(ast.unparse(a.annotation))
    }
    assigns = [
        n for n in ast.walk(fn) if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
    ]
    for _ in range(2):
        for node in assigns:
            if _markup_safe(node.value, names) or MARKUP_NAME.match(node.targets[0].id):
                names.add(node.targets[0].id)
    return names


def _unescaped(fn: ast.AST) -> list[ast.JoinedStr]:
    escaped = _escaped_names(fn)
    found = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.JoinedStr):
            continue
        literal = "".join(v.value for v in node.values if isinstance(v, ast.Constant))
        if not HTML_TAG.search(literal):
            continue
        for value in node.values:
            if isinstance(value, ast.FormattedValue) and not _markup_safe(value.value, escaped):
                found.append(node)
                break
    return found


@rule("OWASP-A03-HTML-EMAIL", review="owasp", severity="low", exploitability="low", owasp="A03")
def html_email(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel) or not MAIL_CONTEXT.search(entry.rel) or "<" not in text:
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        lines = (
            sorted({n.lineno for fn in pyast.functions(tree) for n in _unescaped(fn)})
            if tree
            else []
        )
        if lines:
            yield make_finding(
                "OWASP-A03-HTML-EMAIL",
                tag=Tag.INFERRED,
                locations=[Location(entry.rel, n) for n in lines[:5]],
                snippet=snippet(text, lines[0]),
                count=len(lines),
            )
