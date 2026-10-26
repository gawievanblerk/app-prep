"""Passwords built with the `random` module by a helper and handed to `set_password`.

A function is a weak generator when what it returns comes from `random.*` (not `secrets` or
`SystemRandom`), directly or through names, `+=`, `.append()` and other weak generators it
calls. A call resolves to a generator by name when every repository function of that name is
one. The sink is `set_password`, `make_password` or a `password=` keyword of `create_user`.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from dpr.model import Location
from dpr.parsing import pyast
from dpr.reviews.app_code import app_py_files, own_nodes
from dpr.rules import Context

PY_RANDOM = re.compile(
    r"(?:random\.)?(?:random|choice|choices|randint|randrange|sample|getrandbits|shuffle|uniform)"
)
SINK = re.compile(r"(?:^|\.)(?:set_password|make_password)$")
USER_CREATE = re.compile(r"(?:^|\.)create_(?:super)?user$")
SEND = re.compile(r"(?i)(?:^|\.)(?:send\w*|\w*_sms\w*|\w*sms_\w*|\w*_email\w*|EmailMessage)$")
MUTATORS = frozenset({"append", "extend", "insert"})


@dataclass(frozen=True)
class WeakUse:
    rel: str
    line: int
    helper: str
    source: Location
    sent: Location | None


def _random_names(tree: ast.Module) -> set[str]:
    """Names imported from random (`from random import choice`) and `random` itself."""
    found = set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == "random":
            found |= {a.asname or a.name for a in node.names if a.name != "SystemRandom"}
        if isinstance(node, ast.Import) and any(a.name == "random" for a in node.names):
            found.add("random")
    return found


def _weak_call(call: ast.Call, randoms: set[str], weak: dict[str, Location]) -> Location | None:
    name = pyast.dotted(call.func) or ""
    root = name.split(".")[0]
    last = name.split(".")[-1]
    if root in randoms and PY_RANDOM.fullmatch(name if root == "random" else last):
        return Location("", call.lineno)
    return weak.get(last)


def _tainted(
    fn: ast.AST, randoms: set[str], weak: dict[str, Location]
) -> tuple[dict, Location | None]:
    """Local names holding weak random output (with where it came from), and the source of
    the returned value when it is weak."""
    names: dict[str, Location] = {}

    def source(expr: ast.AST | None) -> Location | None:
        for sub in ast.walk(expr) if expr is not None else []:
            if isinstance(sub, ast.Name) and sub.id in names:
                return names[sub.id]
            if isinstance(sub, ast.Call):
                found = _weak_call(sub, randoms, weak)
                if found is not None:
                    return found
        return None

    nodes = sorted(
        (n for n in own_nodes(fn) if isinstance(n, ast.stmt | ast.Call)),
        key=lambda n: (n.lineno, n.col_offset),
    )
    for _round in range(2):
        for node in nodes:
            targets: list[ast.AST] = []
            value = None
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, ast.AugAssign | ast.AnnAssign):
                targets, value = [node.target], node.value
            elif isinstance(node, ast.For):
                targets, value = [node.target], node.iter
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in MUTATORS and isinstance(node.func.value, ast.Name):
                    targets, value = [node.func.value], node
            found = source(value)
            for target in targets if found is not None else []:
                if isinstance(target, ast.Name):
                    names.setdefault(target.id, found)
    returned = next(
        (s for n in nodes if isinstance(n, ast.Return) and (s := source(n.value)) is not None),
        None,
    )
    return names, returned


def generators(ctx: Context) -> dict[str, Location]:
    """Function name to the random call its value comes from, for weak generators."""
    if "weak-generators" in ctx.facts:
        return ctx.facts["weak-generators"]
    files = list(app_py_files(ctx, "random"))
    weak: dict[str, Location] = {}
    rejected: set[str] = set()
    for _round in range(4):
        before = dict(weak)
        for rel, _text, tree in files:
            randoms = _random_names(tree)
            for fn in pyast.functions(tree):
                _names, returned = _tainted(fn, randoms, before)
                if returned is not None:
                    weak.setdefault(fn.name, Location(returned.file or rel, returned.line))
        if weak == before:
            break
        needles = tuple(weak)
        files = list(app_py_files(ctx, *needles)) if needles else files
    for _rel, _text, tree in app_py_files(ctx, *weak) if weak else []:
        for fn in pyast.functions(tree):
            if fn.name in weak and _tainted(fn, _random_names(tree), weak)[1] is None:
                rejected.add(fn.name)
    ctx.facts["weak-generators"] = {k: v for k, v in weak.items() if k not in rejected}
    return ctx.facts["weak-generators"]


def _password_arg(call: ast.Call) -> ast.AST | None:
    name = pyast.dotted(call.func) or ""
    if SINK.search(name):
        return call.args[0] if call.args else pyast.kwarg(call, "raw_password")
    if USER_CREATE.search(name):
        return pyast.kwarg(call, "password") or (call.args[2] if len(call.args) > 2 else None)
    return None


def _sent(fn: ast.AST, names: set[str]) -> int | None:
    for node in own_nodes(fn):
        if isinstance(node, ast.Call) and SEND.search(pyast.dotted(node.func) or ""):
            args = [*node.args, *(k.value for k in node.keywords)]
            if any(names & pyast.names_in(a) for a in args):
                return node.lineno
    return None


def _sent_by_callers(ctx: Context, name: str) -> Location | None:
    """Where a caller of `name` sends its returned password in a message."""
    for rel, _text, tree in app_py_files(ctx, name):
        for fn in pyast.functions(tree):
            held = {
                t.id
                for n in own_nodes(fn)
                if isinstance(n, ast.Assign)
                and isinstance(n.value, ast.Call)
                and (pyast.dotted(n.value.func) or "").endswith(name)
                for t in n.targets
                if isinstance(t, ast.Name)
            }
            line = _sent(fn, held) if held else None
            if line is not None:
                return Location(rel, line)
    return None


def weak_password_uses(ctx: Context) -> list[WeakUse]:
    """set_password and similar calls fed by a weak generator, one per call site."""
    weak = generators(ctx)
    found: list[WeakUse] = []
    if not weak:
        return found
    for rel, _text, tree in app_py_files(ctx, "set_password", "make_password", "create_user"):
        for fn in pyast.functions(tree):
            names, returned = _tainted(fn, set(), weak)
            for call in (n for n in own_nodes(fn) if isinstance(n, ast.Call)):
                arg = _password_arg(call)
                if arg is None:
                    continue
                helper = next(
                    (
                        (pyast.dotted(c.func) or "").split(".")[-1]
                        for c in ast.walk(arg)
                        if isinstance(c, ast.Call) and _weak_call(c, set(), weak)
                    ),
                    None,
                )
                used = pyast.names_in(arg) & set(names)
                if helper is None and not used:
                    continue
                if helper is None:
                    helper = _helper_of(fn, used, weak) or "a helper"
                source = weak.get(helper) or next(names[n] for n in used)
                line = _sent(fn, used | set(names))
                sent = Location(rel, line) if line else None
                if sent is None and returned is not None:
                    sent = _sent_by_callers(ctx, fn.name)
                found.append(WeakUse(rel, call.lineno, helper, source, sent))
    return found


def _helper_of(fn: ast.AST, used: set[str], weak: dict[str, Location]) -> str | None:
    for node in own_nodes(fn):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id in used for t in node.targets
        ):
            for call in (c for c in ast.walk(node.value) if isinstance(c, ast.Call)):
                last = (pyast.dotted(call.func) or "").split(".")[-1]
                if last in weak:
                    return last
    return None
