"""FastAPI dependency functions read as gates.

A dependency guards a route when its name is an auth word (`get_current_user`,
`verify_internal_token`) or its body rejects callers (raises 401 or 403, or compares a
header with a secret), unless every definition of it does nothing (`pass`, a docstring, a
bare `return`). An internal-token gate compares a request header with a configured secret;
it fails open when it returns early while that secret is unset.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from dpr.parsing import pyast
from dpr.parsing.routes_py import top_level_defs
from dpr.reviews.access_names import AUTHENTICATED, PY_DEP, dep_level
from dpr.reviews.paths import is_test
from dpr.walk import RepoIndex

DENY = re.compile(r"\b40[13]\b|HTTP_40[13]|Unauthori[sz]ed|Forbidden|PermissionDenied")
SECRET_READ = re.compile(r"\bsettings\.\w+|\bos\.environ\b|\bgetenv\(|\bconfig\.\w+|\benv\(")
USER_WORD = re.compile(r"(?i)user|jwt|decode|session|claims")


@dataclass(frozen=True)
class FailOpen:
    rel: str
    line: int
    name: str
    setting: str


def _defs(index: RepoIndex, name: str) -> list[tuple[str, ast.AST]]:
    return [
        (rel, node)
        for rel, node, _tree in top_level_defs(index).get(name, [])
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and not is_test(rel)
    ]


def _body(fn: ast.AST) -> list[ast.stmt]:
    body = list(fn.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        body = body[1:]
    return body


def hollow(fn: ast.AST) -> bool:
    """The function does nothing: only a docstring, `pass`, `...` or a constant return."""
    for stmt in _body(fn):
        if isinstance(stmt, ast.Pass):
            continue
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            continue
        if isinstance(stmt, ast.Return) and (
            stmt.value is None or isinstance(stmt.value, ast.Constant)
        ):
            continue
        return False
    return True


def _header_params(fn: ast.AST) -> set[str]:
    args = fn.args
    params = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    defaults = [None] * (len(args.posonlyargs) + len(args.args) - len(args.defaults))
    defaults += [*args.defaults, *args.kw_defaults]
    found = set()
    for param, default in zip(params, defaults, strict=True):
        text = " ".join(ast.unparse(n) for n in (param.annotation, default) if n is not None)
        if re.search(r"\b(?:Header|APIKeyHeader|Security)\(", text):
            found.add(param.arg)
    return found


def _compares_secret(fn: ast.AST) -> bool:
    text = ast.unparse(fn)
    if "compare_digest(" in text:
        return True
    return any(
        isinstance(node, ast.Compare) and SECRET_READ.search(ast.unparse(node))
        for node in ast.walk(fn)
    )


def rejects(fn: ast.AST) -> bool:
    """The body turns callers away: a 401 or 403, or a header compared with a secret."""
    if hollow(fn):
        return False
    raises = any(
        isinstance(node, ast.Raise) and DENY.search(ast.unparse(node)) for node in ast.walk(fn)
    )
    return raises or (bool(_header_params(fn)) and _compares_secret(fn))


def dep_names(node: ast.AST | None, aliases: dict[str, str]) -> list[str]:
    """Dependency names in `Depends(x)` / `Security(x)` calls and `Annotated` aliases."""
    names = []
    for sub in ast.walk(node) if node is not None else []:
        if isinstance(sub, ast.Call) and PY_DEP.fullmatch(pyast.dotted(sub.func) or ""):
            if sub.args:
                names.append((pyast.dotted(sub.args[0]) or "").split(".")[-1])
        elif isinstance(sub, ast.Name) and sub.id in aliases:
            names.append(aliases[sub.id])
    return [n for n in names if n]


def kwarg_deps(call: ast.Call, tree: ast.Module | None, aliases: dict[str, str]) -> list[str]:
    """Names in a call's `dependencies=`, read through a module-level list it names."""
    node = pyast.kwarg(call, "dependencies")
    if isinstance(node, ast.Name) and tree is not None:
        node = pyast.assignments(tree.body).get(node.id, node)
    return dep_names(node, aliases)


def gate_levels(index: RepoIndex):
    """`gate_level` for this index, each name read once per run."""
    memo = index.cache.setdefault(("fastapi-gate-levels", ""), {})

    def level(name: str) -> str | None:
        if name not in memo:
            memo[name] = gate_level(index, name)
        return memo[name]

    return level


def gate_level(index: RepoIndex, name: str) -> str | None:
    """The access a dependency named `name` gives, or None when it guards nothing."""
    defs = _defs(index, name)
    if defs and all(hollow(fn) for _rel, fn in defs):
        return None
    level = dep_level(name)
    if level:
        return level
    return AUTHENTICATED if any(rejects(fn) for _rel, fn in defs) else None


def internal_gate(index: RepoIndex, name: str) -> bool:
    """A service-to-service gate: a request header compared with a configured secret, with
    no user lookup."""
    for _rel, fn in _defs(index, name):
        headers = _header_params(fn)
        if headers and _compares_secret(fn) and not USER_WORD.search(" ".join(headers)):
            if not re.search(r"(?i)get_current_user|\bdecode\(|jwt\.", ast.unparse(fn)):
                return True
    return False


def _setting(node: ast.AST, secrets: dict[str, str]) -> str | None:
    """The configured secret a test reads, as an environment-style name."""
    if isinstance(node, ast.Name) and node.id in secrets:
        return secrets[node.id]
    text = ast.unparse(node)
    if not SECRET_READ.search(text):
        return None
    constant = next(
        (
            n.value
            for n in ast.walk(node)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)
        ),
        None,
    )
    if constant:
        return constant
    return (pyast.dotted(node) or text).split(".")[-1].upper()


def _unset_test(test: ast.AST, secrets: dict[str, str]) -> str | None:
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return _setting(test.operand, secrets)
    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        other = test.comparators[0]
        empty = isinstance(other, ast.Constant) and other.value in (None, "")
        if empty and isinstance(test.ops[0], ast.Is | ast.Eq):
            return _setting(test.left, secrets)
    return None


def fail_open(index: RepoIndex, name: str) -> FailOpen | None:
    """The early return of an internal-token gate that runs when its secret is unset."""
    if not internal_gate(index, name):
        return None
    for rel, fn in _defs(index, name):
        secrets: dict[str, str] = {}
        for stmt in _body(fn):
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                target = stmt.targets[0]
                setting = _setting(stmt.value, {})
                if isinstance(target, ast.Name) and setting:
                    secrets[target.id] = setting
            elif isinstance(stmt, ast.If):
                setting = _unset_test(stmt.test, secrets)
                if setting and stmt.body and hollow_block(stmt.body):
                    return FailOpen(rel, fn.lineno, name, setting)
                if any(isinstance(n, ast.Raise) for n in ast.walk(stmt)):
                    break
            elif isinstance(stmt, ast.Raise | ast.Return):
                break
    return None


def hollow_block(body: list[ast.stmt]) -> bool:
    """A block that only returns without a value (or with None or True)."""
    return all(
        isinstance(s, ast.Pass)
        or isinstance(s, ast.Return)
        and (s.value is None or isinstance(s.value, ast.Constant) and s.value.value in (None, True))
        for s in body
    ) and any(isinstance(s, ast.Return) for s in body)
