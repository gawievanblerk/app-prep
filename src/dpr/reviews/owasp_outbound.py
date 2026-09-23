"""Review 5, OWASP A02 and A05: how the app calls other services.

`OWASP-A02-PLAIN-HTTP-CALL`: an outbound call, or a URL setting, to a literal `http://`
address outside the local network. `OWASP-A05-NO-TIMEOUT`: `requests` calls with no
`timeout=`, one finding per file. `OWASP-A05-HARDCODED-VENDOR-URL`: a live vendor address
written as a default that no environment variable can change. Query-string credentials in
dicts (`params=`, `urlencode`) are reported by `OWASP-A02-SECRET-IN-URL`.
"""

from __future__ import annotations

import ast
import ipaddress
import re
from collections.abc import Iterator
from urllib.parse import urlsplit

from dpr.model import Finding, Location, Tag
from dpr.parsing import pyast
from dpr.parsing.pyenv import env_read, module_assignments, reads_env
from dpr.redact import snippet
from dpr.reviews.app_code import app_file, app_py_files, local_values, own_calls
from dpr.reviews.request_values import PERSONAL_KEY
from dpr.reviews.settings_files import production_file, secret_name, settings_module
from dpr.rules import Context, make_finding, rule

HTTP_CALL = re.compile(
    r"(?:requests|httpx)\.(?:get|post|put|patch|delete|head|options|request)"
    r"|(?:urllib\.request\.)?urlopen"
)
NO_TIMEOUT_CALL = re.compile(
    r"requests\.(?:api\.)?(?:get|post|put|patch|delete|head|options|request)|(?:urllib\.request\.)?urlopen"
)
CLIENT_CALL = re.compile(
    rf"(?:{HTTP_CALL.pattern})|(?:[\w.]*\.)?(?:session|client|Session\(\)|http)\.(?:get|post|put|patch"
    r"|delete|request|send)|(?:[\w.]*\.)?Client"
)
URL_NAME = re.compile(r"(?:^|_)(?:URL|URI|ENDPOINT|HOST|BASE|API|SERVER|GATEWAY)(?:_|$)")
INTERNAL_SUFFIX = (
    ".local", ".internal", ".localhost", ".svc", ".test", ".example", ".invalid", ".lan",
    "example.com", "example.org", "example.net",
)  # fmt: skip
LIVE = re.compile(r"(?i)(?:^|_)(?:LIVE|PROD|PRODUCTION)(?:_|$)")
NOT_LIVE = re.compile(r"(?i)test|staging|stage|sandbox|uat|(?:^|[._-])dev|(?:^|[._-])qa(?:$|[._-])")
JS_PLAIN = re.compile(r"""(?:fetch|axios(?:\.\w+)?|got|ky)\(\s*[`'"](http://[^`'"\s]+)""")


def public_host(url: str) -> str | None:
    """The host of an http(s) URL outside the local network, or None."""
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return None
    if not host or "." not in host or host.endswith(INTERNAL_SUFFIX):
        return None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host
    return None if (address.is_private or address.is_loopback or address.is_link_local) else host


def _head(node: ast.AST | None) -> ast.AST | None:
    """The part of a URL expression that holds its scheme and host."""
    if isinstance(node, ast.JoinedStr) and node.values:
        return node.values[0]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
        return _head(node.left)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "format":
            return node.func.value
    return node


def _literal(node: ast.AST | None, scopes: list[dict], depth: int = 0) -> str | None:
    """The literal a URL expression starts with, following names, class attributes and
    environment defaults."""
    node = _head(node)
    if depth > 4 or node is None:
        return None
    value = pyast.constant(node, None)
    if isinstance(value, str):
        return value
    read = env_read(node)
    if read is not None:
        return _literal(read.default, scopes, depth + 1)
    name = node.id if isinstance(node, ast.Name) else None
    if isinstance(node, ast.Attribute) and pyast.dotted(node.value) in ("self", "cls", "settings"):
        name = node.attr
    for scope in scopes if name else []:
        if name in scope:
            return _literal(scope[name], scopes, depth + 1)
    return None


def _settings_values(ctx: Context) -> dict[str, ast.expr]:
    key = ("settings-values", "")
    if key not in ctx.index.cache:
        found: dict[str, ast.expr] = {}
        for entry in ctx.index.py_files:
            text = ctx.index.text(entry.rel)
            if not settings_module(entry.rel, text) or not production_file(ctx, entry.rel):
                continue
            tree = pyast.parse_file(ctx.index, entry.rel)
            for name, value, _line in module_assignments(tree) if tree else []:
                found.setdefault(name, value)
        ctx.index.cache[key] = found
    return ctx.index.cache[key]


def _class_scopes(tree: ast.Module) -> dict[int, dict[str, ast.expr]]:
    """Class-level assignments, keyed by the id of each method of the class."""
    scopes = {}
    for cls in pyast.class_defs(tree):
        values = pyast.assignments(cls.body)
        for item in cls.body:
            if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef):
                scopes[id(item)] = values
    return scopes


def _url_arg(call: ast.Call) -> ast.AST | None:
    name = pyast.dotted(call.func) or ""
    position = 1 if name.endswith(".request") else 0
    if len(call.args) > position:
        return call.args[position]
    return pyast.kwarg(call, "url")


def _dict_keys(node: ast.AST | None, values: dict, line: int) -> list[str]:
    """Literal keys of a dict argument, following a local name assigned a dict."""
    if isinstance(node, ast.Name):
        earlier = [v for at, v in values.get(node.id, []) if at < line]
        node = earlier[-1] if earlier else None
    if isinstance(node, ast.Call) and pyast.dotted(node.func) == "dict":
        return [k.arg for k in node.keywords if k.arg]
    if isinstance(node, ast.Dict):
        return [k.value for k in node.keys if isinstance(pyast.constant(k, None), str)]
    return []


def _sensitive_keys(keys: list[str]) -> list[str]:
    return [
        k for k in keys if secret_name(k) or k.lower() in ("pass", "pwd") or PERSONAL_KEY.search(k)
    ]


def _plain_sites(ctx: Context) -> Iterator[tuple[str, int, str, list[str]]]:
    settings = _settings_values(ctx)
    for rel, text, tree in app_py_files(ctx, "http://"):
        module = pyast.assignments(tree.body)
        classes = _class_scopes(tree)
        for fn in pyast.functions(tree):
            values = local_values(fn)
            local = {k: v[-1][1] for k, v in values.items()}
            scopes = [local, classes.get(id(fn), {}), module, settings]
            for call in own_calls(fn, HTTP_CALL):
                url = _literal(_url_arg(call), scopes) or ""
                host = public_host(url) if url.startswith("http://") else None
                if host:
                    keys = [
                        k
                        for kw in call.keywords
                        if kw.arg in ("params", "data", "json", "auth", "headers")
                        for k in _dict_keys(kw.value, values, call.lineno)
                    ]
                    creds = _sensitive_keys(keys) + (["auth"] if pyast.kwarg(call, "auth") else [])
                    yield rel, call.lineno, host, creds
        if settings_module(rel, text) and production_file(ctx, rel):
            for name, value, line in module_assignments(tree):
                url = _literal(value, [module]) or ""
                if URL_NAME.search(name) and url.startswith("http://") and public_host(url):
                    yield rel, line, public_host(url) or "", []
    for entry in ctx.index.js_files:
        text = ctx.index.text(entry.rel)
        if "http://" not in text or not app_file(ctx, entry.rel):
            continue
        for match in JS_PLAIN.finditer(text):
            host = public_host(match.group(1))
            if host:
                yield entry.rel, text.count("\n", 0, match.start()) + 1, host, []


@rule(
    "OWASP-A02-PLAIN-HTTP-CALL",
    review="owasp",
    severity="medium",
    exploitability="low",
    owasp="A02",
)
def plain_http_call(ctx: Context) -> Iterator[Finding]:
    by_file: dict[str, list[tuple[int, str, list[str]]]] = {}
    for rel, line, host, creds in _plain_sites(ctx):
        if all(line != seen for seen, _, _ in by_file.get(rel, [])):
            by_file.setdefault(rel, []).append((line, host, creds))
    for rel, sites in by_file.items():
        sites.sort(key=lambda s: (not s[2], s[0]))
        creds = list(dict.fromkeys(k for _, _, keys in sites for k in keys))
        carried = f" The request carries {', '.join(creds)} in the clear." if creds else ""
        yield make_finding(
            "OWASP-A02-PLAIN-HTTP-CALL",
            tag=Tag.CONFIRMED,
            locations=[Location(rel, line) for line, _, _ in sites],
            snippet=snippet(ctx.index.text(rel), sites[0][0]),
            severity="high" if creds else None,
            exploitability="medium" if creds else None,
            hosts=", ".join(dict.fromkeys(host for _, host, _ in sites)),
            carried=carried,
        )


def query_credentials(ctx: Context) -> Iterator[tuple[str, int, str]]:
    """Secret-named keys of a dict sent as a query string: `params=` of an HTTP call, or the
    argument of `urlencode`."""
    for rel, _text, tree in app_py_files(ctx, "params", "urlencode"):
        for fn in pyast.functions(tree):
            values = local_values(fn)
            for call in own_calls(fn):
                name = pyast.dotted(call.func) or ""
                if name.endswith("urlencode") and call.args:
                    node = call.args[0]
                elif HTTP_CALL.fullmatch(name):
                    node = pyast.kwarg(call, "params")
                else:
                    continue
                keys = _dict_keys(node, values, call.lineno)
                secret = [k for k in keys if secret_name(k) or k.lower() in ("pass", "pwd")]
                if secret:
                    yield rel, call.lineno, secret[0]


@rule("OWASP-A05-NO-TIMEOUT", review="owasp", severity="low", exploitability="low", owasp="A05")
def no_timeout(ctx: Context) -> Iterator[Finding]:
    for rel, text, tree in app_py_files(ctx, "requests.", "urlopen"):
        lines = []
        for call in pyast.calls(tree, NO_TIMEOUT_CALL):
            if any(k.arg == "timeout" or k.arg is None for k in call.keywords):
                continue
            if (pyast.dotted(call.func) or "").endswith("urlopen") and len(call.args) >= 3:
                continue
            lines.append(call.lineno)
        if lines:
            yield make_finding(
                "OWASP-A05-NO-TIMEOUT",
                tag=Tag.CONFIRMED,
                locations=[Location(rel, line) for line in lines],
                snippet=snippet(text, lines[0]),
                count=len(lines),
            )


def _named_in_code(ctx: Context) -> set[str]:
    """Every string literal that names an environment variable read in the application."""
    key = ("env-read-names", "")
    if key not in ctx.index.cache:
        names = set()
        for _rel, _text, tree in app_py_files(ctx, "environ", "getenv", "env(", "config("):
            for node in ast.walk(tree):
                read = env_read(node) if isinstance(node, ast.Call) else None
                if read is not None:
                    names.add(read.name)
        ctx.index.cache[key] = names
    return ctx.index.cache[key]


def _vendor_constants(scope: dict[str, ast.expr]) -> Iterator[tuple[str, str, str]]:
    """(name, url, the constant it came from) for URL constants holding a literal address."""
    for name, value in scope.items():
        if not URL_NAME.search(name.upper()) or reads_env(value):
            continue
        source = value.id if isinstance(value, ast.Name) else name
        literal = _literal(value, [scope])
        if literal and literal.startswith(("http://", "https://")) and public_host(literal):
            yield name, literal, source


def _live_defaults(scope: dict[str, ast.expr], env_driven: bool, env_names: set[str]) -> list[str]:
    constants = list(_vendor_constants(scope))
    alternatives = any(NOT_LIVE.search(n) or NOT_LIVE.search(u) for n, u, _ in constants)
    found = []
    for name, url, source in constants:
        if name in env_names or NOT_LIVE.search(name) or NOT_LIVE.search(url):
            continue
        if any(s == name and n != name for n, _, s in constants):
            continue  # the alias that selects it is reported instead
        if LIVE.search(name) or LIVE.search(source) or alternatives or env_driven:
            found.append(name)
    return found


def _client_functions(ctx: Context) -> list[str]:
    """Source of every application function that makes an HTTP call, and of every class with
    such a method (a client that keeps its base address in `self`)."""
    key = ("client-functions", "")
    if key not in ctx.index.cache:
        found = []
        for _rel, _text, tree in app_py_files(ctx, "requests", "httpx", "urlopen", "Client("):
            calling = [
                fn
                for fn in pyast.functions(tree)
                if any(CLIENT_CALL.fullmatch(pyast.dotted(c.func) or "") for c in own_calls(fn))
            ]
            found += [ast.unparse(fn) for fn in calling]
            found += [
                ast.unparse(cls)
                for cls in pyast.class_defs(tree)
                if any(fn in cls.body for fn in calling)
            ]
        ctx.index.cache[key] = found
    return ctx.index.cache[key]


def _used_by_client(ctx: Context, name: str) -> bool:
    """A function that makes an HTTP call reads the constant."""
    word = re.compile(rf"\b{re.escape(name)}\b")
    return any(word.search(source) for source in _client_functions(ctx))


@rule(
    "OWASP-A05-HARDCODED-VENDOR-URL",
    review="owasp",
    severity="low",
    exploitability="low",
    owasp="A05",
)
def hardcoded_vendor_url(ctx: Context) -> Iterator[Finding]:
    env_names = _named_in_code(ctx)
    for rel, text, tree in app_py_files(ctx, "http"):
        if not production_file(ctx, rel):
            continue
        module = dict(pyast.assignments(tree.body))
        env_driven = settings_module(rel, text) and any(reads_env(v) for v in module.values())
        scopes = [(module, env_driven)] + [
            (pyast.assignments(cls.body), False) for cls in pyast.class_defs(tree)
        ]
        names = [n for scope, driven in scopes for n in _live_defaults(scope, driven, env_names)]
        used = [n for n in dict.fromkeys(names) if _used_by_client(ctx, n)]
        lines = [
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id in used for t in node.targets)
        ]
        if lines:
            yield make_finding(
                "OWASP-A05-HARDCODED-VENDOR-URL",
                tag=Tag.INFERRED,
                locations=[Location(rel, line) for line in sorted(set(lines))],
                snippet=snippet(text, min(lines)),
                names=", ".join(dict.fromkeys(used)),
            )
