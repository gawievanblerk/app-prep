"""JS/TS SQL text that is fixed in the source: literals, constants, placeholders and helpers.

`OWASP-A03-RAW-SQL` skips a `$queryRawUnsafe(sql, ...args)` call when every part of `sql` is
literal text. A part is fixed when it is a literal, an UPPER_CASE constant, a ternary between
fixed values, a number, a name only ever assigned fixed values, the parameter of a local helper
whose callers in the file all pass fixed values, or a call to a same-file or imported helper
whose returned text is fixed once its parameters take the call's arguments.
"""

from __future__ import annotations

import re

from dpr.parsing import imports, jsts, pyast
from dpr.reviews.sql_constants import CONSTANT_NAME

MAX_DEPTH = 10
LITERALS = {"string", "number", "true", "false", "null", "undefined", "regex"}
# Operators whose result is a number or a boolean, whatever the operands hold.
NUMERIC_OPS = {"-", "*", "/", "%", "**", "<<", ">>", ">>>", "&", "|", "^"}
COMPARE_OPS = {"==", "===", "!=", "!==", "<", ">", "<=", ">=", "in", "instanceof"}
NUMBER_CALLS = re.compile(r"^(?:Number|parseInt|parseFloat|Math\.\w+|Boolean)$")
PLACEHOLDER = re.compile(r"\$\d+|\$\$\{|[=(,]\s*\?(?!\?)")


def _key(fn) -> tuple:
    return (fn.start_byte, fn.end_byte, fn.type)


def params_of(fn) -> list[tuple[str, object, bool]]:
    """(name, default value, is rest) for each simple parameter of a function."""
    single = fn.child_by_field_name("parameter")
    if single is not None:
        return [(jsts.node_text(single), None, False)]
    formal = fn.child_by_field_name("parameters")
    found = []
    for param in formal.named_children if formal is not None else []:
        if param.type in ("required_parameter", "optional_parameter"):
            pattern, default = (
                param.child_by_field_name("pattern"),
                param.child_by_field_name("value"),
            )
        elif param.type == "assignment_pattern":
            pattern, default = param.child_by_field_name("left"), param.child_by_field_name("right")
        else:
            pattern, default = param, None
        rest = pattern is not None and pattern.type == "rest_pattern"
        if rest:
            pattern = pattern.named_children[0] if pattern.named_children else None
        found.append((jsts.node_text(pattern) if pattern is not None else "", default, rest))
    return found


def _function_name(fn) -> str | None:
    if fn.type in jsts.NAMED_FUNCTIONS:
        return jsts.node_text(fn.child_by_field_name("name"))
    parent = fn.parent
    if parent is not None and parent.type == "variable_declarator":
        return jsts.node_text(parent.child_by_field_name("name"))
    return None


def _returns(fn) -> list:
    body = fn.child_by_field_name("body")
    if body is None:
        return []
    if body.type != "statement_block":
        return [body]
    found = []
    for node in jsts.walk(body, {"return_statement"}):
        if _key(jsts.enclosing_function(node)) == _key(fn):
            value = node.named_children[0] if node.named_children else None
            found.append(value)
    return found


def _local_callers(fn) -> list:
    """Calls of a named, unexported function in the scope that declares it, or [] when the name
    is also used as a value (passed on, exported) so other callers may exist."""
    name = _function_name(fn)
    holder = fn if fn.type in jsts.NAMED_FUNCTIONS else fn.parent
    if name is None or holder is None:
        return []
    outer = [holder.parent, holder.parent.parent if holder.parent is not None else None]
    if any(n is not None and n.type == "export_statement" for n in outer):
        return []
    home = jsts.enclosing_function(holder) or _root(holder)
    callers = []
    for ident in jsts.walk(home, {"identifier", "shorthand_property_identifier"}):
        if jsts.node_text(ident) != name or ident.parent is None:
            continue
        parent = ident.parent
        if parent.type == "call_expression" and parent.child_by_field_name("function") == ident:
            callers.append(parent)
        elif not (parent == holder or parent.child_by_field_name("name") == ident):
            return []
    return callers


def _root(node):
    while node.parent is not None:
        node = node.parent
    return node


def assigned(scope, name: str) -> list | None:
    """Every value given to `name` in the scope, or None when it is not declared there.

    A destructured name maps to a synthetic ("member", call, key) tuple."""
    values: list = []
    declared = False
    for decl in jsts.walk(scope, {"variable_declarator"}):
        if _key(jsts.enclosing_function(decl) or _root(decl)) != _key(scope):
            continue
        target, value = decl.child_by_field_name("name"), decl.child_by_field_name("value")
        if target.type == "identifier" and jsts.node_text(target) == name:
            declared = True
            if value is not None:
                values.append(value)
        elif target.type == "object_pattern":
            for part in target.named_children:
                if part.type == "pair_pattern":
                    key = jsts.node_text(part.child_by_field_name("key"))
                    local = jsts.node_text(part.child_by_field_name("value"))
                elif part.type == "shorthand_property_identifier_pattern":
                    key = local = jsts.node_text(part)
                else:
                    continue
                if local == name:
                    declared = True
                    values.append(("member", value, key))
    for node in jsts.walk(scope, {"assignment_expression", "augmented_assignment_expression"}):
        if jsts.node_text(node.child_by_field_name("left")) == name:
            values.append(node.child_by_field_name("right"))
    if not declared:
        return None
    return values


class FixedSql:
    """Decides whether a JS expression can only produce literal SQL text."""

    def __init__(self, index, rel: str) -> None:
        self.index = index
        self.rel = rel
        # Parameters bound while a helper is being evaluated: (rel, fn key) -> {name: fixed}.
        self.bound: dict[tuple, dict[str, bool]] = {}

    def fixed(self, node, rel: str | None = None, depth: int = 0) -> bool:
        rel = rel or self.rel
        node = jsts.unwrap(node)
        if node is None or depth > MAX_DEPTH:
            return False
        kind = node.type
        if kind in LITERALS:
            return True
        if kind == "template_string":
            subs = [c for c in node.named_children if c.type == "template_substitution"]
            return all(self.fixed(s.named_children[0], rel, depth + 1) for s in subs)
        if kind == "binary_expression":
            op = jsts.node_text(node.child_by_field_name("operator"))
            if op in NUMERIC_OPS or op in COMPARE_OPS:
                return True
            return all(
                self.fixed(node.child_by_field_name(side), rel, depth + 1)
                for side in ("left", "right")
            )
        if kind == "ternary_expression":
            return all(
                self.fixed(node.child_by_field_name(side), rel, depth + 1)
                for side in ("consequence", "alternative")
            )
        if kind == "unary_expression":
            return True
        if kind == "array":
            return all(self.fixed(c, rel, depth + 1) for c in node.named_children)
        if kind in ("identifier", "shorthand_property_identifier"):
            return self._name(node, rel, depth)
        if kind == "member_expression":
            return self._member(node, rel, depth)
        if kind == "call_expression":
            return self._call(node, rel, depth)
        return False

    def _name(self, node, rel: str, depth: int) -> bool:
        name = jsts.node_text(node)
        if CONSTANT_NAME.match(name):
            return True
        scope = jsts.enclosing_function(node)
        values = None
        while values is None:
            if scope is not None:
                names = [p[0] for p in params_of(scope)]
                if name in names:
                    return self._param(scope, names.index(name), rel, depth)
            values = assigned(scope if scope is not None else _root(node), name)
            if scope is None:
                break
            scope = jsts.enclosing_function(scope)
        return bool(values) and all(
            self._key_of(v[1], v[2], rel, depth + 1)
            if isinstance(v, tuple)
            else self.fixed(v, rel, depth + 1)
            for v in values
        )

    def _param(self, fn, position: int, rel: str, depth: int) -> bool:
        name, default, rest = params_of(fn)[position]
        env = self.bound.get((rel, _key(fn)))
        if env is not None:
            return env.get(name, False)
        parent = fn.parent
        if parent is not None and parent.type == "arguments" and not rest:
            call = parent.parent
            member = call.child_by_field_name("function")
            if member is not None and member.type == "member_expression":
                method = jsts.node_text(member.child_by_field_name("property"))
                if method in ("map", "forEach", "flatMap", "filter") and position == 1:
                    return True
                if method in ("map", "forEach", "flatMap", "filter") and position == 0:
                    return self.fixed(member.child_by_field_name("object"), rel, depth + 1)
        callers = _local_callers(fn)
        if rest or not callers:
            return False
        for call in callers:
            args = jsts.arguments(call)
            arg = args[position] if position < len(args) else default
            if arg is None or not self.fixed(arg, rel, depth + 1):
                return False
        return True

    def _member(self, node, rel: str, depth: int) -> bool:
        prop = jsts.node_text(node.child_by_field_name("property"))
        if CONSTANT_NAME.match(prop) or prop == "length":
            return True
        obj = jsts.unwrap(node.child_by_field_name("object"))
        if obj is None or obj.type != "identifier":
            return False
        scope = jsts.enclosing_function(node)
        values = assigned(scope if scope is not None else _root(node), jsts.node_text(obj))
        return bool(values) and all(
            not isinstance(v, tuple) and self._key_of(v, prop, rel, depth + 1) for v in values
        )

    def _key_of(self, value, key: str, rel: str, depth: int) -> bool:
        """The `key` property of an object literal, or of what a helper call returns."""
        value = jsts.unwrap(value)
        if value is None or depth > MAX_DEPTH:
            return False
        if value.type == "object":
            pairs = jsts.object_pairs(value)
            if key not in pairs:
                return True  # missing key reads as undefined
            return self.fixed(pairs[key], rel, depth + 1)
        if value.type == "call_expression":
            return self._helper(value, rel, depth, lambda r, fr, d: self._key_of(r, key, fr, d))
        return False

    def _call(self, node, rel: str, depth: int) -> bool:
        func = jsts.unwrap(node.child_by_field_name("function"))
        args = jsts.arguments(node)
        name = jsts.node_text(func)
        if NUMBER_CALLS.match(name):
            return True
        if name == "String":
            return all(self.fixed(a, rel, depth + 1) for a in args)
        if func is not None and func.type == "member_expression":
            method = jsts.node_text(func.child_by_field_name("property"))
            receiver = func.child_by_field_name("object")
            if method == "join":
                return self.fixed(receiver, rel, depth + 1) and all(
                    self.fixed(a, rel, depth + 1) for a in args
                )
            if method in ("map", "flatMap") and args:
                callback = jsts.unwrap(args[0])
                if callback is not None and callback.type in jsts.FUNCTION_TYPES:
                    return all(self.fixed(r, rel, depth + 1) for r in _returns(callback) or [None])
            if method in ("toFixed", "toString") and not args:
                return self.fixed(receiver, rel, depth + 1)
            return False
        return self._helper(node, rel, depth, self.fixed)

    def _resolve(self, func, rel: str):
        """The function a callee names, in this file or through a relative import."""
        name = jsts.node_text(func)
        if func.type != "identifier":
            return None, rel
        local = jsts.resolve_identifier(func)
        if local is not None and local.type in jsts.FUNCTION_TYPES:
            return local, rel
        found = jsts.declared_value(_root(func), name)
        if found is not None and found.type in jsts.FUNCTION_TYPES:
            return found, rel
        target, exported, _spec = imports.js_imports(self.index, rel).get(name, (None, "", ""))
        if target is None or exported in ("*", "default"):
            return None, rel
        for tree in jsts.parse_file(self.index, target):
            found = jsts.declared_value(tree.root, exported)
            if found is not None and found.type in jsts.FUNCTION_TYPES:
                return found, target
        return None, rel

    def _helper(self, call, rel: str, depth: int, check) -> bool:
        fn, fn_rel = self._resolve(jsts.unwrap(call.child_by_field_name("function")), rel)
        if fn is None:
            return False
        args = jsts.arguments(call)
        env = {}
        for position, (name, default, rest) in enumerate(params_of(fn)):
            if rest:
                env[name] = all(self.fixed(a, rel, depth + 1) for a in args[position:])
                continue
            arg = args[position] if position < len(args) else None
            if arg is not None:
                env[name] = self.fixed(arg, rel, depth + 1)
            else:
                env[name] = default is None or self.fixed(default, fn_rel, depth + 1)
        key = (fn_rel, _key(fn))
        if key in self.bound:
            return False  # recursion
        self.bound[key] = env
        try:
            returns = _returns(fn)
            return bool(returns) and all(check(r, fn_rel, depth + 1) for r in returns)
        finally:
            del self.bound[key]


def has_placeholder(node) -> bool:
    """Bind placeholders ($1, ?) in the SQL text, or in the values a name is given."""
    node = jsts.unwrap(node)
    if node is None:
        return False
    texts = [jsts.node_text(node)]
    if node.type == "identifier":
        scope = jsts.enclosing_function(node) or _root(node)
        for value in assigned(scope, jsts.node_text(node)) or []:
            texts.append(jsts.node_text(value if not isinstance(value, tuple) else value[1]))
    return any(PLACEHOLDER.search(t) for t in texts)


SCRIPT_PATH = re.compile(r"(?:^|/)scripts?/")


def unrouted_scripts(index) -> set[str]:
    """Files under a scripts/ folder that no file outside such folders imports: CLI tools run by
    hand, which no route reaches."""
    key = ("unrouted-scripts",)
    if key in index.cache:
        return index.cache[key]
    scripts = {e.rel for e in [*index.js_files, *index.py_files] if SCRIPT_PATH.search(e.rel)}
    imported = set()
    if scripts:
        for entry in index.js_files:
            if not SCRIPT_PATH.search(entry.rel):
                imported |= {t[0] for t in imports.js_imports(index, entry.rel).values()}
        for entry in index.py_files:
            if not SCRIPT_PATH.search(entry.rel):
                tree = pyast.parse_file(index, entry.rel)
                imported |= {t[0] for t in imports.py_imports(index, entry.rel, tree).values()}
    index.cache[key] = scripts - imported
    return index.cache[key]
