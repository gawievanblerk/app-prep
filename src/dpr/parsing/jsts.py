"""tree-sitter parsing for JavaScript and TypeScript, plus small node helpers."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from functools import cache

import tree_sitter_javascript
import tree_sitter_typescript
from tree_sitter import Language, Node, Parser

from dpr.walk import RepoIndex

FUNCTION_TYPES = frozenset({
    "function_declaration", "generator_function_declaration", "function_expression",
    "function", "arrow_function", "method_definition",
})
WRAPPERS = frozenset({
    "await_expression", "parenthesized_expression", "as_expression", "non_null_expression",
    "satisfies_expression", "type_assertion",
})
SCRIPT_BLOCK = re.compile(r"<script\b([^>]*)>(.*?)</script>", re.DOTALL | re.IGNORECASE)


@dataclass(frozen=True)
class JsTree:
    rel: str
    root: Node
    source: bytes
    line_offset: int
    tree: object


@cache
def _parser(grammar: str) -> Parser:
    if grammar == "javascript":
        return Parser(Language(tree_sitter_javascript.language()))
    if grammar == "typescript":
        return Parser(Language(tree_sitter_typescript.language_typescript()))
    if grammar == "tsx":
        return Parser(Language(tree_sitter_typescript.language_tsx()))
    raise ValueError(f"unknown grammar {grammar}")


def grammar_for(rel: str) -> str:
    lower = rel.lower()
    if lower.endswith((".ts", ".mts", ".cts")):
        return "typescript"
    if lower.endswith(".tsx"):
        return "tsx"
    return "javascript"


def script_blocks(text: str) -> list[tuple[str, int, str]]:
    blocks = []
    for match in SCRIPT_BLOCK.finditer(text):
        is_ts = re.search(r"lang\s*=\s*['\"]ts['\"]", match.group(1))
        offset = text.count("\n", 0, match.start(2))
        blocks.append((match.group(2), offset, "typescript" if is_ts else "javascript"))
    return blocks


def parse_source(rel: str, code: str, grammar: str | None = None,
                 line_offset: int = 0) -> JsTree:
    source = code.encode("utf-8")
    parsed = _parser(grammar or grammar_for(rel)).parse(source)
    return JsTree(rel, parsed.root_node, source, line_offset, parsed)


def parse_file(index: RepoIndex, rel: str) -> list[JsTree]:
    key = ("js", rel)
    if key not in index.cache:
        text = index.text(rel)
        if rel.lower().endswith((".vue", ".svelte")):
            trees = [parse_source(rel, c, g, o) for c, o, g in script_blocks(text)]
        else:
            trees = [parse_source(rel, text)]
        index.cache[key] = trees
    return index.cache[key]


def node_text(node: Node | None) -> str:
    if node is None or node.text is None:
        return ""
    return node.text.decode("utf-8", errors="replace")


def line(tree: JsTree, node: Node) -> int:
    return node.start_point.row + 1 + tree.line_offset


def walk(node: Node, types: frozenset[str] | set[str] | None = None
         ) -> Iterator[Node]:
    stack = [node]
    while stack:
        current = stack.pop()
        if types is None or current.type in types:
            yield current
        stack.extend(reversed(current.children))


def callee(call: Node) -> str:
    return re.sub(r"\s+", "", node_text(call.child_by_field_name("function")))


def calls(tree: JsTree, pattern: str | re.Pattern[str],
          within: Node | None = None) -> Iterator[Node]:
    regex = re.compile(pattern) if isinstance(pattern, str) else pattern
    for node in walk(within or tree.root, {"call_expression"}):
        if regex.fullmatch(callee(node)):
            yield node


def arguments(call: Node) -> list[Node]:
    args = call.child_by_field_name("arguments")
    if args is None:
        return []
    return [child for child in args.named_children if child.type != "comment"]


def unwrap(node: Node | None) -> Node | None:
    while node is not None and node.type in WRAPPERS:
        named = [c for c in node.named_children if c.type != "comment"]
        if node.type == "type_assertion":
            node = named[-1] if named else None
        else:
            node = named[0] if named else None
    return node


def string_value(node: Node | None) -> str | None:
    node = unwrap(node)
    if node is None:
        return None
    if node.type == "string":
        parts = [c for c in node.named_children
                 if c.type in ("string_fragment", "escape_sequence")]
        return "".join(node_text(c) for c in parts)
    if node.type == "template_string":
        if any(c.type == "template_substitution" for c in node.named_children):
            return None
        return node_text(node)[1:-1]
    return None


def object_pairs(obj: Node | None) -> dict[str, Node]:
    pairs: dict[str, Node] = {}
    obj = unwrap(obj)
    if obj is None or obj.type != "object":
        return pairs
    for child in obj.named_children:
        if child.type == "pair":
            key = child.child_by_field_name("key")
            name = string_value(key) if key.type == "string" else node_text(key)
            pairs[name or ""] = child.child_by_field_name("value")
        elif child.type == "shorthand_property_identifier":
            pairs[node_text(child)] = child
        elif child.type == "method_definition":
            pairs[node_text(child.child_by_field_name("name"))] = child
    return pairs


def has_spread(obj: Node | None) -> bool:
    obj = unwrap(obj)
    return obj is not None and any(c.type == "spread_element"
                                   for c in obj.named_children)


def enclosing_function(node: Node) -> Node | None:
    current = node.parent
    while current is not None:
        if current.type in FUNCTION_TYPES:
            return current
        current = current.parent
    return None


def _top_level_function(root: Node, name: str) -> Node | None:
    for stmt in root.named_children:
        if stmt.type in ("function_declaration", "generator_function_declaration"):
            if node_text(stmt.child_by_field_name("name")) == name:
                return stmt
        if stmt.type in ("lexical_declaration", "variable_declaration"):
            for decl in stmt.named_children:
                value = unwrap(decl.child_by_field_name("value"))
                if node_text(decl.child_by_field_name("name")) == name and \
                   value is not None:
                    if value.type in FUNCTION_TYPES:
                        return value
    return None


def exported_functions(tree: JsTree) -> dict[str, Node]:
    found: dict[str, Node] = {}
    for stmt in tree.root.named_children:
        if stmt.type != "export_statement":
            continue
        is_default = any(c.type == "default" for c in stmt.children)
        decl = stmt.child_by_field_name("declaration")
        named_function = ("function_declaration", "generator_function_declaration")
        if decl is not None and decl.type in named_function:
            found[node_text(decl.child_by_field_name("name"))] = decl
            if is_default:
                found["default"] = decl
        elif decl is not None and decl.type in ("lexical_declaration",
                                                 "variable_declaration"):
            for item in decl.named_children:
                value = unwrap(item.child_by_field_name("value"))
                if item.type == "variable_declarator" and value is not None:
                    if value.type in FUNCTION_TYPES:
                        found[node_text(item.child_by_field_name("name"))] = value
        elif is_default:
            value = unwrap(stmt.child_by_field_name("value"))
            if value is not None and value.type in FUNCTION_TYPES:
                found["default"] = value
            elif value is not None and value.type == "identifier":
                target = _top_level_function(tree.root, node_text(value))
                if target is not None:
                    found["default"] = target
    return found


def resolve_identifier(ident: Node) -> Node | None:
    name = node_text(ident)
    ident_scope = enclosing_function(ident)
    if ident_scope is None:
        search_root = ident
        while search_root.parent is not None:
            search_root = search_root.parent
    else:
        search_root = ident_scope
    best = None
    for decl in walk(search_root, {"variable_declarator"}):
        target = decl.child_by_field_name("name")
        if target is None or target.type != "identifier" or \
           node_text(target) != name:
            continue
        decl_scope = enclosing_function(decl)
        if ident_scope is None:
            if decl_scope is not None:
                continue
        else:
            if (decl_scope is None or
                decl_scope.start_byte != ident_scope.start_byte or
                decl_scope.end_byte != ident_scope.end_byte or
                decl_scope.type != ident_scope.type):
                continue
        if decl.start_byte < ident.start_byte:
            best = decl.child_by_field_name("value")
    return unwrap(best)


def has_directive(tree: JsTree, directive: str = "use server") -> bool:
    for stmt in tree.root.named_children:
        if stmt.type == "comment":
            continue
        if stmt.type == "expression_statement" and stmt.named_children:
            return string_value(stmt.named_children[0]) == directive
        return False
    return False


def member_root(node: Node | None) -> str | None:
    node = unwrap(node)
    while node is not None and node.type in ("member_expression", "subscript_expression"):
        node = unwrap(node.child_by_field_name("object"))
    if node is not None and node.type == "identifier":
        return node_text(node)
    return None
