"""Resolve import statements to files in the repository, for Python and JS/TS."""

from __future__ import annotations

import ast
import re
from pathlib import PurePosixPath

from dpr.walk import RepoIndex

JS_IMPORT = re.compile(
    r"""\bimport\s+(?:type\s+)?(?:([\w$]+)\s*,?\s*)?(?:\*\s*as\s+([\w$]+)|\{([^}]*)\})?"""
    r"""\s*from\s*['"]([^'"]+)['"]"""
)
JS_REQUIRE = re.compile(
    r"""\b(?:const|let|var)\s+(?:([\w$]+)|\{([^}]*)\})\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)"""
)
ALIAS = re.compile(r"^(?:@|~|#)/")
Target = tuple[str | None, str, str]


def _shared(a: str, b: str) -> int:
    count = 0
    for left, right in zip(a.split("/"), b.split("/"), strict=False):
        if left != right:
            break
        count += 1
    return count


def _closest(candidates: list[str], importer: str) -> str | None:
    if not candidates:
        return None
    return max(candidates, key=lambda rel: (_shared(rel, importer), -len(rel)))


def _py_modules(index: RepoIndex) -> dict[str, list[str]]:
    """Every dotted module suffix ("c", "b.c", "a.b.c") mapped to the files that define it."""
    key = ("py-module-suffixes", "")
    if key not in index.cache:
        found: dict[str, list[str]] = {}
        for entry in index.py_files:
            parts = PurePosixPath(entry.rel).with_suffix("").parts
            if parts and parts[-1] == "__init__":
                parts = parts[:-1]
            for start in range(len(parts)):
                found.setdefault(".".join(parts[start:]), []).append(entry.rel)
        index.cache[key] = found
    return index.cache[key]


def module_file(index: RepoIndex, importer: str, module: str, level: int = 0) -> str | None:
    """The repository file for a Python module imported from `importer`, or None."""
    if level:
        base = PurePosixPath(importer).parent
        for _ in range(level - 1):
            base = base.parent
        stem = (base / module.replace(".", "/")) if module else base
        wanted = {f"{stem.as_posix()}.py", f"{stem.as_posix()}/__init__.py"}
        wanted = {w.removeprefix("./") for w in wanted}
        return next((f.rel for f in index.py_files if f.rel in wanted), None)
    return _closest(_py_modules(index).get(module, []), importer)


def py_imports(index: RepoIndex, rel: str, tree: ast.Module | None) -> dict[str, Target]:
    """Local name to (file or None, attribute, module) for every import in the file.

    The attribute is "" when the name is the module itself. Imports inside functions count.
    """
    key = ("py-imports", rel)
    if key in index.cache:
        return index.cache[key]
    names: dict[str, Target] = {}
    for node in ast.walk(tree) if tree is not None else []:
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                local = alias.asname or alias.name
                sub = f"{node.module}.{alias.name}" if node.module else alias.name
                as_module = module_file(index, rel, sub, node.level)
                if as_module is not None:
                    names[local] = (as_module, "", sub)
                    continue
                owner = module_file(index, rel, node.module or "", node.level)
                names[local] = (owner, alias.name, "." * node.level + (node.module or ""))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    names[alias.asname] = (module_file(index, rel, alias.name), "", alias.name)
    index.cache[key] = names
    return names


def _js_stems(index: RepoIndex) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Exact stems (path without extension, and folder for index files), and every path suffix
    of those stems, each mapped to the files they name."""
    key = ("js-stems", "")
    if key not in index.cache:
        exact: dict[str, list[str]] = {}
        suffixes: dict[str, list[str]] = {}
        for entry in index.js_files:
            parts = re.sub(r"\.[^./]+$", "", entry.rel).split("/")
            stems = [parts]
            if parts[-1] == "index" and len(parts) > 1:
                stems.append(parts[:-1])
            for stem in stems:
                exact.setdefault("/".join(stem), []).append(entry.rel)
                for start in range(len(stem)):
                    suffixes.setdefault("/".join(stem[start:]), []).append(entry.rel)
        index.cache[key] = (exact, suffixes)
    return index.cache[key]


def js_target(index: RepoIndex, importer: str, spec: str) -> str | None:
    """The file a relative (./x) or aliased (@/x, ~/x) import specifier points at, or None."""
    exact, suffixes = _js_stems(index)
    if spec.startswith("."):
        parts: list[str] = []
        for part in (PurePosixPath(importer).parent / spec).as_posix().split("/"):
            if part == "..":
                parts = parts[:-1]
            elif part not in (".", ""):
                parts.append(part)
        stem = re.sub(r"\.(?:[cm]?[jt]sx?)$", "", "/".join(parts))
        return _closest(exact.get(stem, []), importer)
    if not ALIAS.match(spec):
        return None
    tail = re.sub(r"\.(?:[cm]?[jt]sx?)$", "", ALIAS.sub("", spec))
    return _closest(suffixes.get(tail, []), importer)


def is_local_spec(spec: str) -> bool:
    return spec.startswith(".") or bool(ALIAS.match(spec))


def _named(clause: str, separator: str) -> list[tuple[str, str]]:
    pairs = []
    for part in clause.split(","):
        words = part.replace("type ", " ").strip().split(separator)
        exported = words[0].strip()
        local = words[-1].strip()
        if re.fullmatch(r"[\w$]+", exported) and re.fullmatch(r"[\w$]+", local):
            pairs.append((local, exported))
    return pairs


def js_imports(index: RepoIndex, rel: str) -> dict[str, Target]:
    """Local name to (file or None, exported name, specifier).

    The exported name is "default" for a default import and "*" for a namespace import or a
    whole CommonJS require.
    """
    key = ("js-imports", rel)
    if key in index.cache:
        return index.cache[key]
    text = index.text(rel)
    names: dict[str, Target] = {}
    for match in JS_IMPORT.finditer(text):
        default, namespace, clause, spec = match.groups()
        target = js_target(index, rel, spec)
        if default:
            names[default] = (target, "default", spec)
        if namespace:
            names[namespace] = (target, "*", spec)
        for local, exported in _named(clause or "", " as "):
            names[local] = (target, exported, spec)
    for match in JS_REQUIRE.finditer(text):
        whole, clause, spec = match.groups()
        target = js_target(index, rel, spec)
        if whole:
            names[whole] = (target, "*", spec)
        for local, exported in _named(clause or "", ":"):
            names[local] = (target, exported, spec)
    index.cache[key] = names
    return names
