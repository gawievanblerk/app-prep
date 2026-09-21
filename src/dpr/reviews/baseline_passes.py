"""Review 4, baseline: checks the repository passes, so the fix list is read in proportion."""

from __future__ import annotations

import ast
import re

from dpr.discovery.approots import root_of
from dpr.model import Finding, Location
from dpr.parsing import pyast
from dpr.reviews.paths import is_test
from dpr.rules import Context
from dpr.walk import line_of

STRONG_HASHERS = re.compile(r"(?i)\b(bcrypt|argon2|scrypt|pbkdf2)\b")
PY_HASH_SETUP = re.compile(r"CryptContext\(|PASSWORD_HASHERS|argon2\.PasswordHasher|bcrypt\.hashpw")
JS_HASH_SETUP = re.compile(r"(?:bcrypt|bcryptjs|argon2|@node-rs/argon2)['\"]")
COOKIE_SETTING = re.compile(r"(?i)^(?:session_)?cookie_(httponly|secure)$")
SECRET_SETTING = re.compile(r"(?i)^(?:jwt_)?secret(?:_key)?$|^jwt_secret\w*$")
DB_TLS = re.compile(
    r"sslmode=(?:require|verify-full|verify-ca)|ssl=(?:require|true)", re.IGNORECASE
)
BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
LINE_COMMENT_PREFIXES = {
    ".py": ("#",),
    ".toml": ("#",),
    ".yaml": ("#", "//"),
    ".yml": ("#", "//"),
    ".tf": ("#", "//"),
    ".ts": ("//",),
    ".js": ("//",),
}
LITERAL_CONTEXT = re.compile(r"[:=]\s*$")
MARKUP = (".html", ".htm")


def _is_comment_line(line: str, suffix: str) -> bool:
    stripped = line.lstrip()
    return any(stripped.startswith(prefix) for prefix in LINE_COMMENT_PREFIXES.get(suffix, ()))


def _is_assigned_literal(line: str, start: int, end: int) -> bool:
    """Whether line[start:end] is inside a quoted literal assigned or keyed on this line.

    Rejects a string used in a comparison or membership test (`"sslmode=require" in url`),
    which reads a parameter rather than setting one.
    """
    before, after = line[:start], line[end:]
    quote_at = max(before.rfind('"'), before.rfind("'"))
    if quote_at == -1 or after.find(before[quote_at]) == -1:
        return False
    return bool(LITERAL_CONTEXT.search(before[:quote_at]))


def _guarded(cls: ast.ClassDef, name: str) -> int | None:
    """Line of a validator branch in the settings class that raises and mentions the setting."""
    for node in ast.walk(cls):
        if isinstance(node, ast.If) and name in ast.unparse(node.test):
            if any(isinstance(sub, ast.Raise) for stmt in node.body for sub in ast.walk(stmt)):
                return node.lineno
    return None


def _settings_passes(ctx: Context) -> list[str]:
    found = []
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if is_test(entry.rel) or "Settings" not in text:
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        for cls in pyast.class_defs(tree) if tree else []:
            if not any(b.endswith("Settings") for b in pyast.base_names(cls)):
                continue
            for stmt in cls.body:
                if not (isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name)):
                    continue
                name, value = stmt.target.id, pyast.constant(stmt.value, None)
                cookie = COOKIE_SETTING.match(name)
                guard = _guarded(cls, name)
                if cookie and (value is True or guard):
                    how = (
                        "defaults to on"
                        if value is True
                        else "is enforced in production by a validator"
                    )
                    line = stmt.lineno if value is True else guard
                    found.append(f"Cookie {cookie.group(1)} {how} (`{entry.rel}:{line}`)")
                if SECRET_SETTING.match(name) and guard:
                    found.append(
                        f"The signing secret {name} is checked by a production validator that "
                        f"rejects development values (`{entry.rel}:{guard}`)"
                    )
    return found


def _hashing(ctx: Context) -> list[str]:
    found: dict[object, str] = {}
    for entry in [*ctx.index.py_files, *ctx.index.js_files]:
        if is_test(entry.rel):
            continue
        home = root_of(ctx.detection.app_roots, entry.rel)
        if home in found:
            continue
        text = ctx.index.text(entry.rel)
        setup = (
            PY_HASH_SETUP.search(text) if entry.rel.endswith(".py") else JS_HASH_SETUP.search(text)
        )
        if not setup:
            continue
        window = text[setup.start() : setup.start() + 200]
        strong = STRONG_HASHERS.search(window)
        if strong:
            line = line_of(text, setup.start())
            found[home] = f"Password hashing uses {strong.group(1).lower()} (`{entry.rel}:{line}`)"
    return list(found.values())


def _database_tls(ctx: Context) -> list[str]:
    locations = []
    for entry in ctx.index.files:
        if not entry.rel.endswith((".tf", ".yaml", ".yml", ".toml", ".json", ".py", ".ts", ".js")):
            continue
        if is_test(entry.rel):
            continue
        text = ctx.index.text(entry.rel)
        if entry.suffix in (".js", ".ts"):
            text = BLOCK_COMMENT.sub("", text)
        for match in DB_TLS.finditer(text):
            line_start = text.rfind("\n", 0, match.start()) + 1
            line_end = text.find("\n", match.end())
            line_end = len(text) if line_end == -1 else line_end
            line_text = text[line_start:line_end]
            if _is_comment_line(line_text, entry.suffix):
                continue
            if not _is_assigned_literal(
                line_text, match.start() - line_start, match.end() - line_start
            ):
                continue
            locations.append(Location(entry.rel, line_of(text, match.start())))
            break
    if not locations:
        return []
    return [
        "Database connections require TLS (" + ", ".join(f"`{loc}`" for loc in locations[:3]) + ")"
    ]


def _mixed_content(ctx: Context, findings: list[Finding]) -> list[str]:
    pages = [f.rel for f in ctx.index.files if f.rel.endswith(MARKUP) and not is_test(f.rel)]
    if pages and not any(f.rule_id == "BASE-MIXED-CONTENT" for f in findings):
        return [f"No http:// asset URLs in {len(pages)} HTML file(s)"]
    return []


def checks_that_pass(ctx: Context, findings: list[Finding]) -> str:
    lines = [
        *_hashing(ctx),
        *_settings_passes(ctx),
        *_database_tls(ctx),
        *_mixed_content(ctx, findings),
    ]
    if not lines:
        return "No passing checks could be confirmed from code."
    return "\n".join(f"- {line}. CONFIRMED" for line in dict.fromkeys(lines))
