import ast

from dpr.parsing.pyvalues import Literal, resolve
from dpr.reviews.paths import is_test

CODE = """
import os
TOP = 'alpha'
ITEMS = [{'name': 'x', 'secret': 'bravo'}]
def f(arg):
    local = 'charlie'
    use(local)
    use(TOP)
    use(os.getenv('X', 'delta'))
    use(arg)
    for item in ITEMS:
        use(item['secret'])
    use('echo'.encode())
    use(later)
    later = 'too late'
"""


def uses(tree):
    return [
        n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "use"
    ]


def test_resolve_literals():
    tree = ast.parse(CODE)
    values = [
        resolve(tree, call.args[0], call.lineno)
        for call in sorted(uses(tree), key=lambda c: c.lineno)
    ]
    assert values == [
        Literal("charlie"),
        Literal("alpha"),
        Literal("delta", env_fallback=True),
        None,
        Literal("bravo"),
        Literal("echo"),
        None,
    ]


def test_is_test_paths():
    for rel in (
        "tests/a.py",
        "app/test_x.py",
        "x_test.py",
        "conftest.py",
        "web/a.test.tsx",
        "src/__tests__/b.js",
    ):
        assert is_test(rel), rel
    for rel in ("app/testing_utils.py", "src/contest.ts", "latest/a.py"):
        assert not is_test(rel), rel
