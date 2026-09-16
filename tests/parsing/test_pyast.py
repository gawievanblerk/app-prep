import ast

from dpr.parsing import pyast
from dpr.walk import RepoIndex

CODE = '''
from django.db import models

class Invoice(models.Model):
    amount = models.IntegerField(unique=True)
    note: str = "x"

    class Meta:
        db_table = "billing_invoice"

def view(request, pk):
    def inner():
        return requests.get(request.GET.get("url"))
    return cookies().set("sid", "v")
'''


def tree():
    return ast.parse(CODE)


def test_dotted_and_calls():
    t = tree()
    names = [pyast.dotted(c.func) for c in pyast.calls(t, r".*")]
    assert names == [
        "models.IntegerField", "requests.get", "request.GET.get", "cookies().set", "cookies",
    ]
    assert [c.lineno for c in pyast.calls(t, r"requests\.get")] == [13]


def test_kwarg_and_constant():
    [call] = list(pyast.calls(tree(), r"models\.IntegerField"))
    assert pyast.constant(pyast.kwarg(call, "unique")) is True
    assert pyast.kwarg(call, "null") is None
    assert pyast.constant(call.func, default="nope") == "nope"


def test_classes_bases_assignments():
    [cls] = [c for c in pyast.class_defs(tree()) if c.name == "Invoice"]
    assert pyast.base_names(cls) == ["models.Model"]
    body = pyast.assignments(cls.body)
    assert sorted(body) == ["amount", "note"]
    meta = next(n for n in cls.body if isinstance(n, ast.ClassDef))
    assert pyast.constant(pyast.assignments(meta.body)["db_table"]) == "billing_invoice"


def test_function_at_is_innermost():
    t = tree()
    assert pyast.function_at(t, 13).name == "inner"
    assert pyast.function_at(t, 14).name == "view"
    assert pyast.function_at(t, 2) is None
    assert [f.name for f in pyast.functions(t)] == ["view", "inner"]


def test_name_root_and_names_in():
    [call] = list(pyast.calls(tree(), r"requests\.get"))
    assert pyast.name_root(call.args[0]) == "request"
    assert {"request", "requests"} <= pyast.names_in(call)


def test_parse_file_caches_and_records_syntax_errors(tmp_path):
    (tmp_path / "ok.py").write_text("x = 1\n")
    (tmp_path / "bad.py").write_text("print 'py2'\n")
    index = RepoIndex(tmp_path)
    assert pyast.parse_file(index, "ok.py") is pyast.parse_file(index, "ok.py")
    assert pyast.parse_file(index, "bad.py") is None
    assert index.skipped == ["bad.py: Python syntax could not be parsed"]
