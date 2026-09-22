import time

from dpr.model import Location
from dpr.parsing.sql import split_sql
from dpr.parsing.sqlgrants import parse_grant
from dpr.parsing.sqlschema import SchemaState

LOC = Location("m.sql", 1)


def grant(sql):
    [stmt] = split_sql(sql)
    return parse_grant(stmt.norm, LOC)


def test_table_grant_to_client_roles():
    g = grant("GRANT SELECT, INSERT ON TABLE public.notes, profiles TO anon, authenticated;")
    assert (g.action, g.privileges, g.kind) == ("grant", ("select", "insert"), "table")
    assert g.objects == ("public.notes", "public.profiles")
    assert g.roles == ("anon", "authenticated") and g.to_public_role


def test_schema_wide_grant_and_revoke():
    g = grant("grant all on all tables in schema public to app_rw with grant option;")
    assert (g.kind, g.objects, g.roles, g.to_public_role) == (
        "all tables in schema",
        ("public",),
        ("app_rw",),
        False,
    )
    r = grant("REVOKE CREATE ON SCHEMA public FROM PUBLIC;")
    assert (r.action, r.kind, r.objects, r.roles) == ("revoke", "schema", ("public",), ("public",))


def test_role_membership_is_not_an_object_grant():
    assert grant("grant app_admin to alice;") is None
    assert grant("select 1;") is None


def test_schema_state_collects_grants_in_order():
    state = SchemaState()
    for stmt in split_sql(
        "create table t (id int);\ngrant select on t to anon;\nrevoke all on t from anon;"
    ):
        state.apply(stmt, "m.sql")
    assert [(g.action, g.objects, g.location.line) for g in state.grants] == [
        ("grant", ("public.t",), 2),
        ("revoke", ("public.t",), 3),
    ]


def test_malformed_grants_with_no_to_or_from_return_none_quickly():
    start = time.perf_counter()
    result = grant("grant " + ("select on " * 5000) + "x;")
    assert time.perf_counter() - start < 0.5
    assert result is None

    start = time.perf_counter()
    result = grant("grant " + ("a on " * 20000) + ";")
    assert time.perf_counter() - start < 0.5
    assert result is None


def test_grant_with_many_objects_still_parses():
    names = ", ".join(f"t{i}" for i in range(2000))
    g = grant(f"grant select on {names} to anon;")
    assert g is not None
    assert len(g.objects) == 2000
    assert g.objects[0] == "public.t0" and g.objects[-1] == "public.t1999"
    assert g.roles == ("anon",)
