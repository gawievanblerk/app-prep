from dpr.parsing.sql import (
    balanced,
    clean_predicate,
    find_top_level,
    qualify,
    split_sql,
    split_top_level,
)


def test_split_basic_lines_and_norm():
    stmts = split_sql("CREATE TABLE A (id int);\n\n  ALTER   TABLE a\n ENABLE ROW LEVEL SECURITY;")
    assert [s.line for s in stmts] == [1, 3]
    assert stmts[0].norm == "create table a (id int)"
    assert stmts[1].norm == "alter table a enable row level security"


def test_semicolons_inside_quotes_comments_and_dollar_bodies():
    sql = (
        "-- leading comment; not a statement\n"
        "insert into t values ('a;b', 'it''s');\n"
        "/* block /* nested; */ still; */ select \"Mixed;Case\" from t;\n"
        "create function f() returns int as $$ select 1; select 2; $$ language sql;\n"
        "create function g() returns int as $body$ SELECT 3; $body$ language sql;\n"
    )
    stmts = split_sql(sql)
    assert len(stmts) == 4
    assert stmts[0].line == 2
    assert stmts[0].norm == "insert into t values ('a;b', 'it''s')"
    assert stmts[1].norm == 'select "Mixed;Case" from t'
    assert stmts[1].line == 3
    assert "select 1; select 2;" in stmts[2].norm
    assert "$body$ select 3; $body$" in stmts[3].norm


def test_quoted_values_keep_case():
    [stmt] = split_sql("INSERT INTO storage.buckets (id) VALUES ('Avatars')")
    assert stmt.norm == "insert into storage.buckets (id) values ('Avatars')"


def test_positional_parameters_are_not_dollar_quotes():
    stmts = split_sql("select $1; select 2;")
    assert [s.norm for s in stmts] == ["select $1", "select 2"]


def test_helpers():
    s = "for select to authenticated using (a = (b)) with check (c)"
    assert find_top_level(s, r"using\b") == s.index("using")
    assert find_top_level("x (using y)", r"using\b") == -1
    assert find_top_level("reusing", r"using\b") == -1
    inner, end = balanced(s, s.index("("))
    assert inner == "a = (b)"
    assert s[end:].startswith(" with check")
    assert split_top_level("a int, b numeric(10, 2), 'x,y'") == ["a int", "b numeric(10, 2)", "'x,y'"]
    assert qualify('"public"."Docs"') == "public.Docs"
    assert qualify("docs") == "public.docs"
    assert qualify("auth.users") == "auth.users"
    assert clean_predicate(" ((true)) ") == "true"
    assert clean_predicate("(a) and (b)") == "(a) and (b)"
