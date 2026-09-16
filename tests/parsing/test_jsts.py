from dpr.parsing import jsts
from dpr.walk import RepoIndex

ROUTE = """import { prisma } from "@/lib/db"

export async function GET(req: Request, { params }: { params: { id: string } }) {
  const invoice = await prisma.invoice.findUnique({ where: { id: params.id } })
  return NextResponse.json(invoice)
}

export const POST = async (req) => {
  const body = await req.json()
  return Response.json({ ok: true, ...body })
}
"""


def tree(code=ROUTE, rel="app/api/x/route.ts"):
    return jsts.parse_source(rel, code)


def test_grammar_for():
    assert jsts.grammar_for("a.ts") == "typescript"
    assert jsts.grammar_for("a.tsx") == "tsx"
    assert jsts.grammar_for("a.jsx") == "javascript"


def test_calls_callee_and_line():
    t = tree()
    [call] = list(jsts.calls(t, r"prisma\.\w+\.findUnique"))
    assert jsts.callee(call) == "prisma.invoice.findUnique"
    assert jsts.line(t, call) == 4


def test_object_pairs_and_spread():
    t = tree()
    [call] = list(jsts.calls(t, r"prisma\.\w+\.findUnique"))
    [arg] = jsts.arguments(call)
    pairs = jsts.object_pairs(arg)
    assert list(pairs) == ["where"]
    assert list(jsts.object_pairs(pairs["where"])) == ["id"]
    [resp] = list(jsts.calls(t, r"Response\.json"))
    obj = jsts.arguments(resp)[0]
    assert jsts.has_spread(obj)
    assert list(jsts.object_pairs(obj)) == ["ok"]


def test_string_value():
    t = tree("a('x'); b(\"y\"); c(`z`); d(`${v}`); e(1)", rel="a.js")
    values = [jsts.string_value(jsts.arguments(c)[0]) for c in jsts.calls(t, r"[a-e]")]
    assert values == ["x", "y", "z", None, None]


def test_exported_functions_and_default():
    t = tree(ROUTE + "\nexport default function handler(req, res) {}\n")
    exported = jsts.exported_functions(t)
    assert sorted(exported) == ["GET", "POST", "default", "handler"]
    assert exported["POST"].type == "arrow_function"


def test_default_export_of_identifier():
    t = tree("function handler(req, res) {}\nexport default handler\n", rel="pages/api/a.js")
    assert jsts.exported_functions(t)["default"].type == "function_declaration"


def test_resolve_identifier_and_enclosing_function():
    t = tree()
    [resp] = list(jsts.calls(t, r"NextResponse\.json"))
    ident = jsts.arguments(resp)[0]
    value = jsts.resolve_identifier(ident)
    assert value.type == "call_expression"
    assert jsts.callee(value) == "prisma.invoice.findUnique"
    fn = jsts.enclosing_function(resp)
    assert fn.type == "function_declaration"


def test_member_root():
    t = tree("log(req.body.email); log(user); log(a[0].b)", rel="a.js")
    roots = [jsts.member_root(jsts.arguments(c)[0]) for c in jsts.calls(t, "log")]
    assert roots == ["req", "user", "a"]


def test_has_directive():
    assert jsts.has_directive(tree('"use server"\nexport async function a() {}', rel="a.ts"))
    assert not jsts.has_directive(tree("import x from 'y'\n'use server'", rel="a.ts"))


def test_vue_script_blocks_keep_file_line_numbers(tmp_path):
    (tmp_path / "C.vue").write_text(
        "<template>\n  <div/>\n</template>\n"
        "<script setup lang=\"ts\">\nconst a = fetchIt()\n</script>\n"
    )
    index = RepoIndex(tmp_path)
    [t] = jsts.parse_file(index, "C.vue")
    [call] = list(jsts.calls(t, "fetchIt"))
    assert jsts.line(t, call) == 5
    assert jsts.parse_file(index, "C.vue") is jsts.parse_file(index, "C.vue")


def test_unwrap_type_assertions():
    t = tree(
        """const a = <Foo>bar
const b = baz as Foo
const c = qux!
const d = (await zap) satisfies Foo""",
        rel="a.ts"
    )
    values = []
    for stmt in t.root.named_children:
        if stmt.type in ("lexical_declaration", "variable_declaration"):
            for decl in stmt.named_children:
                if decl.type == "variable_declarator":
                    value = decl.child_by_field_name("value")
                    values.append(jsts.node_text(jsts.unwrap(value)))
    assert values == ["bar", "baz", "qux", "zap"]


def test_resolve_identifier_respects_scope():
    t = tree(
        """function outer() {
  function helper() { const secret = "inner"; return secret }
  helper()
  log(secret)
}""",
        rel="a.js"
    )
    [log_call] = list(jsts.calls(t, "log"))
    secret_ident = jsts.arguments(log_call)[0]
    assert jsts.resolve_identifier(secret_ident) is None

    t2 = tree(
        """function f() { const ok = "yes"; function g() {} ; log(ok) }""",
        rel="a.js"
    )
    [log_call2] = list(jsts.calls(t2, "log"))
    ok_ident = jsts.arguments(log_call2)[0]
    value = jsts.resolve_identifier(ok_ident)
    assert value is not None
    assert jsts.string_value(value) == "yes"
