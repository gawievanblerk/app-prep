from dpr.parsing import jsts
from dpr.parsing.routes_js import (
    next_app_routes,
    next_pages_routes,
    response_calls,
    segments_to_path,
    server_actions,
    server_routes,
)
from dpr.walk import RepoIndex


def write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def repo(tmp_path):
    write(
        tmp_path,
        "app/api/users/[id]/route.ts",
        "export async function GET() {}\nexport const DELETE = async () => {}\n"
        "export function helper() {}\n",
    )
    write(tmp_path, "app/(marketing)/api/signup/route.ts", "export async function POST(req) {}\n")
    write(tmp_path, "src/app/route.ts", "export function GET() {}\n")
    write(
        tmp_path,
        "pages/api/reset/index.js",
        "export default async function handler(req, res) {\n"
        "  if (req.method === 'POST') { return res.json({}) }\n}\n",
    )
    write(tmp_path, "pages/api/ping.ts", "export default function ping(req, res) {}\n")
    write(
        tmp_path,
        "app/actions.ts",
        '"use server"\nexport async function createInvoice(data) {}\n'
        "export default async function signupAction() {}\n",
    )
    write(tmp_path, "lib/not-actions.ts", "export async function nope() {}\n")
    write(
        tmp_path,
        "server.js",
        "const app = express()\n"
        "app.get('/health', (req, res) => res.send('ok'))\n"
        "function loginHandler(req, res) {}\n"
        "router.post('/login', loginHandler)\n"
        "axios.get('/x', cb)\n"
        "client.get('/y', (r) => r)\n"
        "app.all('/any', async (req, res) => {})\n",
    )
    return RepoIndex(tmp_path)


def test_segments_to_path():
    assert segments_to_path(["(shop)", "api", "[id]", "@modal", "[...slug]"]) == "/api/:id/*slug"
    assert segments_to_path(["docs", "[[...rest]]"]) == "/docs/*rest"
    assert segments_to_path([""]) == "/"


def test_next_app_routes(tmp_path):
    routes = next_app_routes(repo(tmp_path))
    got = sorted((r.method, r.path, r.file, r.framework) for r in routes)
    assert got == [
        ("DELETE", "/api/users/:id", "app/api/users/[id]/route.ts", "next-app"),
        ("GET", "/", "src/app/route.ts", "next-app"),
        ("GET", "/api/users/:id", "app/api/users/[id]/route.ts", "next-app"),
        ("POST", "/api/signup", "app/(marketing)/api/signup/route.ts", "next-app"),
    ]
    delete = next(r for r in routes if r.method == "DELETE")
    assert delete.line == 2 and delete.handler.type == "arrow_function"


def test_next_pages_routes(tmp_path):
    routes = next_pages_routes(repo(tmp_path))
    assert sorted((r.method, r.path) for r in routes) == [
        ("ANY", "/api/ping"),
        ("POST", "/api/reset"),
    ]


def test_server_actions(tmp_path):
    routes = server_actions(repo(tmp_path))
    assert sorted((r.method, r.path, r.line) for r in routes) == [
        ("ACTION", "action:createInvoice", 2),
        ("ACTION", "action:signupAction", 3),
    ]


def test_server_routes(tmp_path):
    routes = server_routes(repo(tmp_path))
    assert [(r.method, r.path, r.line, r.framework) for r in routes] == [
        ("GET", "/health", 2, "express"),
        ("POST", "/login", 4, "express"),
        ("ANY", "/any", 7, "express"),
    ]
    login = routes[1]
    assert login.handler.type == "function_declaration"


def test_wrapped_next_handlers_and_export_clauses(tmp_path):
    write(
        tmp_path,
        "app/api/orders/route.ts",
        "export const POST = withAuth(async (req) => {\n  return Response.json({})\n})\n"
        "export const GET = withAuth(withRole('admin', async function list() {}))\n"
        "export const helper = withAuth(async () => {})\n"
        "export const revalidate = 60\n",
    )
    write(
        tmp_path,
        "app/api/auth/[...nextauth]/route.ts",
        "const handler = NextAuth(authOptions)\nexport { handler as GET, handler as POST }\n",
    )
    write(
        tmp_path,
        "app/api/plain/route.ts",
        "async function handler(req) {}\nexport { handler as GET, handler as DELETE }\n"
        "export { PUT } from './other'\nexport { helper as PATCH }\n",
    )
    write(
        tmp_path,
        "pages/api/me.ts",
        "export default withSession(async function me(req, res) {\n"
        "  if (req.method === 'GET') { return }\n})\n",
    )
    index = RepoIndex(tmp_path)
    got = sorted(
        (r.method, r.path, r.line, r.wrappers, r.handler.type) for r in next_app_routes(index)
    )
    assert got == [
        ("DELETE", "/api/plain", 1, (), "function_declaration"),
        ("GET", "/api/auth/*nextauth", 1, ("NextAuth",), "call_expression"),
        ("GET", "/api/orders", 4, ("withAuth", "withRole"), "function_expression"),
        ("GET", "/api/plain", 1, (), "function_declaration"),
        ("POST", "/api/auth/*nextauth", 1, ("NextAuth",), "call_expression"),
        ("POST", "/api/orders", 1, ("withAuth",), "arrow_function"),
    ]
    [me] = next_pages_routes(index)
    assert (me.method, me.path, me.wrappers, me.handler.type) == (
        "GET",
        "/api/me",
        ("withSession",),
        "function_expression",
    )


def test_wrapped_server_action(tmp_path):
    write(
        tmp_path,
        "app/actions.ts",
        '"use server"\nexport const save = authAction(async (data) => {})\n',
    )
    [action] = server_actions(RepoIndex(tmp_path))
    assert (action.path, action.wrappers, action.handler.type) == (
        "action:save",
        ("authAction",),
        "arrow_function",
    )


def test_wrapped_express_and_fastify_handlers(tmp_path):
    write(
        tmp_path,
        "server.js",
        "const router = express.Router()\n"
        "const listUsers = require('./handlers/users')\n"
        "router.get('/x', auth, asyncHandler(async (req, res) => {}))\n"
        "router.post('/y', [requireUser, rateLimit({ max: 5 })], controller.create)\n"
        "router.put('/z', asyncHandler(controller.update))\n"
        "router.get('/users', listUsers)\n"
        "axios.get('/nope', auth, asyncHandler(async () => {}))\n",
    )
    write(
        tmp_path,
        "api.js",
        "const fastify = require('fastify')()\n"
        "fastify.get('/f', { preHandler: [fastify.authenticate] }, async (req, reply) => {})\n"
        "fastify.get('/open', { schema }, async (req, reply) => {})\n",
    )
    routes = server_routes(RepoIndex(tmp_path))
    got = sorted((r.file, r.method, r.path, r.wrappers, r.handler.type) for r in routes)
    assert got == [
        ("api.js", "GET", "/f", ("fastify.authenticate",), "arrow_function"),
        ("api.js", "GET", "/open", (), "arrow_function"),
        ("server.js", "GET", "/users", (), "identifier"),
        ("server.js", "GET", "/x", ("auth", "asyncHandler"), "arrow_function"),
        ("server.js", "POST", "/y", ("requireUser", "rateLimit"), "member_expression"),
        ("server.js", "PUT", "/z", ("asyncHandler",), "call_expression"),
    ]


def test_response_calls():
    tree = jsts.parse_source(
        "a.ts",
        "res.status(200).json(a)\nreply.code(201).send(b)\nNextResponse.json(c)\n"
        "Response.json(d)\nres.json(e)\njson(f)\ncache.json(g)\nres.status(200)\n"
        "res.render('x')\nfetch(u).then((r) => r.json())\nthis.res.json(h)\nclient.send(i)\n",
    )
    assert [jsts.callee(c) for c in response_calls(tree.root)] == [
        "res.status(200).json",
        "reply.code(201).send",
        "NextResponse.json",
        "Response.json",
        "res.json",
        "json",
    ]
