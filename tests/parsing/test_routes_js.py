from dpr.parsing.routes_js import (
    next_app_routes,
    next_pages_routes,
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
