import subprocess

from tests.reviews.helpers import findings_for, write


def git(root, *args):
    subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "-c",
            "user.name=dpr",
            "-c",
            "user.email=dpr@example.invalid",
            *args,
        ],
        check=True,
        capture_output=True,
    )


def locs(found):
    return sorted(str(f.locations[0]) for f in found)


def test_env_tracked_and_in_history(tmp_path):
    git(tmp_path, "init", "-q")
    write(tmp_path, ".env.production", "OLD=1\n")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "add prod env")
    git(tmp_path, "rm", "-q", "--cached", ".env.production")
    (tmp_path / ".env.production").unlink()
    write(tmp_path, ".env", "A=1\n")
    write(tmp_path, ".env.example", "A=\n")
    write(tmp_path, "a.py", "x = 1\n")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "more")
    assert locs(findings_for(tmp_path, "leaks", "LEAK-ENV-TRACKED")) == [".env:1"]
    [history] = findings_for(tmp_path, "leaks", "LEAK-ENV-IN-HISTORY")
    assert str(history.locations[0]) == ".env.production:1"
    assert "Commit " in history.detail


def test_history_paths_are_relative_to_scanned_subfolder(tmp_path):
    git(tmp_path, "init", "-q")
    write(tmp_path, "web/.env.staging", "A=1\n")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "one")
    git(tmp_path, "rm", "-q", "web/.env.staging")
    write(tmp_path, "web/a.py", "x = 1\n")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "two")
    assert locs(findings_for(tmp_path / "web", "leaks", "LEAK-ENV-IN-HISTORY")) == [
        ".env.staging:1"
    ]


def test_git_checks_skipped_outside_repo(tmp_path):
    from dpr import reviews, rules
    from dpr.discovery.detect import detect
    from dpr.walk import RepoIndex

    write(tmp_path, "a.py", "x = 1\n")
    reviews.available()
    index = RepoIndex(tmp_path)
    ctx = rules.Context(index=index, detection=detect(index))
    rules.run_checks("leaks", ctx)
    assert "git checks skipped: not a git repository or git is unavailable" in ctx.not_covered


SCHEMA = "model User {\n  id Int @id\n  email String\n  passwordHash String\n}\nmodel Invoice {\n  id Int @id\n}\n"


def test_broad_response_js(tmp_path):
    write(tmp_path, "prisma/schema.prisma", SCHEMA)
    write(
        tmp_path,
        "app/api/users/[id]/route.ts",
        "export async function GET(req, { params }) {\n"
        "  const user = await prisma.user.findUnique({ where: { id: params.id } })\n"
        "  return NextResponse.json(user)\n}\n",
    )
    write(
        tmp_path,
        "app/api/invoices/[id]/route.ts",
        "export async function GET(req, { params }) {\n"
        "  return NextResponse.json(await prisma.invoice.findFirst({ where: { id: params.id } }))\n}\n",
    )
    write(
        tmp_path,
        "app/api/safe/route.ts",
        "export async function GET() {\n"
        "  const user = await prisma.user.findUnique({ where: { id: 1 }, select: { id: true } })\n"
        "  return NextResponse.json(user)\n}\n",
    )
    write(
        tmp_path,
        "app/api/profile/route.ts",
        "export async function GET() {\n"
        "  const { data } = await supabase.from('profiles').select('*').single()\n"
        "  return Response.json(data)\n}\n",
    )
    write(
        tmp_path,
        "app/actions.ts",
        '"use server"\nexport async function me() {\n  return prisma.user.findFirst({ where: { id: 1 } })\n}\n',
    )
    found = {str(f.locations[0]): f for f in findings_for(tmp_path, "leaks", "LEAK-BROAD-RESPONSE")}
    assert sorted(found) == [
        "app/actions.ts:3",
        "app/api/invoices/[id]/route.ts:2",
        "app/api/profile/route.ts:3",
        "app/api/users/[id]/route.ts:3",
    ]
    assert found["app/api/users/[id]/route.ts:3"].severity.value == "high"
    assert found["app/api/invoices/[id]/route.ts:2"].severity.value == "medium"
    assert found["app/api/profile/route.ts:3"].tag.value == "INFERRED"


def test_broad_response_python(tmp_path):
    write(
        tmp_path,
        "shop/serializers.py",
        "from rest_framework import serializers\n\n"
        "class UserSerializer(serializers.ModelSerializer):\n"
        '    class Meta:\n        model = User\n        fields = "__all__"\n',
    )
    write(
        tmp_path,
        "shop/urls.py",
        "from django.urls import path\nfrom . import views\n"
        "urlpatterns = [path('me/', views.me)]\n",
    )
    write(
        tmp_path,
        "shop/views.py",
        "from django.forms.models import model_to_dict\n\n"
        "def me(request):\n    return JsonResponse(model_to_dict(request.user))\n",
    )
    assert locs(findings_for(tmp_path, "leaks", "LEAK-BROAD-RESPONSE")) == [
        "shop/serializers.py:6",
        "shop/views.py:4",
    ]


def test_ssr_props(tmp_path):
    write(
        tmp_path,
        "pages/account.tsx",
        "export async function getServerSideProps() {\n"
        "  const user = await prisma.user.findUnique({ where: { id: 1 } })\n"
        "  return { props: { user } }\n}\n"
        "export default function Page() { return null }\n",
    )
    assert locs(findings_for(tmp_path, "leaks", "LEAK-SSR-PROPS")) == ["pages/account.tsx:3"]


def test_logged_pii(tmp_path):
    write(
        tmp_path,
        "app/api/signup/route.ts",
        "export async function POST(req) {\n"
        "  const body = await req.json()\n"
        "  try {\n    await prisma.user.create({ data: body })\n"
        "  } catch (err) {\n"
        "    console.error('signup failed', body)\n"
        "    console.error(err)\n"
        "    console.error('signup failed', { requestId })\n"
        "  }\n"
        "  try { parse() } catch (e) { console.log(e) }\n"
        "  logger.info(JSON.stringify(req.headers))\n"
        "}\n",
    )
    write(
        tmp_path,
        "svc/views.py",
        "import logging, traceback\nlogger = logging.getLogger(__name__)\n\n"
        "def create(request):\n"
        "    logger.error(f'bad input {request.data}')\n"
        "    try:\n        Invoice.objects.create(**request.data)\n"
        "    except Exception as e:\n        print(e)\n        traceback.print_exc()\n"
        "    try:\n        parse()\n    except ValueError as e:\n        print(e)\n",
    )
    assert locs(findings_for(tmp_path, "leaks", "LEAK-LOGGED-PII")) == [
        "app/api/signup/route.ts:11",
        "app/api/signup/route.ts:6",
        "app/api/signup/route.ts:7",
        "svc/views.py:10",
        "svc/views.py:5",
        "svc/views.py:9",
    ]


def test_broad_response_through_wrappers_and_chained_status(tmp_path):
    write(tmp_path, "prisma/schema.prisma", SCHEMA)
    write(
        tmp_path,
        "app/api/me/route.ts",
        "export const GET = withAuth(async () => {\n"
        "  const user = await prisma.user.findUnique({ where: { id: 1 } })\n"
        "  return NextResponse.json(user)\n})\n",
    )
    write(
        tmp_path,
        "server.js",
        "router.get('/users/:id', auth, asyncHandler(async (req, res) => {\n"
        "  const user = await prisma.user.findUnique({ where: { id: req.params.id } })\n"
        "  res.status(200).json(user)\n"
        "  res.status(200).json({ id: user.id })\n"
        "  cache.json(user)\n"
        "}))\n",
    )
    write(
        tmp_path,
        "api.js",
        "fastify.get('/invoices/:id', async (req, reply) => {\n"
        "  const invoice = await prisma.invoice.findFirst({ where: { id: 1 } })\n"
        "  return reply.code(200).send(invoice)\n})\n",
    )
    assert locs(findings_for(tmp_path, "leaks", "LEAK-BROAD-RESPONSE")) == [
        "api.js:3",
        "app/api/me/route.ts:3",
        "server.js:3",
    ]


def test_env_tracked_severity_follows_the_names_in_the_file(tmp_path):
    git(tmp_path, "init", "-q")
    write(tmp_path, ".env.production", "NEXT_PUBLIC_SITE_NAME=Example Shop\n")
    write(tmp_path, ".env", "NEXT_PUBLIC_SITE_NAME=x\nDATABASE_URL=postgres://localhost/app\n")
    write(tmp_path, ".env.development", "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=\n")
    write(tmp_path, "web/.env.staging", "NEXT_PUBLIC_A=1\n")
    write(tmp_path, "a.py", "x = 1\n")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "envs")
    (tmp_path / "web/.env.staging").unlink()
    found = {str(f.locations[0]): f for f in findings_for(tmp_path, "leaks", "LEAK-ENV-TRACKED")}
    assert {loc: f.severity.value for loc, f in found.items()} == {
        ".env.development:1": "critical",
        ".env.production:1": "low",
        ".env:1": "critical",
        "web/.env.staging:1": "critical",
    }
    low = found[".env.production:1"]
    assert low.detail == (
        "Only public-prefixed, non-secret names are tracked; "
        "frameworks such as Next.js commit these on purpose."
    )
    assert "Rotate" not in low.fix
    assert "Rotate" in found[".env:1"].fix
    text = repr(list(found.values()))
    assert "Example Shop" not in text and "postgres://localhost/app" not in text
