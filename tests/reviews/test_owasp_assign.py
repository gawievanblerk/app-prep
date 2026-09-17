from tests.reviews.helpers import findings_for, write


def test_mass_assignment_js(tmp_path):
    write(
        tmp_path,
        "prisma/schema.prisma",
        "model User {\n  id Int @id\n  email String\n  role String\n}\nmodel Note {\n  id Int @id\n  body String\n}\n",
    )
    write(
        tmp_path,
        "app/api/users/route.ts",
        "export async function POST(req: Request) {\n"
        "  const body = await req.json()\n"
        "  await prisma.user.create({ data: body })\n"
        "  await prisma.note.create({ data: { ...body } })\n"
        "  await prisma.note.create({ data: { body: body.text } })\n"
        "}\n",
    )
    write(
        tmp_path,
        "server/notes.js",
        "router.put('/notes/:id', auth, async (req, res) => {\n"
        "  await Note.findByIdAndUpdate(req.params.id, req.body)\n"
        "  await Note.findByIdAndUpdate(req.params.id, { text: req.body.text })\n"
        "})\n",
    )
    found = findings_for(tmp_path, "owasp", "OWASP-A01-MASS-ASSIGNMENT")
    assert sorted((str(f.locations[0]), f.tag.value) for f in found) == [
        ("app/api/users/route.ts:3", "CONFIRMED"),
        ("app/api/users/route.ts:4", "INFERRED"),
        ("server/notes.js:2", "INFERRED"),
    ]
    confirmed = next(f for f in found if f.tag.value == "CONFIRMED")
    assert "role" in confirmed.detail


def test_mass_assignment_python(tmp_path):
    write(
        tmp_path,
        "api/app.py",
        "from fastapi import FastAPI, Request\napp = FastAPI()\n"
        "@app.post('/items')\nasync def create(request: Request):\n"
        "    payload = await request.json()\n    return Item(**payload)\n"
        "@app.put('/items/{item_id}')\nasync def update(item_id: str, data: ItemUpdate):\n"
        "    item = Item(**data.model_dump())\n"
        "    for key, value in data.model_dump(exclude_unset=True).items():\n        setattr(item, key, value)\n",
    )
    write(
        tmp_path,
        "shop/urls.py",
        "from django.urls import path\nfrom . import views\nurlpatterns = [path('orders/', views.order)]\n",
    )
    write(
        tmp_path,
        "shop/views.py",
        "def order(request):\n    data = request.POST.dict()\n"
        "    for key, value in data.items():\n        setattr(order, key, value)\n",
    )
    found = findings_for(tmp_path, "owasp", "OWASP-A01-MASS-ASSIGNMENT")
    assert sorted(str(f.locations[0]) for f in found) == ["api/app.py:6", "shop/views.py:3"]


def test_client_only_guard(tmp_path):
    write(
        tmp_path,
        "src/Nav.tsx",
        "export const Nav = ({ user }) => user.role === 'admin' ? <Admin /> : null\n",
    )
    write(
        tmp_path,
        "app/api/admin/users/route.ts",
        "export async function GET() {\n  const session = await auth()\n}\n",
    )
    write(
        tmp_path,
        "app/api/admin/stats/route.ts",
        "export async function GET() {\n  const session = await auth()\n  if (session.user.role !== 'admin') return null\n}\n",
    )
    [f] = findings_for(tmp_path, "owasp", "OWASP-A01-CLIENT-ONLY-GUARD")
    assert [str(loc) for loc in f.locations] == ["app/api/admin/users/route.ts:1", "src/Nav.tsx:1"]
    (tmp_path / "src/Nav.tsx").write_text("export const Nav = () => null\n")
    assert findings_for(tmp_path, "owasp", "OWASP-A01-CLIENT-ONLY-GUARD") == []
