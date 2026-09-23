from dpr import rules
from tests.reviews.helpers import findings_for, write

MODELS = (
    "from sqlalchemy import Column, ForeignKey, Integer, String\n"
    "class Attachment(Base):\n    __tablename__ = 'attachments'\n"
    "    id = Column(String, primary_key=True)\n    uploaded_by_id = Column(String)\n"
    "class Note(Base):\n    __tablename__ = 'notes'\n"
    "    id = Column(String, primary_key=True)\n    attachment_id = Column(String, ForeignKey('attachments.id'))\n"
    "class Country(Base):\n    __tablename__ = 'countries'\n    id = Column(Integer, primary_key=True)\n"
)
DEPS = (
    "from typing import Annotated\nfrom fastapi import Depends\n"
    "CurrentUser = Annotated[dict, Depends(get_current_user)]\n"
    "AdminUser = Annotated[dict, Depends(get_admin_user)]\n"
)


def fastapi_app(root):
    write(root, "api/app/models.py", MODELS)
    write(root, "api/app/deps.py", DEPS)
    write(
        root,
        "api/app/service.py",
        "class AttachmentService:\n    def __init__(self, db):\n        self.db = db\n"
        "    async def get_attachment(self, attachment_id):\n"
        "        return await self.db.execute(select(Attachment).where(Attachment.id == attachment_id))\n"
        "    async def get_for_user(self, attachment_id, user):\n"
        "        return await self.db.execute(select(Attachment).where(Attachment.id == attachment_id))\n",
    )
    write(
        root,
        "api/app/routes.py",
        "from fastapi import APIRouter, Form, Query\nfrom app.deps import AdminUser, CurrentUser\n"
        "router = APIRouter(prefix='/files')\n"
        "@router.get('/{attachment_id}')\n"
        "async def direct(attachment_id: str, current_user: CurrentUser, db=Depends(get_db)):\n"
        "    result = await db.execute(select(Attachment).where(Attachment.id == attachment_id))\n"
        "    return result.scalar_one_or_none()\n"
        "@router.get('/{attachment_id}/mine')\n"
        "async def scoped(attachment_id: str, current_user: CurrentUser, db=Depends(get_db)):\n"
        "    return await db.execute(select(Attachment).where(\n"
        "        Attachment.id == attachment_id, Attachment.uploaded_by_id == current_user.id))\n"
        "@router.get('/{attachment_id}/checked')\n"
        "async def checked(attachment_id: str, current_user: CurrentUser, db=Depends(get_db)):\n"
        "    result = await db.execute(select(Attachment).where(Attachment.id == attachment_id))\n"
        "    item = result.scalar_one_or_none()\n"
        "    if item.uploaded_by_id != current_user.id:\n        raise HTTPException(404)\n"
        "@router.get('/{attachment_id}/helper')\n"
        "async def helper(attachment_id: str, current_user: CurrentUser, db=Depends(get_db)):\n"
        "    result = await db.execute(select(Attachment).where(Attachment.id == attachment_id))\n"
        "    audit(current_user)\n"
        "@router.delete('/{attachment_id}')\n"
        "async def via_service(attachment_id: str, current_user: CurrentUser, db=Depends(get_db)):\n"
        "    service = AttachmentService(db)\n"
        "    item = await service.get_attachment(attachment_id)\n"
        "    logger.info('deleted %s by %s', attachment_id, current_user.id)\n"
        "@router.put('/{attachment_id}')\n"
        "async def via_scoped_service(attachment_id: str, current_user: CurrentUser, db=Depends(get_db)):\n"
        "    return await AttachmentService(db).get_for_user(attachment_id, current_user)\n"
        "@router.get('/notes/{note_id}')\n"
        "async def note(note_id: str, current_user: CurrentUser, db=Depends(get_db)):\n"
        "    return await db.get(Note, note_id)\n"
        "@router.get('/countries/{country_id}')\n"
        "async def country(country_id: int, current_user: CurrentUser, db=Depends(get_db)):\n"
        "    return await db.get(Country, country_id)\n"
        "@router.get('/admin/{attachment_id}')\n"
        "async def admin(attachment_id: str, boss: AdminUser, db=Depends(get_db)):\n"
        "    return await db.get(Attachment, attachment_id)\n"
        "@router.get('')\n"
        "async def listing(current_user: CurrentUser, attachment_id: str = Query(...), db=Depends(get_db)):\n"
        "    return await db.execute(select(Attachment).where(Attachment.id == attachment_id))\n"
        "@router.post('')\n"
        "async def create(current_user: CurrentUser, attachment_id: str = Form(...), db=Depends(get_db)):\n"
        "    return await db.get(Attachment, attachment_id)\n",
    )
    return root


def summary(found):
    return sorted((str(f.locations[0]), f.tag.value) for f in found)


def test_fastapi_unscoped_queries(tmp_path):
    root = fastapi_app(tmp_path)
    found = findings_for(root, "owasp", "OWASP-A01-UNSCOPED-QUERY")
    by_line = {f.locations[0].line: f for f in found}
    assert sorted(by_line) == [6, 20, 25, 32, 41]
    assert {line: f.tag.value for line, f in by_line.items()} == {
        6: "CONFIRMED",
        20: "INFERRED",
        25: "CONFIRMED",
        32: "CONFIRMED",
        41: "CONFIRMED",
    }
    assert by_line[20].proof_needed
    assert [str(loc) for loc in by_line[25].locations] == [
        "api/app/routes.py:25",
        "api/app/service.py:5",
    ]
    assert (
        by_line[6].title
        == "GET /files/{attachment_id} loads Attachment by attachment_id with no owner check"
    )
    assert by_line[32].title.startswith("GET /files/notes/{note_id} loads Note")


def test_django_views_and_sequential_ids(tmp_path):
    write(
        tmp_path,
        "shop/models.py",
        "from django.db import models\n"
        "class Invoice(models.Model):\n    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)\n"
        "    user_id = models.IntegerField()\n    total = models.IntegerField()\n",
    )
    write(
        tmp_path,
        "shop/urls.py",
        "from django.urls import path\nfrom . import views\nurlpatterns = [\n"
        "    path('invoices/<int:pk>/', views.invoice),\n    path('mine/<int:pk>/', views.mine),\n]\n",
    )
    write(
        tmp_path,
        "shop/views.py",
        "from django.contrib.auth.decorators import login_required\n"
        "@login_required\ndef invoice(request, pk):\n    return get_object_or_404(Invoice, pk=pk)\n"
        "@login_required\ndef mine(request, pk):\n    return get_object_or_404(Invoice, pk=pk, user=request.user)\n",
    )
    [unscoped] = findings_for(tmp_path, "owasp", "OWASP-A01-UNSCOPED-QUERY")
    assert (str(unscoped.locations[0]), unscoped.tag.value) == ("shop/views.py:4", "CONFIRMED")
    assert str(unscoped.locations[-1]) == "shop/models.py:2"
    assert "auto-increment integer key" in unscoped.detail
    assert "OWASP-A01-GUESSABLE-ID" not in rules.SPECS


def test_next_and_express_lookups(tmp_path):
    write(
        tmp_path,
        "prisma/schema.prisma",
        "model Invoice {\n  id Int @id @default(autoincrement())\n  userId Int\n}\n",
    )
    write(
        tmp_path,
        "app/api/invoices/[id]/route.ts",
        "export async function GET(req: Request, { params }: { params: { id: string } }) {\n"
        "  const session = await auth()\n"
        "  const invoice = await prisma.invoice.findUnique({ where: { id: Number(params.id) } })\n"
        "  return Response.json(invoice)\n}\n"
        "export async function PUT(req: Request, { params }: { params: { id: string } }) {\n"
        "  const session = await auth()\n"
        "  return prisma.invoice.findFirst({ where: { id: Number(params.id), userId: session.user.id } })\n}\n"
        "export async function DELETE(req: Request, { params }: { params: { id: string } }) {\n"
        "  const session = await auth()\n"
        "  const invoice = await prisma.invoice.findUnique({ where: { id: Number(params.id) } })\n"
        "  if (invoice.userId !== session.user.id) return new Response(null, { status: 404 })\n}\n",
    )
    write(
        tmp_path,
        "server/orders.js",
        "router.get('/orders/:id', requireAuth, async (req, res) => {\n"
        "  const order = await Order.findById(req.params.id)\n  res.json(order)\n})\n",
    )
    found = findings_for(tmp_path, "owasp", "OWASP-A01-UNSCOPED-QUERY")
    assert summary(found) == [
        ("app/api/invoices/[id]/route.ts:3", "CONFIRMED"),
        ("server/orders.js:2", "INFERRED"),
    ]
    invoice = next(f for f in found if f.locations[0].file.startswith("app/"))
    assert str(invoice.locations[-1]) == "prisma/schema.prisma:2"
    assert invoice.detail.endswith(
        "Invoice has an auto-increment integer key, so one working ID reveals the others."
    )
    assert invoice.severity.value == "high"


def test_unguarded_method(tmp_path):
    write(
        tmp_path,
        "app/api/posts/[id]/route.ts",
        "export async function GET() {\n  const session = await auth()\n}\n"
        "export async function DELETE() {\n  return new Response(null)\n}\n",
    )
    write(
        tmp_path,
        "app/api/open/route.ts",
        "export async function GET() {}\nexport async function POST() {}\n",
    )
    [f] = findings_for(tmp_path, "owasp", "OWASP-A01-UNGUARDED-METHOD")
    assert str(f.locations[0]) == "app/api/posts/[id]/route.ts:4"
    assert f.title == "DELETE /api/posts/:id has no auth check while GET on the same route does"


def test_email_ownership(tmp_path):
    write(
        tmp_path,
        "app/portal.py",
        "async def resolve(db, user):\n"
        "    return await db.execute(select(Client).where(func.lower(Client.email) == user.email.lower()))\n"
        "async def me(db, current_user):\n"
        "    return await db.execute(select(User).where(User.email == current_user.email))\n",
    )
    write(
        tmp_path,
        "lib/portal.ts",
        "export const load = (session) => prisma.customerRecord.findFirst({ where: { email: session.user.email } })\n",
    )
    found = findings_for(tmp_path, "owasp", "OWASP-A01-EMAIL-OWNERSHIP")
    assert sorted((str(f.locations[0]), f.tag.value) for f in found) == [
        ("app/portal.py:2", "INFERRED"),
        ("lib/portal.ts:1", "INFERRED"),
    ]


def test_unguarded_method_is_inferred_when_app_middleware_cannot_be_read(tmp_path):
    write(
        tmp_path,
        "server.js",
        "const express = require('express')\nconst app = express()\n"
        "app.use(tenantGate)\n"
        "app.get('/notes/:id', requireAuth, (req, res) => res.json({}))\n"
        "app.delete('/notes/:id', (req, res) => res.json({}))\n",
    )
    [f] = findings_for(tmp_path, "owasp", "OWASP-A01-UNGUARDED-METHOD")
    assert (str(f.locations[0]), f.tag.value) == ("server.js:5", "INFERRED")
    assert "tenantGate" in f.proof_needed
    write(
        tmp_path,
        "server.js",
        "const express = require('express')\nconst app = express()\n"
        "app.use(express.json())\n"
        "app.get('/notes/:id', requireAuth, (req, res) => res.json({}))\n"
        "app.delete('/notes/:id', (req, res) => res.json({}))\n",
    )
    [f] = findings_for(tmp_path, "owasp", "OWASP-A01-UNGUARDED-METHOD")
    assert f.tag.value == "CONFIRMED"


def test_unscoped_lookups_on_public_routes_are_inferred(tmp_path):
    write(
        tmp_path,
        "prisma/schema.prisma",
        "model Post {\n  id String @id @default(uuid())\n  authorId String\n  published Boolean\n}\n"
        "model Invoice {\n  id String @id @default(uuid())\n  userId String\n}\n",
    )
    write(
        tmp_path,
        "app/api/posts/[id]/route.ts",
        "export async function GET(req: Request, { params }: { params: { id: string } }) {\n"
        "  const post = await prisma.post.findUnique({ where: { id: params.id, published: true } })\n"
        "  return Response.json(post)\n}\n",
    )
    write(
        tmp_path,
        "app/api/invoices/[id]/route.ts",
        "export async function GET(req: Request, { params }: { params: { id: string } }) {\n"
        "  const invoice = await prisma.invoice.findUnique({ where: { id: params.id } })\n"
        "  return Response.json(invoice)\n}\n"
        "export async function PUT(req: Request, { params }: { params: { id: string } }) {\n"
        "  const session = await auth()\n"
        "  return prisma.invoice.update({ where: { id: params.id }, data: {} })\n}\n",
    )
    write(
        tmp_path,
        "api/posts.py",
        "from fastapi import APIRouter\nrouter = APIRouter()\n"
        "@router.get('/pages/{page_id}')\nasync def page(page_id: str, db=None):\n"
        "    return await db.execute(select(Post).where(Post.id == page_id, Post.is_public == True))\n",
    )
    found = findings_for(tmp_path, "owasp", "OWASP-A01-UNSCOPED-QUERY")
    assert summary(found) == [
        ("app/api/invoices/[id]/route.ts:2", "INFERRED"),
        ("app/api/invoices/[id]/route.ts:7", "CONFIRMED"),
    ]
    public = next(f for f in found if f.tag.value == "INFERRED")
    assert public.proof_needed == "Confirm this record type is not meant to be public."
    assert "Sign in" not in public.attack


def test_positional_only_parameters_do_not_break_lookups(tmp_path):
    write(
        tmp_path,
        "app/main.py",
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "@app.get('/items/{item_id}')\ndef read(item_id: int = 1, /, q: str = ''):\n"
        "    return db.get(Item, item_id)\n",
    )
    found = findings_for(tmp_path, "owasp", "OWASP-A01-UNSCOPED-QUERY")
    assert summary(found) == [("app/main.py:5", "INFERRED")]


def test_visibility_skip_needs_a_truthy_top_level_filter_on_a_read(tmp_path):
    write(
        tmp_path,
        "prisma/schema.prisma",
        "model User {\n  id String @id\n  posts Post[]\n}\n"
        "model Post {\n  id String @id @default(uuid())\n  authorId String\n  published Boolean\n}\n",
    )
    route = (
        "export async function {method}(req: Request, {{ params }}: {{ params: {{ id: string }} }}) {{\n"
        "  const session = await getServerSession()\n"
        "  return Response.json(await {call})\n}}\n"
    )
    cases = {
        "include": "prisma.user.findUnique({ where: { id: params.id }, include: { posts: { where: { published: true } } } })",
        "update": "prisma.post.update({ where: { id: params.id, published: true }, data: { title: 'x' } })",
        "hidden": "prisma.post.findFirst({ where: { id: params.id, published: false } })",
        "shown": "prisma.post.findFirst({ where: { id: params.id, published: true } })",
        "listed": "prisma.post.findFirst({ where: { id: params.id, visibility: 'public' } })",
    }
    for name, call in cases.items():
        write(
            tmp_path,
            f"app/api/{name}/[id]/route.ts",
            route.format(method="PUT" if name == "update" else "GET", call=call),
        )
    write(
        tmp_path,
        "api/app/models.py",
        "class Page(Base):\n    __tablename__ = 'pages'\n    id = Column(String, primary_key=True)\n"
        "    owner_id = Column(String)\n    is_public = Column(Boolean)\n",
    )
    write(tmp_path, "api/app/deps.py", DEPS)
    write(
        tmp_path,
        "api/app/pages.py",
        "from fastapi import APIRouter\nfrom app.deps import CurrentUser\nrouter = APIRouter()\n"
        "@router.get('/pages/{page_id}')\nasync def shown(page_id: str, me: CurrentUser, db=None):\n"
        "    return await db.execute(select(Page).where(Page.id == page_id, Page.is_public == True))\n"
        "@router.get('/private/{page_id}')\nasync def hidden(page_id: str, me: CurrentUser, db=None):\n"
        "    return await db.execute(select(Page).where(Page.id == page_id, Page.is_public == False))\n"
        "@router.get('/owner/{page_id}')\nasync def owner(page_id: str, me: CurrentUser, db=None):\n"
        "    return await db.execute(select(Page).join(Owner).where(Page.id == page_id, Owner.published == True))\n",
    )
    found = findings_for(tmp_path, "owasp", "OWASP-A01-UNSCOPED-QUERY")
    assert sorted(str(f.locations[0]) for f in found) == [
        "api/app/pages.py:12",
        "api/app/pages.py:9",
        "app/api/hidden/[id]/route.ts:3",
        "app/api/include/[id]/route.ts:3",
        "app/api/update/[id]/route.ts:3",
    ]


def test_visibility_skip_needs_a_public_literal_and_no_later_write(tmp_path):
    write(
        tmp_path,
        "prisma/schema.prisma",
        "model Post {\n  id String @id @default(uuid())\n  authorId String\n  published Boolean\n"
        "  visibility String\n}\n",
    )
    route = (
        "export async function GET(req: Request, {{ params }}: {{ params: {{ id: string }} }}) {{\n"
        "  const session = await getServerSession()\n  const body = await req.json()\n"
        "  const post = await prisma.post.findFirst({{ where: {{ id: params.id, {where} }} }})\n"
        "  {after}\n  return Response.json(post)\n}}\n"
    )
    cases = {
        "team": ('visibility: "team"', ""),
        "members": ('visibility: "members"', ""),
        "restricted": ('visibility: "restricted"', ""),
        "body": ("published: body.published", ""),
        "request": ("isPublic: req.isPublic", ""),
        "written": (
            "published: true",
            "await prisma.post.update({ where: { id: post.id }, data: body })",
        ),
        "assigned": ("published: true", "post.title = body.title"),
        "literal-true": ("published: true", ""),
        "literal-one": ("published: 1", ""),
        "literal-public": ('visibility: "public"', ""),
    }
    for name, (where, after) in cases.items():
        write(tmp_path, f"app/api/{name}/[id]/route.ts", route.format(where=where, after=after))
    write(
        tmp_path,
        "api/app/models.py",
        "class Page(Base):\n    __tablename__ = 'pages'\n    id = Column(String, primary_key=True)\n"
        "    owner_id = Column(String)\n    is_public = Column(Boolean)\n    title = Column(String)\n",
    )
    write(tmp_path, "api/app/deps.py", DEPS)
    write(
        tmp_path,
        "api/app/pages.py",
        "from fastapi import APIRouter\nfrom app.deps import CurrentUser\nrouter = APIRouter()\n"
        "@router.put('/pages/{page_id}')\nasync def rename(page_id: str, title: str, me: CurrentUser, db=None):\n"
        "    page = (await db.execute(select(Page).where(Page.id == page_id, Page.is_public == True))).scalar_one()\n"
        "    page.title = title\n    await db.commit()\n    return page\n"
        "@router.get('/query/{page_id}')\nasync def by_flag(page_id: str, is_public: bool, me: CurrentUser, db=None):\n"
        "    return await db.execute(select(Page).where(Page.id == page_id, Page.is_public == is_public))\n"
        "@router.get('/body/{page_id}')\nasync def by_body(page_id: str, me: CurrentUser, filters: Filters, db=None):\n"
        "    return await db.execute(select(Page).where(Page.id == page_id, Page.is_public == filters.is_public))\n"
        "@router.get('/shown/{page_id}')\nasync def shown(page_id: str, me: CurrentUser, db=None):\n"
        "    return await db.execute(select(Page).where(Page.id == page_id, Page.is_public == True))\n",
    )
    found = findings_for(tmp_path, "owasp", "OWASP-A01-UNSCOPED-QUERY")
    assert sorted(str(f.locations[0]) for f in found) == [
        "api/app/pages.py:12",
        "api/app/pages.py:15",
        "api/app/pages.py:6",
        "app/api/assigned/[id]/route.ts:4",
        "app/api/body/[id]/route.ts:4",
        "app/api/members/[id]/route.ts:4",
        "app/api/request/[id]/route.ts:4",
        "app/api/restricted/[id]/route.ts:4",
        "app/api/team/[id]/route.ts:4",
        "app/api/written/[id]/route.ts:4",
    ]
