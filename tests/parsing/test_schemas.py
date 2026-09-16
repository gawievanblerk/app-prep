from dpr.parsing.schemas import extract_models, find_model
from dpr.parsing.sqlschema import load_schema
from dpr.walk import RepoIndex


def write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def build(tmp_path):
    write(tmp_path, "prisma/schema.prisma", """
model User {
  id    Int    @id @default(autoincrement())
  email String @unique
  @@map("users")
}
""")
    write(tmp_path, "prisma/migrations/1_init/migration.sql",
          'create table "users" (id serial primary key, email text);')
    write(tmp_path, "supabase/migrations/1.sql", "create table public.documents (id uuid, user_id uuid);")
    write(tmp_path, "billing/models.py", """
from django.db import models

class Invoice(models.Model):
    amount = models.IntegerField()
    number = models.CharField(max_length=20, unique=True)
    owner = models.ForeignKey("auth.User", on_delete=models.CASCADE)

class Base(models.Model):
    class Meta:
        abstract = True

class Note(models.Model):
    uid = models.UUIDField(primary_key=True)
    class Meta:
        db_table = "notes"
""")
    write(tmp_path, "svc/db.py", """
from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

class Account(Base):
    __tablename__ = "accounts"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"))
""")
    write(tmp_path, "src/db/schema.ts", """
import { pgTable, serial, text, uuid } from "drizzle-orm/pg-core"

export const profiles = pgTable("profiles", {
  id: serial("id").primaryKey(),
  fullName: text("full_name").notNull(),
  email: text().unique(),
  orgId: uuid("org_id"),
})
""")
    index = RepoIndex(tmp_path)
    return extract_models(index, load_schema(index))


def test_sources_and_prisma_sql_dedupe(tmp_path):
    models = build(tmp_path)
    assert [(m.source, m.name, m.table) for m in models] == [
        ("prisma", "User", "users"),
        ("sql", "documents", "public.documents"),
        ("django", "Invoice", "billing_invoice"),
        ("django", "Note", "notes"),
        ("sqlalchemy", "Account", "accounts"),
        ("drizzle", "profiles", "profiles"),
    ]


def test_fields(tmp_path):
    models = {m.name: m for m in build(tmp_path)}
    user = models["User"]
    assert [(f.name, f.unique, f.autoincrement) for f in user.fields] == [
        ("id", True, True), ("email", True, False),
    ]
    invoice = models["Invoice"]
    assert invoice.field_names() == ["id", "amount", "number", "owner"]
    assert invoice.fields[0].autoincrement is True
    assert invoice.fields[2].unique is True
    assert models["Note"].field_names() == ["uid"]
    account = models["Account"]
    assert [(f.name, f.type, f.unique, f.autoincrement) for f in account.fields] == [
        ("id", "Integer", True, True), ("email", "String", True, False), ("org_id", "Mapped[int]", False, False),
    ]
    profiles = models["profiles"]
    assert [(f.name, f.type, f.unique, f.autoincrement) for f in profiles.fields] == [
        ("id", "serial", True, True), ("full_name", "text", False, False),
        ("email", "text", True, False), ("org_id", "uuid", False, False),
    ]
    assert profiles.fields[1].location.line == 6


def test_find_model(tmp_path):
    models = build(tmp_path)
    assert find_model(models, "user").name == "User"
    assert find_model(models, "invoices").name == "Invoice"
    assert find_model(models, "documents").source == "sql"
    assert find_model(models, "missing") is None
