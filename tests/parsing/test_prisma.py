from dpr.parsing.prisma import parse_prisma

SCHEMA = """
generator client { provider = "prisma-client-js" }

// a comment with model Fake {
model User {
  id           Int       @id @default(autoincrement())
  email        String    @unique
  passwordHash String    @map("password_hash")
  website      String?   @default("https://example.com") // trailing comment
  invoices     Invoice[]
  @@map("users")
}

enum Role {
  ADMIN
}

model Invoice {
  id     Int  @id
  userId Int
  user   User @relation(fields: [userId], references: [id], onDelete: Cascade)
}
"""


def test_models_and_fields():
    user, invoice = parse_prisma(SCHEMA)
    assert (user.name, user.table, user.line) == ("User", "users", 5)
    names = [f.name for f in user.fields]
    assert names == ["id", "email", "passwordHash", "website", "invoices"]
    by_name = {f.name: f for f in user.fields}
    assert "@default(autoincrement())" in by_name["id"].attributes
    assert by_name["passwordHash"].column == "password_hash"
    assert by_name["website"].optional is True
    assert by_name["website"].attributes == '@default("https://example.com")'
    assert by_name["invoices"].is_list is True
    assert by_name["email"].line == 7
    assert invoice.table == "Invoice"
    assert [f.name for f in invoice.fields] == ["id", "userId", "user"]


SHAPES = """model Account {
  id        Int      @id @default(autoincrement())
  userId    Int      @map("user_id")
  tags      String[]
  nickname  String?
  scores    Int[]    @default([])
  note      String?  @default("a // not a comment") @map("note_text")
  createdAt DateTime @default(now())

  @@map("accounts")
  @@unique([userId, nickname])
  @@index([createdAt])
}

model Plain {
  id   Int
  name String
}
"""


def test_attribute_shapes_and_a_model_without_attributes():
    account, plain = parse_prisma(SHAPES)
    assert (account.name, account.table, account.line) == ("Account", "accounts", 1)
    fields = {f.name: f for f in account.fields}
    assert list(fields) == ["id", "userId", "tags", "nickname", "scores", "note", "createdAt"]
    assert fields["id"].attributes == "@id @default(autoincrement())"
    assert (fields["id"].type, fields["id"].optional, fields["id"].is_list) == ("Int", False, False)
    assert fields["userId"].column == "user_id"
    assert (fields["tags"].type, fields["tags"].is_list, fields["tags"].attributes) == (
        "String",
        True,
        "",
    )
    assert (fields["nickname"].optional, fields["nickname"].is_list) == (True, False)
    assert (fields["scores"].is_list, fields["scores"].attributes) == (True, "@default([])")
    assert (fields["note"].optional, fields["note"].column) == (True, "note_text")
    assert fields["note"].attributes == '@default("a // not a comment") @map("note_text")'
    assert (fields["createdAt"].column, fields["createdAt"].attributes) == (
        "createdAt",
        "@default(now())",
    )
    assert (plain.name, plain.table, plain.line) == ("Plain", "Plain", 15)
    assert [(f.name, f.type, f.attributes, f.column, f.line) for f in plain.fields] == [
        ("id", "Int", "", "id", 16),
        ("name", "String", "", "name", 17),
    ]
