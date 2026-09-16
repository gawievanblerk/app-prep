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
