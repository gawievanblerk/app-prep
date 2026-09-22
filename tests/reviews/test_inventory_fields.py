from dpr import reviews, rules
from dpr.discovery.detect import detect
from dpr.reviews.personal import classify, is_person_model, personal_fields
from dpr.walk import RepoIndex
from tests.reviews.helpers import findings_for, write


def context(root):
    reviews.available()
    index = RepoIndex(root)
    return rules.Context(index=index, detection=detect(index))


def test_classify_field_names():
    assert classify("email").key == "identifiers"
    assert classify("firstName").key == "identifiers"
    assert classify("medicalConditions").key == "special"
    assert classify("password_hash").key == "account"
    assert classify("ip_address").key == "technical"
    assert classify("followup_note").key == "content"
    assert classify("id_number").key == "government_ids"
    assert classify("client_id") is None and classify("uploaded_by") is None
    assert classify("name", person=False) is None and classify("name").key == "identifiers"
    assert classify("model_year") is None and classify("steel_grade") is None


def test_person_models_and_models_keyed_to_people(tmp_path):
    write(
        tmp_path,
        "app/models.py",
        "class Client(Base):\n    __tablename__ = 'clients'\n"
        "    name = Column(String)\n    phone = Column(String)\n"
        "class Order(Base):\n    __tablename__ = 'orders'\n"
        "    client_id = Column(String)\n    net_price = Column(Numeric)\n    notes = Column(Text)\n"
        "class ProductType(Base):\n    __tablename__ = 'product_types'\n"
        "    name = Column(String)\n    price = Column(Numeric)\n",
    )
    ctx = context(tmp_path)
    found = sorted((p.model.name, p.field.name, p.category.key) for p in personal_fields(ctx))
    assert found == [
        ("Client", "name", "identifiers"),
        ("Client", "phone", "identifiers"),
        ("Order", "net_price", "financial"),
        ("Order", "notes", "content"),
    ]
    assert is_person_model(ctx.detection.models[0])


def test_special_category_and_catch_all_json(tmp_path):
    write(
        tmp_path,
        "prisma/schema.prisma",
        "model Patient {\n  id Int @id\n  email String @unique\n  diagnosis String?\n"
        "  metadata Json?\n  notes String?\n}\n",
    )
    [special] = findings_for(tmp_path, "inventory", "INV-SPECIAL-CATEGORY")
    assert (special.tag.value, special.severity.value) == ("CONFIRMED", "high")
    assert [str(loc) for loc in special.locations] == ["prisma/schema.prisma:4"]
    [catch_all] = findings_for(tmp_path, "inventory", "INV-CATCHALL-JSON")
    assert (catch_all.title, str(catch_all.locations[0])) == (
        "Catch-all JSON column Patient.metadata",
        "prisma/schema.prisma:5",
    )


def test_text_column_named_metadata_is_not_catch_all_json(tmp_path):
    write(tmp_path, "prisma/schema.prisma", "model Post {\n  id Int @id\n  metadata String?\n}\n")
    assert findings_for(tmp_path, "inventory", "INV-CATCHALL-JSON") == []


def test_children_signals_from_fields_and_age_minimums(tmp_path):
    write(
        tmp_path,
        "app/models.py",
        "class Student(Base):\n    __tablename__ = 'students'\n"
        "    guardian = Column(String)\n    school_name = Column(String)\n",
    )
    write(
        tmp_path,
        "app/schemas.py",
        "class Signup(BaseModel):\n    age: int = Field(ge=13)\n"
        "class Adult(BaseModel):\n    age: int = Field(ge=18)\n",
    )
    write(tmp_path, "web/signup.ts", "const schema = z.object({ age: z.number().int().min(16) })\n")
    found = findings_for(tmp_path, "inventory", "INV-CHILDREN-SIGNAL")
    assert sorted(f.detail for f in found) == [
        "An age check accepts users as young as 13.",
        "Student stores guardian, school_name.",
    ]
    ages = next(f for f in found if f.detail.startswith("An age"))
    assert [str(loc) for loc in ages.locations] == ["app/schemas.py:2", "web/signup.ts:1"]


def test_no_children_signal_for_adult_products(tmp_path):
    write(tmp_path, "app/schemas.py", "class Signup(BaseModel):\n    age: int = Field(ge=18)\n")
    assert findings_for(tmp_path, "inventory", "INV-CHILDREN-SIGNAL") == []


def test_camel_case_model_name_is_split_before_lowercasing(tmp_path):
    write(
        tmp_path,
        "prisma/schema.prisma",
        "model PortalUser {\n  id Int @id\n  emailAddress String\n  fullName String?\n}\n",
    )
    ctx = context(tmp_path)
    found = sorted(p.field.name for p in personal_fields(ctx))
    assert found == ["emailAddress", "fullName"]


def test_id_and_count_suffixed_fields_are_not_classified():
    assert classify("address_line_count") is None
    assert classify("loginCount") is None


def test_ambiguous_terms_need_a_personal_neighbour_or_last_place():
    assert classify("minor_version") is None
    assert classify("race_condition_flag") is None
    assert classify("genetic_algorithm_seed") is None
    assert classify("guardian_angel_flag") is None
    assert classify("guardian_name").key == "children"
    assert classify("is_minor").key == "children"
    assert classify("race").key == "special"
    assert classify("ethnicity").key == "special"


def test_price_total_and_amount_count_only_as_the_head_of_a_field_name():
    assert classify("net_price").key == "financial"
    assert classify("total").key == "financial"
    assert classify("total_amount").key == "financial"
    assert classify("price_tier_label") is None
    assert classify("total_distance") is None
    assert classify("amount_in_stock_units") is None
