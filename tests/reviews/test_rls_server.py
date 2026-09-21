from dpr import reviews, rules
from dpr.api import review
from dpr.discovery.detect import detect
from dpr.report.markdown import render_markdown
from dpr.walk import RepoIndex
from tests.fixture_builder import build
from tests.reviews.helpers import write


def section(root):
    reviews.available()
    index = RepoIndex(root)
    ctx = rules.Context(index=index, detection=detect(index))
    return {p.title: p for p in reviews.available()["rls"].run(ctx).parts}


def two_apis(root):
    write(root, "azure-pipelines.yml", "steps:\n  - script: cd api && pytest\n")
    write(root, "api/requirements.txt", "fastapi\nsqlalchemy\nasyncpg\n")
    write(
        root,
        "api/app/models.py",
        "class User(Base):\n    __tablename__ = 'users'\n    id = Column(String, primary_key=True)\n"
        "class Note(Base):\n    __tablename__ = 'notes'\n    id = Column(String, primary_key=True)\n",
    )
    write(
        root,
        "api/alembic/versions/002_rls.py",
        "from alembic import op\n\ndef upgrade():\n"
        "    op.execute('ALTER TABLE notes ENABLE ROW LEVEL SECURITY')\n"
        "    op.execute('GRANT SELECT ON notes TO reporting')\n",
    )
    write(root, "api/startup.sh", "alembic upgrade head\ngunicorn app.main:app\n")
    write(root, "worker/requirements.txt", "sqlalchemy\n")
    write(
        root,
        "worker/models.py",
        "class Job(Base):\n    __tablename__ = 'jobs'\n    id = Column(String, primary_key=True)\n",
    )
    write(
        root,
        "infra/main.tf",
        'resource "azurerm_postgresql_flexible_server" "db" {\n  name = "db"\n}\n',
    )
    return root


def test_reduced_section_groups_tables_per_app_and_rls_state(tmp_path):
    parts = section(two_apis(tmp_path))
    rows = parts["Table protection status"].rows
    assert [r[:3] for r in rows] == [
        ("api: users", "no", "0"),
        ("api: notes", "yes", "0"),
        ("worker: jobs", "no", "0"),
    ]
    assert rows[0][3:5] == (
        "no, no client-side key",
        "protected only by application code and database credentials",
    )
    assert rows[1][5] == "models in api/app; RLS or policy statements found in api/alembic/versions"


def test_least_privilege_sql_grants_migrations_and_cloud_commands(tmp_path):
    parts = section(two_apis(tmp_path))
    body = parts["Missing policies (runnable SQL)"].body
    assert "create role app_runtime login" in body
    assert (
        "- `api/alembic/versions/002_rls.py:5`: grant select on table public.notes to reporting"
        in body
    )
    assert "Move migrations to a deploy step first: `api/startup.sh:1`." in body
    confirm = parts["How to confirm from outside the app"].body
    assert "select current_user;" in confirm
    assert "az postgres flexible-server firewall-rule list" in confirm


def test_migration_evidence_in_a_sibling_root_does_not_count_for_a_repository_root_app(tmp_path):
    write(tmp_path, "requirements.txt", "flask\nsqlalchemy\n")
    write(
        tmp_path,
        "app/models.py",
        "class User(Base):\n    __tablename__ = 'users'\n    id = Column(String, primary_key=True)\n",
    )
    write(tmp_path, "migrations/0001_init.sql", "-- noop\n")
    write(tmp_path, "admin/requirements.txt", "flask\n")
    write(tmp_path, "admin/migrations/0001_init.sql", "-- noop\n")
    rows = section(tmp_path)["Table protection status"].rows
    [row] = rows
    assert row[:3] == ("repository root: users", "no", "0")
    assert row[5] == "models in app; no RLS or policy statements in migrations"


def test_mysql_and_unknown_engines(tmp_path):
    write(tmp_path, "requirements.txt", "flask\npymysql\nsqlalchemy\n")
    write(
        tmp_path,
        "app/models.py",
        "class User(Base):\n    __tablename__ = 'users'\n    id = Column(String, primary_key=True)\n",
    )
    assert "create user 'app_runtime'" in section(tmp_path)["Missing policies (runnable SQL)"].body
    write(tmp_path, "requirements.txt", "flask\nsqlalchemy\n")
    body = section(tmp_path)["Missing policies (runnable SQL)"].body
    assert "database engine was not recognised" in body


def test_exposure_findings_are_cross_referenced_in_section_2(tmp_path):
    root = build("express-prisma", tmp_path)
    text = render_markdown(review(root))
    part = text[text.index("### Database exposure and privilege") :]
    part = part[: part.index("### Missing policies")]
    assert "(medium, CONFIRMED, reported in review 4): `infra/main.tf:4`" in part


def test_refs_part_without_findings_prints_its_note(tmp_path):
    write(tmp_path, "requirements.txt", "fastapi\nsqlalchemy\n")
    write(
        tmp_path,
        "app/models.py",
        "class User(Base):\n    __tablename__ = 'users'\n    id = Column(String, primary_key=True)\n",
    )
    text = render_markdown(review(tmp_path, reviews=["rls"]))
    assert "No database firewall, public access or admin connection string finding" in text
