from dpr.api import review
from dpr.parsing.pymigrations import migration_folders, python_migration_state
from dpr.walk import RepoIndex
from tests.reviews.helpers import write


def test_migration_folders_for_each_tool(tmp_path):
    write(tmp_path, "api/alembic/versions/001_users.py", "def upgrade():\n    pass\n")
    write(tmp_path, "shop/orders/migrations/0001_initial.py", "class Migration: pass\n")
    write(tmp_path, "shop/orders/migrations/__init__.py", "")
    write(tmp_path, "prisma/migrations/20240101_init/migration.sql", "create table a (id int);")
    write(tmp_path, "drizzle/0000_init.sql", "create table b (id int);")
    write(tmp_path, "supabase/migrations/1.sql", "create table c (id int);")
    write(tmp_path, "docs/migrations.md", "notes\n")
    assert migration_folders(RepoIndex(tmp_path)) == [
        ("api/alembic/versions", "alembic"),
        ("drizzle", "drizzle"),
        ("prisma/migrations", "prisma"),
        ("shop/orders/migrations", "django"),
        ("supabase/migrations", "supabase"),
    ]


def test_sql_run_from_python_migrations(tmp_path):
    write(
        tmp_path,
        "api/alembic/versions/002_rls.py",
        "import sqlalchemy as sa\nfrom alembic import op\n\n"
        "def upgrade():\n"
        "    op.create_table('notes', sa.Column('id', sa.Integer()))\n"
        "    op.execute('ALTER TABLE notes ENABLE ROW LEVEL SECURITY')\n"
        '    op.execute(sa.text("CREATE POLICY own ON notes USING (owner = current_user)"))\n'
        "    op.execute('GRANT SELECT ON notes TO app_ro; GRANT ALL ON notes TO app_rw')\n"
        "    op.execute(f'UPDATE notes SET x = {1}')\n",
    )
    write(
        tmp_path,
        "shop/orders/migrations/0002_grants.py",
        "from django.db import migrations\n\nclass Migration(migrations.Migration):\n"
        "    operations = [migrations.RunSQL('REVOKE ALL ON orders_order FROM PUBLIC')]\n",
    )
    state = python_migration_state(RepoIndex(tmp_path))
    assert state.tables["public.notes"].rls is True
    assert str(state.tables["public.notes"].rls_location) == "api/alembic/versions/002_rls.py:6"
    assert [p.name for p in state.policies_for("public.notes")] == ["own"]
    assert [(g.action, g.roles, str(g.location)) for g in state.grants] == [
        ("grant", ("app_ro",), "api/alembic/versions/002_rls.py:8"),
        ("grant", ("app_rw",), "api/alembic/versions/002_rls.py:8"),
        ("revoke", ("public",), "shop/orders/migrations/0002_grants.py:4"),
    ]


def test_orm_models_make_the_database_review_applicable(tmp_path):
    write(tmp_path, "requirements.txt", "fastapi\nsqlalchemy\n")
    write(
        tmp_path,
        "app/models.py",
        "class Note(Base):\n    __tablename__ = 'notes'\n    id = Column(Integer, primary_key=True)\n",
    )
    report = review(tmp_path, reviews=["rls"])
    assert "rls" in report.sections
    assert dict(report.meta.applicability)["rls"] == "runs"


def test_migration_folder_alone_makes_it_applicable(tmp_path):
    write(tmp_path, "api/alembic/versions/001.py", "def upgrade():\n    pass\n")
    assert "rls" in review(tmp_path, reviews=["rls"]).sections
