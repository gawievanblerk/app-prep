import json

import dpr
from tests.reviews.helpers import write


def test_render_json_shape(tmp_path):
    write(tmp_path, ".env.example", "NEXT_PUBLIC_SUPABASE_ANON_KEY=\nNEXT_PUBLIC_ADMIN_SECRET=\n")
    write(
        tmp_path, "supabase/migrations/1.sql", "create table public.notes (id int, user_id uuid);"
    )
    write(tmp_path, "app/api/notes/route.ts", "export async function GET() {}\n")
    report = dpr.review(tmp_path)
    data = json.loads(dpr.render_json(report))
    assert list(data)[:2] == ["schema_version", "meta"]
    assert data["schema_version"] == 1
    assert set(data) == {
        "schema_version",
        "meta",
        "detection",
        "findings",
        "sections",
        "questions",
        "not_covered",
        "answered",
        "register",
        "standards",
    }
    assert "schema" not in data["detection"] and "packages" not in data["detection"]
    [route] = data["detection"]["routes"]
    assert set(route) == {
        "method",
        "path",
        "file",
        "line",
        "framework",
        "is_public_form",
        "wrappers",
    }
    assert route["wrappers"] == []
    first = data["findings"][0]
    assert first["tag"] in ("CONFIRMED", "INFERRED", "UNVERIFIED")
    assert isinstance(first["locations"][0], dict) and {"file", "line"} <= set(
        first["locations"][0]
    )
    assert data["meta"]["applicability"][1] == ["rls", "runs"]
    assert data["questions"][0]["question"]["id"]


def test_package_exports():
    assert callable(dpr.review) and callable(dpr.discover)
    assert callable(dpr.render_markdown) and callable(dpr.render_json)
