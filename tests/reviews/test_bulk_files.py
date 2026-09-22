from tests.fixture_builder import git
from tests.reviews.helpers import findings_for, write

ROUTE = (
    "from fastapi import APIRouter\nfrom pydantic import BaseModel, Field\n\n"
    "router = APIRouter()\nBATCH = 20\n\n\n"
    "class BulkRequest(BaseModel):\n    ids: list[str] = Field(..., max_length={cap})\n\n\n"
    "@router.post('/reports/bulk')\nasync def bulk(payload: BulkRequest):\n"
    "    unique = list(dict.fromkeys(payload.ids))\n{body}"
)
LOOP = "    for item in unique:\n        await service.generate_pdf(item)\n"


def bulk_app(root, cap="200", body=LOOP):
    write(root, "api/requirements.txt", "fastapi\npydantic\n")
    write(root, "api/app/routes/reports.py", ROUTE.format(cap=cap, body=body))
    return root


def test_large_list_driving_a_render_loop_is_reported(tmp_path):
    bulk_app(tmp_path)
    [finding] = findings_for(tmp_path, "abuse", "ABUSE-BULK-UNBOUNDED")
    assert [str(loc) for loc in finding.locations] == [
        "api/app/routes/reports.py:9",
        "api/app/routes/reports.py:15",
    ]
    assert finding.title == "POST /reports/bulk does one render or send per item, up to 200 items"
    assert "service.generate_pdf" in finding.detail
    assert (finding.severity.value, finding.tag.value) == ("low", "CONFIRMED")


def test_list_with_no_cap_is_reported(tmp_path):
    bulk_app(tmp_path)
    write(
        tmp_path,
        "api/app/routes/reports.py",
        ROUTE.format(cap="0", body=LOOP).replace(" = Field(..., max_length=0)", ""),
    )
    [finding] = findings_for(tmp_path, "abuse", "ABUSE-BULK-UNBOUNDED")
    assert finding.title.endswith("with no size cap")


def test_small_cap_truncation_or_cheap_loop_is_not_reported(tmp_path):
    bulk_app(tmp_path, cap="25")
    assert findings_for(tmp_path, "abuse", "ABUSE-BULK-UNBOUNDED") == []
    truncated = "    unique = unique[:BATCH]\n" + LOOP
    bulk_app(tmp_path, body=truncated)
    assert findings_for(tmp_path, "abuse", "ABUSE-BULK-UNBOUNDED") == []
    cheap = "    for item in unique:\n        results.append(Result(id=item))\n"
    bulk_app(tmp_path, body=cheap)
    assert findings_for(tmp_path, "abuse", "ABUSE-BULK-UNBOUNDED") == []


def committed(root):
    git(root, "init", "-q")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "initial")


def test_committed_reports_databases_and_screenshots_are_grouped(tmp_path):
    write(tmp_path, "docs/uat/orders_report.pdf", "%PDF-1.4\n")
    write(tmp_path, "docs/uat/screenshot_orders.png", "png")
    write(tmp_path, "data/app.sqlite3", "db")
    write(tmp_path, "docs/brand/logo.png", "png")
    write(tmp_path, "docs/architecture.pdf", "%PDF-1.4\n")
    write(tmp_path, "web/public/hero.jpg", "jpg")
    committed(tmp_path)
    [finding] = findings_for(tmp_path, "leaks", "LEAK-COMMITTED-DATA-FILE")
    assert [str(loc) for loc in finding.locations] == [
        "data/app.sqlite3:1",
        "docs/uat/orders_report.pdf:1",
    ]
    assert finding.title.startswith("Committed 3 document, spreadsheet or database file(s)")
    assert "docs/uat (2)" in finding.detail
    assert (finding.severity.value, finding.tag.value) == ("medium", "INFERRED")


def test_untracked_or_asset_files_are_not_reported(tmp_path):
    write(tmp_path, "docs/brand/logo.png", "png")
    committed(tmp_path)
    write(tmp_path, "exports/customers_report.pdf", "%PDF-1.4\n")
    assert findings_for(tmp_path, "leaks", "LEAK-COMMITTED-DATA-FILE") == []


def test_real_looking_emails_in_tests_are_counted_but_not_printed(tmp_path):
    domain = "north" + "field-farms.com"
    write(
        tmp_path,
        "api/app/config.py",
        "SUPPORT = 'help@ourapp.io'\nSITE = 'https://app.ourapp.io'\n",
    )
    write(
        tmp_path,
        "api/tests/test_mail.py",
        "OWNER = 'ops@ourapp.io'\nOTHER = 'a@example.com'\nFAKE = 'b@shop.test'\n"
        f"REAL = 'jane.doe@{domain}'\nALSO = 'sam.lee@{domain}'\n",
    )
    write(tmp_path, "api/app/mail.py", f"TO = 'jane.doe@{domain}'\n")
    [finding] = findings_for(tmp_path, "leaks", "LEAK-COMMITTED-DATA-FILE")
    assert [str(loc) for loc in finding.locations] == ["api/tests/test_mail.py:4"]
    assert finding.detail.startswith("2 email addresses in 1 test or documentation files")
    assert domain not in finding.detail and "jane" not in finding.detail


def test_reserved_placeholder_and_own_domains_are_not_reported(tmp_path):
    write(tmp_path, "api/app/settings.py", "FROM = 'noreply@ourapp.io'\n")
    write(
        tmp_path,
        "docs/guide.md",
        "Write to a@example.org, b@x.com, c@company.com, d@ourapp.io or e@db.postgres.database.azure.com\n",
    )
    assert findings_for(tmp_path, "leaks", "LEAK-COMMITTED-DATA-FILE") == []


def test_nearest_schema_never_crosses_app_roots(tmp_path):
    from dpr import reviews, rules
    from dpr.discovery.detect import detect
    from dpr.reviews.abuse_bulk import list_fields, nearest
    from dpr.walk import RepoIndex

    schema = (
        "from pydantic import BaseModel, Field\n\n\n"
        "class BulkRequest(BaseModel):\n    ids: list[str] = Field(..., max_length={cap})\n"
    )
    write(tmp_path, "apps/api/requirements.txt", "fastapi\npydantic\n")
    write(tmp_path, "apps/api-worker/requirements.txt", "fastapi\npydantic\n")
    write(tmp_path, "apps/api-worker/app/routes/schemas.py", schema.format(cap=900))
    route = "apps/api/app/routes/reports.py"

    def pick(root):
        reviews.available()
        index = RepoIndex(root)
        ctx = rules.Context(index=index, detection=detect(index))
        return nearest(ctx, list_fields(ctx)["BulkRequest"], route)

    assert pick(tmp_path) == {}
    write(tmp_path, "apps/api/app/schemas.py", schema.format(cap=50))
    [(cap, where)] = pick(tmp_path).values()
    assert (cap, str(where)) == (50, "apps/api/app/schemas.py:5")
