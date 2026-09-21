from tests.reviews.helpers import findings_for, write

DEPS = (
    "from typing import Annotated\nfrom fastapi import Depends\n\n"
    "CurrentUser = Annotated[dict, Depends(get_current_user)]\n"
)
ROLE_DEPS = DEPS + "AdminUser = Annotated[dict, Depends(get_admin_user)]\n"
CHAT = (
    "import anthropic\nfrom fastapi import APIRouter\nfrom app.deps import CurrentUser\n\n"
    "client = anthropic.Anthropic()\nrouter = APIRouter()\n\n"
    "@router.post('/chat')\nasync def chat(current_user: CurrentUser, body: dict):\n"
    "    return client.messages.create(model='m', max_tokens=10, messages=body['m'])\n"
)


def paid_app(root, deps):
    write(root, "api/requirements.txt", "fastapi\nanthropic\n")
    write(root, "api/app/deps.py", deps)
    write(root, "api/app/routes/chat.py", CHAT)
    return root


def test_paid_route_for_any_signed_in_user_is_reported_when_roles_exist(tmp_path):
    paid_app(tmp_path, ROLE_DEPS)
    [finding] = findings_for(tmp_path, "abuse", "ABUSE-PAID-ANY-ROLE")
    assert str(finding.locations[0]) == "api/app/routes/chat.py:9"
    assert (finding.severity.value, finding.tag.value) == ("medium", "INFERRED")
    assert "get_admin_user" in finding.detail
    assert finding.proof_needed


def test_paid_route_is_not_reported_when_the_app_has_no_roles(tmp_path):
    paid_app(tmp_path, DEPS)
    assert findings_for(tmp_path, "abuse", "ABUSE-PAID-ANY-ROLE") == []


def test_role_checks_in_another_app_root_do_not_count(tmp_path):
    paid_app(tmp_path, DEPS)
    write(tmp_path, "admin/requirements.txt", "fastapi\n")
    write(tmp_path, "admin/app/deps.py", ROLE_DEPS)
    assert findings_for(tmp_path, "abuse", "ABUSE-PAID-ANY-ROLE") == []


def test_role_checks_in_a_sibling_root_do_not_count_for_a_repository_root_app(tmp_path):
    """A paid route whose own app root is the repository root ("") must not pick up role
    dependencies from a sibling root through a string-prefix test that matches every path."""
    write(tmp_path, "requirements.txt", "fastapi\nanthropic\n")
    write(tmp_path, "app/deps.py", DEPS)
    write(tmp_path, "app/routes/chat.py", CHAT)
    write(tmp_path, "admin/requirements.txt", "fastapi\n")
    write(tmp_path, "admin/app/deps.py", ROLE_DEPS)
    findings = findings_for(tmp_path, "abuse", "ABUSE-PAID-ANY-ROLE")
    assert findings == []
    assert not any("get_admin_user" in f.detail for f in findings)


def test_paid_route_behind_a_role_is_not_reported(tmp_path):
    paid_app(tmp_path, ROLE_DEPS + "StaffUser = Annotated[dict, Depends(get_staff_user)]\n")
    route = CHAT.replace("CurrentUser", "StaffUser")
    write(tmp_path, "api/app/routes/chat.py", route)
    assert findings_for(tmp_path, "abuse", "ABUSE-PAID-ANY-ROLE") == []


def main_with(root, call):
    write(root, "api/requirements.txt", "fastapi\n")
    write(root, "api/app/main.py", f"from fastapi import FastAPI\n\napp = FastAPI(\n{call})\n")


def test_schema_left_on_when_docs_are_gated_is_reported(tmp_path):
    main_with(
        tmp_path,
        "    openapi_url=f'{settings.prefix}/openapi.json',\n"
        "    docs_url='/docs' if settings.debug else None,\n",
    )
    [finding] = findings_for(tmp_path, "baseline", "BASE-OPENAPI-ALWAYS-ON")
    assert str(finding.locations[0]) == "api/app/main.py:4"
    assert (finding.severity.value, finding.tag.value) == ("low", "CONFIRMED")
    assert "fixed path" in finding.detail


def test_default_schema_with_docs_off_is_reported_at_the_call(tmp_path):
    main_with(tmp_path, "    docs_url=None, redoc_url=None,\n")
    [finding] = findings_for(tmp_path, "baseline", "BASE-OPENAPI-ALWAYS-ON")
    assert str(finding.locations[0]) == "api/app/main.py:3"
    assert "left at its default" in finding.detail


def test_schema_gated_like_the_docs_or_docs_left_on_is_not_reported(tmp_path):
    main_with(
        tmp_path,
        "    openapi_url='/openapi.json' if settings.debug else None,\n"
        "    docs_url='/docs' if settings.debug else None,\n",
    )
    assert findings_for(tmp_path, "baseline", "BASE-OPENAPI-ALWAYS-ON") == []
    main_with(tmp_path, "    title='api',\n")
    assert findings_for(tmp_path, "baseline", "BASE-OPENAPI-ALWAYS-ON") == []
    main_with(tmp_path, "    docs_url=None, openapi_url=settings.schema_path,\n")
    assert findings_for(tmp_path, "baseline", "BASE-OPENAPI-ALWAYS-ON") == []


EXPORTS = (
    "from fastapi.responses import FileResponse, StreamingResponse\n"
    "from app.deps import CurrentUser\n\n"
    "@router.get('/clients/export')\nasync def export(current_user: CurrentUser):\n"
    "    return StreamingResponse(rows(), media_type='text/csv')\n\n"
    "@router.get('/files/{file_id}')\nasync def download(file_id: str, current_user: CurrentUser):\n"
    "    return FileResponse(path_for(file_id))\n\n"
    "@router.post('/chat')\nasync def chat(current_user: CurrentUser):\n"
    "    return StreamingResponse(tokens(), media_type='text/event-stream')\n\n"
    "@router.get('/public/brochure.pdf')\nasync def brochure():\n"
    "    return FileResponse('brochure.pdf')\n"
)


def test_exports_without_an_audit_write_are_grouped_per_app(tmp_path):
    write(tmp_path, "api/requirements.txt", "fastapi\n")
    write(tmp_path, "api/app/deps.py", DEPS)
    write(tmp_path, "api/app/routes/exports.py", EXPORTS)
    [finding] = findings_for(tmp_path, "owasp", "OWASP-A09-NO-READ-AUDIT")
    assert [str(loc) for loc in finding.locations] == [
        "api/app/routes/exports.py:5",
        "api/app/routes/exports.py:9",
    ]
    assert (finding.severity.value, finding.tag.value) == ("low", "INFERRED")
    assert finding.title == "Exports and downloads in api leave no audit record"
    assert "no audit table" in finding.detail


def test_exports_that_write_an_audit_record_are_not_reported(tmp_path):
    write(tmp_path, "api/requirements.txt", "fastapi\n")
    write(tmp_path, "api/app/deps.py", DEPS)
    audited = EXPORTS.replace(
        "    return StreamingResponse(rows()",
        "    await audit.record(current_user.id, 'clients.export')\n"
        "    return StreamingResponse(rows()",
    ).replace(
        "    return FileResponse(path_for(file_id))",
        "    await log_activity(current_user, 'file.download', file_id)\n"
        "    return FileResponse(path_for(file_id))",
    )
    write(tmp_path, "api/app/routes/exports.py", audited)
    assert findings_for(tmp_path, "owasp", "OWASP-A09-NO-READ-AUDIT") == []


def test_express_download_names_the_existing_audit_model(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"express": "4", "@prisma/client": "5"}}')
    write(
        tmp_path,
        "prisma/schema.prisma",
        "model AuditLog {\n  id String @id\n  action String\n}\n",
    )
    write(
        tmp_path,
        "src/routes/reports.ts",
        "router.get('/reports/:id/pdf', authenticate, async (req, res) => {\n"
        "  res.setHeader('Content-Type', 'application/pdf')\n  res.send(await render(req.params.id))\n"
        "})\n",
    )
    [finding] = findings_for(tmp_path, "owasp", "OWASP-A09-NO-READ-AUDIT")
    assert str(finding.locations[0]) == "src/routes/reports.ts:1"
    assert "audit tables (AuditLog)" in finding.detail
    assert finding.title == "Exports and downloads in this repository leave no audit record"
