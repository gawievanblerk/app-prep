from dpr.api import review
from dpr.report.markdown import render_markdown
from tests.reviews.helpers import write


def app(root):
    write(
        root,
        "api/app/deps.py",
        "from typing import Annotated\nfrom fastapi import Depends\n"
        "CurrentUser = Annotated[dict, Depends(get_current_user)]\n"
        "AdminUser = Annotated[dict, Depends(get_admin_user)]\n",
    )
    write(
        root,
        "api/app/models.py",
        "class Doc(Base):\n    __tablename__ = 'docs'\n    id = Column(String, primary_key=True)\n"
        "    owner_id = Column(String)\n",
    )
    write(
        root,
        "api/app/routes.py",
        "from fastapi import APIRouter\nfrom app.deps import AdminUser, CurrentUser\n"
        "router = APIRouter(prefix='/docs')\n"
        "@router.get('/{doc_id}')\nasync def any_doc(doc_id: str, me: CurrentUser, db=None):\n"
        "    return await db.get(Doc, doc_id)\n"
        "@router.get('/{doc_id}/mine')\nasync def mine(doc_id: str, me: CurrentUser, db=None):\n"
        "    return await db.execute(select(Doc).where(Doc.id == doc_id, Doc.owner_id == me.id))\n"
        "@router.get('')\nasync def listing(me: CurrentUser):\n    return []\n"
        "@router.delete('/{doc_id}')\nasync def purge(doc_id: str, boss: AdminUser, db=None):\n"
        "    return await db.get(Doc, doc_id)\n"
        "@router.get('/health')\nasync def health():\n    return {}\n",
    )
    return root


def test_route_table_and_categories(tmp_path):
    report = review(app(tmp_path), reviews=["owasp"])
    parts = {p.title: p for p in report.sections["owasp"].parts}
    assert list(parts) == [
        "How to read this section",
        "Findings",
        "Route classification",
        "Categories reviewed",
    ]
    access = {(row[0], row[1]): row[3] for row in parts["Route classification"].rows}
    assert access == {
        ("GET", "/docs/{doc_id}"): "authenticated, no ownership check found",
        ("GET", "/docs/{doc_id}/mine"): "authenticated and ownership-checked",
        ("GET", "/docs"): "authenticated",
        ("DELETE", "/docs/{doc_id}"): "admin",
        ("GET", "/docs/health"): "public",
    }
    body = parts["Categories reviewed"].body
    assert "- A01 Broken access control: 1 finding(s) above." in body
    assert (
        "- A06 Vulnerable and outdated components: no finding from this review's own rules. Not run"
        in body
    )
    text = render_markdown(report)
    assert "## 5. OWASP sweep" in text and "#### FINDING 1:" in text


def test_audit_option_is_recorded(tmp_path):
    report = review(app(tmp_path), reviews=["owasp"], with_audit=True)
    assert (
        "Dependency audit not run: the audit adapters arrive in a later version"
        in report.not_covered
    )
