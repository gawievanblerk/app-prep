from dpr.parsing.routes_py import decorator_routes
from dpr.walk import RepoIndex
from tests.reviews.helpers import write


def test_router_and_blueprint_prefixes(tmp_path):
    write(
        tmp_path,
        "api/auth.py",
        "from fastapi import APIRouter\nrouter = APIRouter(prefix='/auth/', tags=['a'])\n"
        "other = APIRouter()\n"
        "@router.post('/register')\nasync def register(): ...\n"
        "@other.get('/health')\nasync def health(): ...\n",
    )
    write(
        tmp_path,
        "web/views.py",
        "from flask import Blueprint\nbp = Blueprint('notes', __name__, url_prefix='/notes')\n"
        "@bp.route('/<int:note_id>')\ndef note(note_id): ...\n",
    )
    paths = sorted(r.path for r in decorator_routes(RepoIndex(tmp_path)))
    assert paths == ["/auth/register", "/health", "/notes/<int:note_id>"]
