from tests.reviews.helpers import findings_for, write

AUTH = (
    "import hmac\nfrom django.conf import settings\n"
    "class StagingAuth:\n"
    "    def authenticate(self, request):\n"
    "        token = request.META.get('HTTP_X_AUTHTOKEN').split()[1]\n"
    "        expected = settings.STAGING_PROD_TOKEN\n"
    "        if token != expected:\n            raise Failed()\n"
    "def webhook(request):\n"
    "    digest = hmac.new(KEY, request.body, 'sha256').hexdigest()\n"
    "    if request.headers['X-Signature'] == digest:\n        return ok()\n"
    "def safe(request):\n"
    "    if not hmac.compare_digest(request.headers['X-Key'], settings.API_KEY):\n"
    "        raise Failed()\n"
    "def status(request):\n"
    "    if request.GET.get('state') == settings.DEFAULT_STATE:\n        return ok()\n"
    "    if request.GET.get('kind') == 'token':\n        return ok()\n"
)


def test_secrets_compared_with_equality(tmp_path):
    write(tmp_path, "api/authentication.py", AUTH)
    write(tmp_path, "tests/test_auth.py", AUTH)
    [finding] = findings_for(tmp_path, "auth", "AUTH-TOKEN-COMPARE")
    assert finding.title == "Request tokens are compared with == in api/authentication.py"
    assert [loc.line for loc in finding.locations] == [7, 11]
    assert (finding.tag.value, finding.severity.value) == ("CONFIRMED", "low")
