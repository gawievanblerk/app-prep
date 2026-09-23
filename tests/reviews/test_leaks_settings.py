from dpr.api import review
from dpr.report.json_out import render_json
from dpr.report.markdown import render_markdown
from tests.reviews.helpers import findings_for, write

# Built at runtime so no secret-shaped literal sits in the test source.
SIGNING = "dj" + "ango-insecure-" + "k3y-" + "90210"
PARTNER = "partner" + "-key-" + "5521a"
SYNC_PASS = "Sync" + "Pass-" + "7710"
SALT = "hash" + "id-salt-" + "4417"
MAIL_KEY = "key-" + "0a1b2c3d" + "4e5f6071"
BEARER = "tok" + "en-" + "88231abc"
VALUES = (SIGNING, PARTNER, SYNC_PASS, SALT, MAIL_KEY, BEARER)


def repo(root):
    write(
        root,
        "proj/settings/django_settings.py",
        "import os\n"
        f'SECRET_KEY = os.environ.get("SECRET_KEY", "{SIGNING}")\n'
        'INSTALLED_APPS = ["axes"]\n'
        'SESSION_SERIALIZER = "django.contrib.sessions.serializers.PickleSerializer"\n',
    )
    write(
        root,
        "proj/settings/api_settings.py",
        "import os\n"
        f'CLIENT_API_KEY = os.getenv("CLIENT_API_KEY", "{PARTNER}")\n'
        'BASE_URL = os.getenv("BASE_URL", "https://api.example.invalid")\n'
        'SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY", "6Lc-public-site-key")\n'
        'API_KEYS = {"CLIENT": os.getenv("PARTNER_API_KEY_CLIENT", "' + PARTNER + '")}\n'
        'SFTP_PASSWORD = os.getenv("SFTP_PASSWORD", "")\n'
        'RESET_TIMEOUT = os.getenv("PASSWORD_RESET_TIMEOUT", "3600")\n'
        'ACCESS_ID = os.getenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")\n',
    )
    write(
        root,
        "proj/settings/sync_settings.py",
        "import os\n"
        f'SYNC_PASSWORD = os.environ.get("SYNC_PASSWORD") or "{SYNC_PASS}"\n'
        'SMS_PASSWORD = os.environ.get("SMS_PASSWORD", "changeme")\n'
        f'HASHIDS_SALT = "{SALT}"\n'
        "TOKEN_LIFETIME = 3600\n",
    )
    write(
        root,
        "proj/settings/sms_settings.py",
        'import os\nAAT_PASSWORD = os.environ.get("AAT_PASSWORD", "pass")\n',
    )
    write(
        root,
        "proj/site.py",
        f'from hashids import Hashids\nHASHER = Hashids(salt="{SALT}", min_length=6)\n'
        "OTHER = Hashids(salt=settings.SALT)\n",
    )
    write(
        root,
        "proj/ci_settings.py",
        f'INSTALLED_APPS = []\nSECRET_KEY = "{SIGNING}"\nAPI_PASSWORD = "{SYNC_PASS}"\n',
    )
    write(
        root,
        "proj/tests/test_mail.py",
        f'import requests\nrequests.post("u", auth=("api", "{MAIL_KEY}"))\n',
    )
    write(
        root,
        "proj/views.py",
        "import requests\nfrom requests.auth import HTTPBasicAuth\n"
        f'MAILGUN = "{MAIL_KEY}"\n\n'
        "def send():\n"
        '    requests.post("https://api.mailgun.invalid", auth=("api", MAILGUN))\n'
        f'    requests.get("u", auth=HTTPBasicAuth("svc", "{SYNC_PASS}"))\n'
        f'    requests.get("u", headers={{"Authorization": "Bearer {BEARER}"}})\n'
        "    requests.get('u', auth=('api', settings.MAILGUN_KEY))\n"
        "    requests.get('u', headers={'Authorization': f'Bearer {token}'})\n"
        "    requests.get('u', auth=('api', ''))\n",
    )
    return root


def by_file(root, rule_id):
    return {f.locations[0].file: f for f in findings_for(root, "leaks", rule_id)}


def test_secret_fallbacks_one_finding_per_file(tmp_path):
    found = by_file(repo(tmp_path), "LEAK-SECRET-ENV-DEFAULT")
    assert set(found) == {
        "proj/settings/django_settings.py",
        "proj/settings/api_settings.py",
        "proj/settings/sync_settings.py",
        "proj/settings/sms_settings.py",
        "proj/site.py",
    }
    django = found["proj/settings/django_settings.py"]
    assert (django.severity.value, django.tag.value) == ("critical", "CONFIRMED")
    assert "SECRET_KEY" in django.detail
    api = found["proj/settings/api_settings.py"]
    assert api.severity.value == "high"
    assert "CLIENT_API_KEY, PARTNER_API_KEY_CLIENT fall back" in api.detail
    assert "SECRET_KEY falls back" in django.detail
    assert [str(loc) for loc in api.locations] == [
        "proj/settings/api_settings.py:2",
        "proj/settings/api_settings.py:5",
    ]
    sync = found["proj/settings/sync_settings.py"]
    assert "SYNC_PASSWORD, SMS_PASSWORD, HASHIDS_SALT" in sync.detail
    assert "SMS_PASSWORD looks like a placeholder" in sync.detail
    assert sync.severity.value == "high"
    assert found["proj/settings/sms_settings.py"].severity.value == "low"
    assert [str(loc) for loc in found["proj/site.py"].locations] == ["proj/site.py:2"]


def test_literal_http_credentials(tmp_path):
    found = by_file(repo(tmp_path), "LEAK-LITERAL-HTTP-AUTH")
    assert set(found) == {"proj/views.py"}
    finding = found["proj/views.py"]
    assert [loc.line for loc in finding.locations] == [6, 7, 8]
    assert "HTTPBasicAuth" in finding.detail and "Authorization header" in finding.detail


def test_values_never_printed(tmp_path):
    report = review(repo(tmp_path))
    text = render_markdown(report) + render_json(report)
    assert "LEAK-SECRET-ENV-DEFAULT" in text and "LEAK-LITERAL-HTTP-AUTH" in text
    for value in VALUES:
        assert value not in text


def test_long_value_with_a_placeholder_prefix_is_a_secret(tmp_path):
    sandbox = "test" + "_4f9a2c7e" + "1b3d5f7a9c"
    write(
        tmp_path,
        "proj/settings.py",
        f'import os\nKEY = os.getenv("PARTNER_API_KEY", "{sandbox}")\n',
    )
    [finding] = findings_for(tmp_path, "leaks", "LEAK-SECRET-ENV-DEFAULT")
    assert finding.severity.value == "high" and "placeholder" not in finding.detail
