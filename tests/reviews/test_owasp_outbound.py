from tests.reviews.helpers import findings_for, write

USSD = """
import requests
from django.conf import settings


class UssdConsent(models.Model):
    def request_consent(self):
        data = {
            "username": settings.NI_USSD_USERNAME,
            "password": settings.NI_USSD_PASSWORD,
            "msisdn": self.cleaned_phone_number,
        }
        response = requests.get("http://ussdpush.provider.co.za/push/", params=data)
        return response


def health():
    requests.get("http://localhost:8000/health", timeout=2)
    requests.get("http://10.0.0.5/ping", timeout=2)
    requests.get("https://api.provider.co.za/ok", timeout=5)
"""

VICIDIAL_SETTINGS = """
import os

VICIDIAL_API_USER = os.environ.get("VICIDIAL_API_USER", "")
VICIDIAL_API_URL = os.environ.get("VICIDIAL_API_URL", "http://105.246.230.186:82/vicidial/api.php")
LOCAL_API_URL = "http://127.0.0.1:8000/api"
"""

VICIDIAL_API = """
import urllib.parse

import requests


class VicidialAPI:
    def call_api(self, api_function):
        url_params = {
            "function": api_function,
            "pass": self.password,
            "user": self.user,
        }
        url = self.api_url + "?" + urllib.parse.urlencode(url_params)
        return requests.get(url)
"""


def test_plain_http_calls_and_url_settings(tmp_path):
    write(tmp_path, "pp/ussd/models.py", USSD)
    write(tmp_path, "pp/settings/vicidial_settings.py", VICIDIAL_SETTINGS)
    write(tmp_path, "pp/tests/test_ussd.py", USSD)
    found = {
        f.locations[0].file: f for f in findings_for(tmp_path, "owasp", "OWASP-A02-PLAIN-HTTP-CALL")
    }
    assert sorted(found) == ["pp/settings/vicidial_settings.py", "pp/ussd/models.py"]
    ussd = found["pp/ussd/models.py"]
    assert [str(loc) for loc in ussd.locations] == ["pp/ussd/models.py:13"]
    assert (ussd.severity.value, ussd.tag.value) == ("high", "CONFIRMED")
    assert "password, msisdn" in ussd.detail
    assert ussd.title == "Calls to ussdpush.provider.co.za use plain HTTP"
    vici = found["pp/settings/vicidial_settings.py"]
    assert [loc.line for loc in vici.locations] == [5]
    assert vici.severity.value == "medium"


def test_credentials_in_a_query_dict(tmp_path):
    write(tmp_path, "pp/vicidial/vicidial_api.py", VICIDIAL_API)
    write(tmp_path, "pp/ussd/models.py", USSD)
    found = sorted(
        (str(f.locations[0]), f.title)
        for f in findings_for(tmp_path, "owasp", "OWASP-A02-SECRET-IN-URL")
    )
    assert found == [
        ("pp/ussd/models.py:13", "password sent in a URL query string"),
        ("pp/vicidial/vicidial_api.py:14", "pass sent in a URL query string"),
    ]


def test_no_timeout_grouped_per_file(tmp_path):
    write(tmp_path, "pp/ussd/models.py", USSD)
    write(tmp_path, "pp/vicidial/vicidial_api.py", VICIDIAL_API)
    write(
        tmp_path,
        "pp/client.py",
        "import requests\n\n\ndef f(**kw):\n    return requests.post('https://x.example.invalid', **kw)\n",
    )
    found = {
        f.locations[0].file: f for f in findings_for(tmp_path, "owasp", "OWASP-A05-NO-TIMEOUT")
    }
    assert sorted(found) == ["pp/ussd/models.py", "pp/vicidial/vicidial_api.py"]
    assert found["pp/ussd/models.py"].title == "1 outbound call(s) have no timeout"
    assert found["pp/ussd/models.py"].severity.value == "low"


def test_live_vendor_address_fixed_in_code(tmp_path):
    write(
        tmp_path,
        "pp/settings/cpb_settings.py",
        'import os\n\nCPB_USER = os.environ.get("CPB_USER", "")\n'
        '# CPB_BASE_URL = os.environ.get("CPB_BASE_URL", "https://cpb.test.bureau.co.za")\n'
        'CPB_BASE_URL = "https://api.bureau.co.za"\n',
    )
    write(
        tmp_path,
        "pp/services/qlink.py",
        "class QLinkAPI:\n"
        '    API_LIVE_ENDPOINT = "https://api.qlink.co.za/v1"\n'
        '    API_STAGING_ENDPOINT = "https://apitest.qlink.co.za/v1"\n'
        "    CURRENT_ENDPOINT = API_LIVE_ENDPOINT\n\n"
        "    def token(self):\n"
        "        return requests.post(self.CURRENT_ENDPOINT + '/token', timeout=5)\n",
    )
    write(
        tmp_path,
        "pp/settings/guardrisk_settings.py",
        'import os\n\nGR_ENDPOINT = os.environ.get("GR_ENDPOINT", "https://api.guardrisk.co.za/x")\n',
    )
    write(
        tmp_path,
        "pp/cpb.py",
        "import requests\nfrom django.conf import settings\n\n\nclass Cpb:\n"
        "    def __init__(self):\n        self.base_url = settings.CPB_BASE_URL\n\n"
        "    def lookup(self):\n"
        "        return requests.post(f'{self.base_url}/check', timeout=5)\n",
    )
    write(
        tmp_path,
        "pp/settings/links.py",
        'import os\n\nX = os.environ.get("X")\nPORTAL_LOGIN_URL = "https://portal.vendor.co.za/login"\n',
    )
    write(
        tmp_path,
        "pp/maps.py",
        'MAPS_URL = "https://maps.googleapis.com/maps/api"\n\n\ndef f():\n    return MAPS_URL\n',
    )
    found = {
        f.locations[0].file: f
        for f in findings_for(tmp_path, "owasp", "OWASP-A05-HARDCODED-VENDOR-URL")
    }
    assert sorted(found) == ["pp/services/qlink.py", "pp/settings/cpb_settings.py"]
    assert [loc.line for loc in found["pp/services/qlink.py"].locations] == [4]
    assert (
        found["pp/services/qlink.py"].title
        == "Live vendor address CURRENT_ENDPOINT is fixed in code"
    )
    assert [loc.line for loc in found["pp/settings/cpb_settings.py"].locations] == [5]
    assert all(f.tag.value == "INFERRED" and f.severity.value == "low" for f in found.values())
