from dpr.api import review
from tests.reviews.helpers import findings_for, write

SIGNING = "committed" + "-signing-" + "k3y-5521"
PICKLE = 'SESSION_SERIALIZER = "django.contrib.sessions.serializers.PickleSerializer"\n'


def test_pickle_sessions_cite_the_committed_signing_key(tmp_path):
    write(
        tmp_path,
        "proj/settings/base.py",
        f'import os\nINSTALLED_APPS = []\nSECRET_KEY = os.environ.get("SECRET_KEY", "{SIGNING}")\n'
        + PICKLE,
    )
    write(tmp_path, "proj/settings/local.py", "INSTALLED_APPS = []\n" + PICKLE)
    write(tmp_path, "proj/notes.py", PICKLE)
    [finding] = findings_for(tmp_path, "baseline", "BASE-PICKLE-SESSIONS")
    assert [str(loc) for loc in finding.locations] == [
        "proj/settings/base.py:4",
        "proj/settings/base.py:3",
    ]
    assert (finding.severity.value, finding.tag.value) == ("high", "CONFIRMED")
    assert "committed at proj/settings/base.py:3" in finding.detail
    report = review(tmp_path)
    [issue] = [i for i in report.register if "Pickle" in i.title]
    assert issue.title.endswith(
        ", and sessions use Pickle, so a signed session can run code on the server"
    )
    assert SIGNING not in repr(report.findings)


def test_pickle_sessions_without_a_committed_key(tmp_path):
    write(
        tmp_path,
        "proj/settings.py",
        'import os\nINSTALLED_APPS = []\nSECRET_KEY = os.environ["SECRET_KEY"]\n' + PICKLE,
    )
    [finding] = findings_for(tmp_path, "baseline", "BASE-PICKLE-SESSIONS")
    assert [str(loc) for loc in finding.locations] == ["proj/settings.py:4"]
    write(tmp_path, "proj/settings.py", "INSTALLED_APPS = []\n")
    assert findings_for(tmp_path, "baseline", "BASE-PICKLE-SESSIONS") == []


def test_environment_flag_that_defaults_to_production(tmp_path):
    write(
        tmp_path,
        "proj/settings/site.py",
        "import os\n"
        'IS_PROD = os.environ.get("DOMAIN", "app.example.invalid") in [\n'
        '    "app.example.invalid",\n    "wealth.example.invalid",\n]\n'
        'ENVIRONMENT = os.getenv("APP_ENV", "production")\n'
        'IS_PRODUCTION = os.getenv("IS_PRODUCTION", "True") == "True"\n'
        'SAFE_ENV = os.getenv("APP_ENV", "production")\n'
        'IS_LIVE = os.getenv("IS_LIVE", "False") == "True"\n'
        'STAGE = os.getenv("STAGE", "development")\n'
        'PROD = os.getenv("DOMAIN") in ["app.example.invalid"]\n'
        "IS_PROD_FIXED = True\n",
    )
    write(tmp_path, "proj/tests/settings.py", 'import os\nIS_PROD = os.getenv("X", "1") == "1"\n')
    found = findings_for(tmp_path, "baseline", "BASE-ENV-DEFAULTS-PROD")
    assert [(str(f.locations[0]), f.title) for f in found] == [
        ("proj/settings/site.py:2", "IS_PROD means production when the environment sets nothing"),
        (
            "proj/settings/site.py:6",
            "ENVIRONMENT means production when the environment sets nothing",
        ),
        (
            "proj/settings/site.py:7",
            "IS_PRODUCTION means production when the environment sets nothing",
        ),
    ]
    assert {f.severity.value for f in found} == {"medium"}


def test_feature_switches_default_on(tmp_path):
    write(
        tmp_path,
        "proj/settings.py",
        "INSTALLED_APPS = ['waffle']\nWAFFLE_SWITCH_DEFAULT = True\nWAFFLE_FLAG_DEFAULT = True\n"
        "WAFFLE_SAMPLE_DEFAULT = False\n",
    )
    write(tmp_path, "other/settings.py", "INSTALLED_APPS = []\nWAFFLE_SWITCH_DEFAULT = False\n")
    [finding] = findings_for(tmp_path, "baseline", "BASE-FEATURE-DEFAULT-ON")
    assert [str(loc) for loc in finding.locations] == ["proj/settings.py:2", "proj/settings.py:3"]
    assert finding.severity.value == "low"
    assert "WAFFLE_SWITCH_DEFAULT, WAFFLE_FLAG_DEFAULT set to True" in finding.detail


def test_debug_that_defaults_on_through_the_environment(tmp_path):
    write(tmp_path, "proj/settings/base.py", "INSTALLED_APPS = []\n")
    write(
        tmp_path,
        "proj/settings/__init__.py",
        'import os\nDEBUG = False if os.environ.get("DEBUG") == "False" else True\n',
    )
    write(tmp_path, "a/settings.py", 'import os\nDEBUG = os.environ.get("DEBUG", "True")\n')
    write(tmp_path, "b/settings.py", 'DEBUG = env.bool("DEBUG", default=True)\n')
    write(
        tmp_path, "c/settings.py", 'import os\nDEBUG = os.environ.get("DEBUG", "False") == "True"\n'
    )
    write(
        tmp_path,
        "d/settings.py",
        'import os\nDEBUG = os.getenv("DEBUG", "0").lower() in ("1", "true")\n',
    )
    write(tmp_path, "e/app.py", 'import os\nDEBUG = os.environ.get("DEBUG", "True")\n')
    write(tmp_path, "proj/ci_settings.py", 'import os\nDEBUG = os.environ.get("DEBUG", "True")\n')
    found = findings_for(tmp_path, "baseline", "BASE-DEBUG-ON")
    assert sorted(str(f.locations[0]) for f in found) == [
        "a/settings.py:2",
        "b/settings.py:1",
        "proj/settings/__init__.py:2",
    ]
    assert {(f.tag.value, f.severity.value) for f in found} == {("INFERRED", "high")}
