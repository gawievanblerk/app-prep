import pytest

from dpr.api import review
from dpr.data import load
from dpr.parsing.pins import pinned_versions
from dpr.reviews.owasp_advisories import affected, version_key
from dpr.walk import RepoIndex
from tests.reviews.helpers import findings_for, write

DJANGO_32 = [["3.2", "3.2.10"]]


@pytest.mark.parametrize(
    ("version", "ranges", "expected"),
    [
        ("3.2.9", DJANGO_32, "3.2.10"),  # inside the range
        ("3.2", DJANGO_32, "3.2.10"),  # 3.2 is 3.2.0, the first version of the range
        ("3.2.10", DJANGO_32, None),  # the fixed version is not affected
        ("3.2.25", DJANGO_32, None),
        ("3.1.14", DJANGO_32, None),  # before the range was introduced
        ("4.0", DJANGO_32, None),
        ("1.4.1", [["0", "3.5.0"]], "3.5.0"),  # "0": every earlier version
        ("3.5.0-rc1", [["0", "3.5.0"]], "3.5.0"),  # a pre-release sorts before its release
        ("4.1.1", [["0", "3.4.0"], ["4.0.0", "4.1.2"]], "4.1.2"),  # a second release line
        ("3.4.0", [["0", "3.4.0"], ["4.0.0", "4.1.2"]], None),  # between the two lines
        ("9.9.9", [["2.0", None]], ""),  # no release fixes it
        ("2.9.0.post0", [["0", "2.9.0"]], None),  # a post release is the release
        ("unknown", [["0", "3.5.0"]], None),
    ],
)
def test_version_ranges(version, ranges, expected):
    assert affected(version, ranges) == expected


def test_version_keys_order_numerically():
    assert version_key("1.10.2") > version_key("1.9.0")
    assert version_key("4.2.67") > version_key("4.1.392")
    assert version_key("3.2") == version_key("3.2.0")


def test_only_exact_pins_are_read(tmp_path):
    write(
        tmp_path,
        "requirements.txt",
        "Django==3.2.9\nfuzzywuzzy[speedup]==0.18.0\npymysql==1.0.2  # a comment\n"
        "requests>=2.0\ncelery~=5.0\n-r other.txt\n",
    )
    write(
        tmp_path,
        "web/package.json",
        '{"dependencies": {"lodash": "4.17.20", "express": "^4.19.2", "moment": "=2.29.1"},'
        ' "devDependencies": {"next": "~14.2.0"}}',
    )
    write(
        tmp_path,
        "api/pyproject.toml",
        '[project]\ndependencies = ["gunicorn==20.1.0", "lxml>=4"]\n'
        '[tool.poetry.dependencies]\npython = "3.11"\nreportlab = "3.5.49"\nhttpx = "^0.27"\n',
    )
    pins = {
        (p.ecosystem, p.name, p.version, str(p.location))
        for p in pinned_versions(RepoIndex(tmp_path))
    }
    assert pins == {
        ("pypi", "django", "3.2.9", "requirements.txt:1"),
        ("pypi", "fuzzywuzzy", "0.18.0", "requirements.txt:2"),
        ("pypi", "pymysql", "1.0.2", "requirements.txt:3"),
        ("npm", "lodash", "4.17.20", "web/package.json:1"),
        ("npm", "moment", "2.29.1", "web/package.json:1"),
        ("pypi", "gunicorn", "20.1.0", "api/pyproject.toml:2"),
        ("pypi", "reportlab", "3.5.49", "api/pyproject.toml:5"),
    }


def advisory_app(root):
    write(
        root,
        "requirements.txt",
        "Django==3.2.9\ngunicorn==20.1.0\nrequests==2.32.5\ndjangorestframework==3.15.2\n",
    )
    write(root, "legacy/requirements.txt", "Django==3.2.25\n")
    write(root, "web/package.json", '{"dependencies": {"lodash": "4.17.20", "express": "^4.19.2"}}')
    write(root, "shop/static/js/jquery-1.12.4.min.js", "/*! jQuery v1.12.4 */\nx.innerHTML=y;")
    write(root, "shop/static/js/jquery-3.6.0.min.js", "/*! jQuery v3.6.0 */\nx.innerHTML=y;")
    write(root, "tests/requirements.txt", "reportlab==3.5.49\n")
    return root


def test_pinned_and_copied_versions_with_advisories(tmp_path):
    found = {
        f.title: f
        for f in findings_for(advisory_app(tmp_path), "owasp", "OWASP-A06-KNOWN-ADVISORY")
    }
    assert sorted(found) == [
        "Django 3.2.9 has 20 published security advisories",
        "Lodash 4.17.20 has 1 published security advisory",
        "gunicorn 20.1.0 has 2 published security advisories",
        "jQuery 1.12.4 has 4 published security advisories",
    ]
    django = found["Django 3.2.9 has 20 published security advisories"]
    assert (django.severity.value, django.tag.value, django.owasp) == ("high", "CONFIRMED", "A06")
    assert [str(loc) for loc in django.locations] == ["requirements.txt:1"]
    assert "CVE-2022-28346 (high, fixed in 3.2.13)" in django.detail
    assert f"dated {load('advisories.yaml')['as_of']}" in django.detail
    assert "not a live advisory database" in django.detail
    assert django.fix.startswith("Upgrade Django to 3.2.25 or later")
    jquery = found["jQuery 1.12.4 has 4 published security advisories"]
    assert [str(loc) for loc in jquery.locations] == ["shop/static/js/jquery-1.12.4.min.js:1"]
    assert jquery.snippet is None
    for cve in ("CVE-2015-9251", "CVE-2019-11358", "CVE-2020-11022", "CVE-2020-11023"):
        assert cve in jquery.detail
    assert "CVE-2012-6708" not in jquery.detail
    assert found["Lodash 4.17.20 has 1 published security advisory"].detail.count("CVE-") == 1


def test_not_covered_names_the_table_date(tmp_path):
    report = review(advisory_app(tmp_path), reviews=["owasp"])
    as_of = load("advisories.yaml")["as_of"]
    assert any(f"bundled advisory table dated {as_of}" in line for line in report.not_covered)
