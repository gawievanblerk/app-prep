import datetime

from tests.reviews.helpers import findings_for, write

TODAY = datetime.date(2026, 9, 23)


def _found(tmp_path, today=TODAY):
    return {
        f.title: f for f in findings_for(tmp_path, "owasp", "OWASP-A06-EOL-COMPONENT", today=today)
    }


def test_end_of_life_versions_from_manifests_and_images(tmp_path):
    write(tmp_path, "requirements.txt", "Django==3.2.9\nPyPDF2==1.26.0\n")
    write(
        tmp_path,
        "Dockerfile",
        "FROM ubuntu:20.04\nRUN apt-get install -y python3.9 \\\n    python3.9-dev\n",
    )
    write(
        tmp_path,
        "web/package.json",
        '{"dependencies": {"next": "^13.4.1", "react": "18"}, "engines": {"node": "16.x"}}',
    )
    write(tmp_path, "svc/Dockerfile", "FROM python:3.12-slim-bookworm\n")
    write(tmp_path, "tests/requirements.txt", "Django==1.8\n")
    found = _found(tmp_path)
    assert sorted(found) == [
        "Django 3.2 is past its end of support",
        "Next.js 13 is past its end of support",
        "Node.js 16 is past its end of support",
        "Python 3.9 is past its end of support",
        "Ubuntu base image 20.04 is past its end of support",
    ]
    django = found["Django 3.2 is past its end of support"]
    assert (django.severity.value, django.tag.value) == ("high", "CONFIRMED")
    assert [str(loc) for loc in django.locations] == ["requirements.txt:1"]
    assert "on 2024-04-01" in django.detail and "dated 2026-06-01" in django.detail
    python = found["Python 3.9 is past its end of support"]
    assert [str(loc) for loc in python.locations] == ["Dockerfile:2"]
    assert python.severity.value == "medium"


def test_supported_versions_and_the_scan_date(tmp_path):
    write(tmp_path, "requirements.txt", "django==4.2.11\n")
    write(tmp_path, ".python-version", "3.10.4\n")
    assert _found(tmp_path, datetime.date(2026, 1, 1)) == {}
    assert sorted(_found(tmp_path)) == ["Django 4.2 is past its end of support"]
    write(tmp_path, "requirements.txt", "Django==1.8.19\n")
    [old] = _found(tmp_path).values()
    assert "no later than 2020-04-01" in old.detail
