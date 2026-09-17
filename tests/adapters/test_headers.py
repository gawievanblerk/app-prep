import urllib.error

import pytest

from dpr.adapters.headers import read_headers, targets
from dpr.model import ScanError


class FakeOpener:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def __call__(self, url, follow, timeout):
        self.calls.append((url, follow, timeout))
        result = self.responses[url]
        if isinstance(result, Exception):
            raise result
        return result


def test_exactly_three_head_targets():
    assert targets("https://app.example.com/some/page", "account/login") == [
        ("https root", "https://app.example.com/", True),
        ("https login page", "https://app.example.com/account/login", True),
        ("http root", "http://app.example.com/", False),
    ]
    with pytest.raises(ScanError, match="not a usable URL"):
        targets("https://", "/login")


def test_read_headers_lowercases_and_records_failures():
    opener = FakeOpener(
        {
            "https://app.example.com/": (200, {"Strict-Transport-Security": "max-age=1"}, "x"),
            "https://app.example.com/login": urllib.error.URLError("timed out"),
            "http://app.example.com/": (301, {"Location": "https://app.example.com/"}, "y"),
        }
    )
    reads = read_headers("app.example.com", "/login", opener=opener)
    assert [c[1] for c in opener.calls] == [True, True, False]
    assert all(c[2] == 10.0 for c in opener.calls)
    assert reads[0].headers == {"strict-transport-security": "max-age=1"}
    assert reads[1].status is None and reads[1].error == "timed out"
    assert reads[2].status == 301 and reads[2].headers["location"].startswith("https://")


def test_urllib_open_sends_head_without_following(monkeypatch):
    from dpr.adapters import headers

    seen = {}

    class Response:
        status = 200
        headers = {"Server": "nginx"}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def geturl(self):
            return seen["url"]

    class Opener:
        def __init__(self, handlers):
            self.handlers = handlers

        def open(self, request, timeout):
            seen.update(url=request.full_url, method=request.get_method(), timeout=timeout)
            seen["handlers"] = self.handlers
            return Response()

    monkeypatch.setattr(
        headers.urllib.request, "build_opener", lambda *h: Opener([type(x).__name__ for x in h])
    )
    status, got, final = headers.urllib_open("http://app.example.com/", False, 10.0)
    assert (status, got, final) == (200, {"Server": "nginx"}, "http://app.example.com/")
    assert seen["method"] == "HEAD" and seen["timeout"] == 10.0
    assert seen["handlers"] == ["_NoRedirect"]
