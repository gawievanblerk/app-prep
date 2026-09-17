"""Live header read: exactly three HEAD requests to a host the owner controls."""

from __future__ import annotations

import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from dpr.model import ScanError
from dpr.redact import redact

TIMEOUT_SECONDS = 10.0
USER_AGENT = "dpr header read (owner-confirmed host)"
Opener = Callable[[str, bool, float], tuple[int, dict[str, str], str]]


@dataclass(frozen=True)
class HeaderRead:
    label: str
    url: str
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    final_url: str | None = None
    error: str | None = None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def urllib_open(url: str, follow: bool, timeout: float) -> tuple[int, dict[str, str], str]:
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
    handlers = [] if follow else [_NoRedirect()]
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, dict(response.headers.items()), response.geturl()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers.items()), url


def targets(url: str, login_path: str) -> list[tuple[str, str, bool]]:
    parts = urlsplit(url if "://" in url else f"https://{url}")
    if not parts.hostname:
        raise ScanError(f"not a usable URL for a header read: {redact(url)}")
    try:
        port = parts.port
    except ValueError as exc:
        raise ScanError(f"not a usable URL for a header read: {redact(url)}") from exc
    hostname = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    host = f"{hostname}:{port}" if port else hostname
    login = "/" + login_path.lstrip("/")
    return [
        ("https root", f"https://{host}/", True),
        ("https login page", f"https://{host}{login}", True),
        ("http root", f"http://{host}/", False),
    ]


def read_headers(
    url: str,
    login_path: str = "/login",
    opener: Opener | None = None,
    timeout: float = TIMEOUT_SECONDS,
) -> list[HeaderRead]:
    open_url = opener or urllib_open
    reads = []
    for label, target, follow in targets(url, login_path):
        try:
            status, headers, final = open_url(target, follow, timeout)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", None) or type(exc).__name__
            reads.append(HeaderRead(label, target, error=redact(str(reason))))
            continue
        except Exception as exc:  # last resort: a bad target must never raise past this point
            reason = str(exc) or type(exc).__name__
            reads.append(HeaderRead(label, target, error=redact(reason)))
            continue
        lowered = {k.lower(): v for k, v in headers.items()}
        reads.append(HeaderRead(label, target, status, lowered, final))
    return reads
