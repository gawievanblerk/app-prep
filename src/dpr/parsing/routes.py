"""All routes from every supported framework."""

from __future__ import annotations

import re
from dataclasses import replace

from dpr.model import Route
from dpr.parsing import routes_js, routes_py
from dpr.walk import RepoIndex

PUBLIC_FORM = re.compile(
    r"sign-?up|register|log-?in|sign-?in|reset|forgot|contact|waitlist|newsletter|feedback"
    r"|invite|upload",
    re.IGNORECASE,
)


def extract_routes(index: RepoIndex) -> list[Route]:
    found = (
        routes_js.next_app_routes(index)
        + routes_js.next_pages_routes(index)
        + routes_js.server_actions(index)
        + routes_js.server_routes(index)
        + routes_py.decorator_routes(index)
        + routes_py.django_routes(index)
    )
    routes = []
    for route in found:
        name = getattr(route.handler, "name", None)
        name = name if isinstance(name, str) else ""
        public = bool(PUBLIC_FORM.search(route.path) or PUBLIC_FORM.search(name))
        routes.append(replace(route, is_public_form=public))
    return sorted(routes, key=lambda r: (r.file, r.line, r.method))
