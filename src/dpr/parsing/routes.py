"""All routes from every supported framework."""

from __future__ import annotations

import re
from dataclasses import replace

from dpr.model import Route
from dpr.parsing import routes_js, routes_py
from dpr.parsing.mounts import apply_mounts
from dpr.walk import RepoIndex

PUBLIC_FORM = re.compile(
    r"sign-?up|register|log-?in|sign-?in|reset|forgot|contact|waitlist|newsletter|feedback"
    r"|invite|upload",
    re.IGNORECASE,
)
# A link that carries a one-time token (a reset confirmation) or a page shown after the form
# was sent is not a form anyone can submit in bulk.
NOT_A_FORM = re.compile(
    r"(?i)<(?:\w+:)?\w*token>|\{\w*token\}|(?:^|/):\w*token\b"
    r"|/(?:done|complete|completed|success|sent)/?$"
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
    for route in apply_mounts(index, found):
        name = getattr(route.handler, "name", None)
        name = name if isinstance(name, str) else ""
        public = bool(PUBLIC_FORM.search(route.path) or PUBLIC_FORM.search(name))
        public = public and not NOT_A_FORM.search(route.path)
        routes.append(replace(route, is_public_form=public))
    return sorted(routes, key=lambda r: (r.file, r.line, r.method))
