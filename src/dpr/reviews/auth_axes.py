"""Review 3: django-axes as the sign-in lockout, and lockout settings that are too weak."""

from __future__ import annotations

import ast
from collections.abc import Iterator
from dataclasses import dataclass, field

from dpr.discovery.approots import same_root
from dpr.facts import fact
from dpr.model import Finding, Location, Tag
from dpr.parsing import pyast
from dpr.parsing.pyenv import module_assignments
from dpr.reviews.settings_files import production_file, settings_module
from dpr.rules import Context, make_finding, rule

AXES_MARKERS = ("AxesMiddleware", "AxesBackend", "AxesStandaloneBackend")
HIGH_LIMIT = 10


@dataclass
class Axes:
    """django-axes enabled in one app root's settings, with its AXES_* settings."""

    enabled: Location
    settings: dict[str, tuple[ast.expr, Location]] = field(default_factory=dict)


def _enabled_at(tree: ast.Module) -> int | None:
    """The line of "axes" in INSTALLED_APPS, its middleware or its authentication backend."""
    for node in ast.walk(tree):
        value = pyast.constant(node, None)
        if isinstance(value, str) and (
            value in ("axes", "axes.apps.AppConfig") or value.endswith(AXES_MARKERS)
        ):
            return node.lineno
    return None


def _all_axes(ctx: Context) -> list[Axes]:
    modules = []
    for entry in ctx.index.py_files:
        text = ctx.index.text(entry.rel)
        if "axes" not in text.lower() or not settings_module(entry.rel, text):
            continue
        tree = pyast.parse_file(ctx.index, entry.rel)
        if tree is not None and production_file(ctx, entry.rel):
            modules.append((entry.rel, tree))
    found: list[Axes] = []
    for rel, tree in modules:
        line = _enabled_at(tree)
        if line is None or any(
            same_root(ctx.detection.app_roots, a.enabled.file, rel) for a in found
        ):
            continue
        axes = Axes(Location(rel, line))
        for other, other_tree in modules:
            if same_root(ctx.detection.app_roots, other, rel):
                for name, value, at in module_assignments(other_tree):
                    if name.startswith("AXES_"):
                        axes.settings[name] = (value, Location(other, at))
        found.append(axes)
    return found


def axes_for(ctx: Context, rel: str) -> Axes | None:
    """django-axes as configured for the app root that holds `rel`, read from settings."""
    return next(
        (
            a
            for a in fact(ctx, "django_axes", _all_axes)
            if same_root(ctx.detection.app_roots, a.enabled.file, rel)
        ),
        None,
    )


def _setting(axes: Axes, name: str) -> object:
    value = axes.settings.get(name)
    return pyast.constant(value[0], pyast.MISSING) if value else None


def _parameters(axes: Axes) -> list[object] | None:
    """The lockout parameters, from AXES_LOCKOUT_PARAMETERS or the settings it replaced; None
    when they cannot be read."""
    if "AXES_LOCKOUT_PARAMETERS" in axes.settings:
        node = axes.settings["AXES_LOCKOUT_PARAMETERS"][0]
        if not isinstance(node, ast.List | ast.Tuple):
            return None
        items: list[object] = []
        for elt in node.elts:
            if isinstance(elt, ast.List | ast.Tuple):
                items.append(tuple(pyast.constant(e, None) for e in elt.elts))
            else:
                items.append(pyast.constant(elt, None))
        return items
    if _setting(axes, "AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP") is True:
        return [("username", "ip_address")]
    if _setting(axes, "AXES_ONLY_USER_FAILURES") is True:
        return ["username"]
    if _setting(axes, "AXES_LOCK_OUT_BY_USER_OR_IP") is True:
        return ["username", "ip_address"]
    return ["ip_address"]


def _weaknesses(axes: Axes) -> tuple[list[str], list[Location], bool]:
    """What is weak, where, and whether any of it lets a stranger lock a known account."""
    weak: list[str] = []
    where: list[Location] = []
    serious = False
    params = _parameters(axes)
    by_user = params == ["username"]
    if _setting(axes, "AXES_COOLOFF_TIME") is None:
        weak.append(
            "AXES_COOLOFF_TIME is not set, so a lockout lasts until an administrator clears it"
        )
        serious = True
    limit = _setting(axes, "AXES_FAILURE_LIMIT")
    if isinstance(limit, int) and not isinstance(limit, bool) and limit > HIGH_LIMIT:
        weak.append(f"AXES_FAILURE_LIMIT allows {limit} failed attempts before a lockout")
        where.append(axes.settings["AXES_FAILURE_LIMIT"][1])
    if by_user:
        weak.append(
            "lockout is keyed by user name only, so anyone can lock a known account and one "
            "address can try a common password against every account unchecked"
        )
        serious = True
    elif params == ["ip_address"]:
        weak.append(
            "lockout is keyed by IP address only, so guesses spread over many addresses are "
            "never locked and one shared office address locks out everyone behind it"
        )
    for name in ("AXES_LOCKOUT_PARAMETERS", "AXES_ONLY_USER_FAILURES"):
        if name in axes.settings and (by_user or params == ["ip_address"]):
            where.append(axes.settings[name][1])
    return weak, where, serious


@rule("AUTH-LOCKOUT-WEAK", review="auth", severity="medium", exploitability="medium", owasp="A07")
def lockout_weak(ctx: Context) -> Iterator[Finding]:
    for axes in fact(ctx, "django_axes", _all_axes):
        weak, where, serious = _weaknesses(axes)
        if not weak:
            continue
        yield make_finding(
            "AUTH-LOCKOUT-WEAK",
            tag=Tag.CONFIRMED,
            locations=list(dict.fromkeys([axes.enabled, *where])),
            severity=None if serious else "low",
            weaknesses="; ".join(weak),
        )
