"""App roots: folders with their own manifest, and whether a deploy or CI config names them."""

from __future__ import annotations

import re
from dataclasses import replace
from pathlib import PurePosixPath

from dpr.model import AppRoot, Finding, Route, Severity
from dpr.walk import RepoIndex

MANIFESTS = ("package.json", "pyproject.toml", "requirements.txt", "manage.py")
DEPLOY_FILES = (
    "render.yaml",
    "fly.toml",
    "vercel.json",
    "netlify.toml",
    "app.yaml",
    "serverless.yml",
    "railway.json",
    "railway.toml",
    "amplify.yml",
    "Procfile",
)
OWN_START = (
    "Procfile",
    "Dockerfile",
    "startup.sh",
    "start.sh",
    "entrypoint.sh",
    "docker-entrypoint.sh",
    "render.yaml",
    "fly.toml",
    "vercel.json",
    "netlify.toml",
    "app.yaml",
    "serverless.yml",
    "railway.json",
    "railway.toml",
    "staticwebapp.config.json",
)
WEB_FILES = ("index.html", "vite.config.*", "next.config.*", "nuxt.config.*", "svelte.config.*")
LOWER = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
}


def root_of(roots: list[AppRoot], rel: str) -> AppRoot | None:
    """The deepest app root that contains a repository-relative path."""
    best = None
    for root in roots:
        if (not root.path or rel.startswith(root.path + "/")) and (
            best is None or len(root.path) > len(best.path)
        ):
            best = root
    return best


def same_root(roots: list[AppRoot], a: str, b: str) -> bool:
    """Whether two repository-relative paths sit in the same app root, comparing `root_of`
    results by path. A path with no app root (root_of returns None) only matches another path
    with no app root, never every path, so a repository-root app root (path "") never crosses
    into a sibling root through a string-prefix test."""
    root_a = root_of(roots, a)
    root_b = root_of(roots, b)
    return (root_a.path if root_a is not None else None) == (
        root_b.path if root_b is not None else None
    )


def _folders(index: RepoIndex) -> list[str]:
    found = set()
    for entry in index.named(*MANIFESTS):
        folder = str(PurePosixPath(entry.rel).parent)
        found.add("" if folder == "." else folder)
    return sorted(found)


def _kind(index: RepoIndex, folders: list[str], folder: str, routes: list[Route]) -> str:
    prefix = f"{folder}/" if folder else ""
    nested = {p for p in folders if p != folder and p.startswith(prefix)}

    def own(rel: str) -> bool:
        return rel.startswith(prefix) and not any(rel.startswith(n + "/") for n in nested)

    if any(own(r.file) for r in routes):
        return "server"
    if any(own(f.rel) for f in index.named(*WEB_FILES)):
        return "web"
    return "library"


def _reference(folder: str) -> re.Pattern[str]:
    return re.compile(rf"(?<![\w.-])(?:\./)?{re.escape(folder)}(?![\w-])")


def app_roots(index: RepoIndex, routes: list[Route], ci: list[str]) -> list[AppRoot]:
    folders = _folders(index)
    deploy = [
        *ci,
        *(f.rel for f in index.named(*DEPLOY_FILES)),
        *(f.rel for f in index.with_suffix(".tf")),
    ]
    texts = {rel: index.text(rel) for rel in dict.fromkeys(deploy)}
    roots = []
    for folder in folders:
        kind = _kind(index, folders, folder, routes)
        refs = [rel for rel, text in texts.items() if folder and _reference(folder).search(text)]
        own = [f.rel for f in index.named(*OWN_START) if str(PurePosixPath(f.rel).parent) == folder]
        if refs:
            roots.append(AppRoot(folder, kind, True, f"named in {refs[0]}"))
        elif own:
            roots.append(AppRoot(folder, kind, True, f"has its own start or host config {own[0]}"))
        else:
            roots.append(AppRoot(folder, kind, None, ""))
    apps = [r for r in roots if r.path and r.kind != "library"]
    if any(r.deployed for r in roots if r.path):
        roots = [
            replace(r, deployed=False, evidence="no deploy or CI configuration names it")
            if r in apps and r.deployed is None
            else r
            for r in roots
        ]
    return roots


def undeployed(roots: list[AppRoot]) -> list[AppRoot]:
    return [r for r in roots if r.deployed is False]


def lower_undeployed(findings: list[Finding], roots: list[AppRoot]) -> list[Finding]:
    """Lower severity one step when every location sits in an app root nothing deploys."""
    if not undeployed(roots):
        return findings
    adjusted = []
    for finding in findings:
        homes = [root_of(roots, loc.file) for loc in finding.locations]
        if homes and all(h is not None and h.deployed is False for h in homes):
            if finding.severity in LOWER:
                note = (
                    f" Every location is in {homes[0].path}, which no deploy or CI configuration "
                    "names, so the severity is one step lower."
                )
                finding = replace(
                    finding, severity=LOWER[finding.severity], detail=finding.detail + note
                )
        adjusted.append(finding)
    return adjusted
