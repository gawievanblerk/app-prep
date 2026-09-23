"""Review 5, OWASP A06: frameworks, runtimes and base images past their end of support.

Versions come from the repository's own files (`dpr.parsing.versions`) and are compared with
the scan date using the bundled table `data/eol.yaml`. No network is used.
"""

from __future__ import annotations

import datetime
from collections.abc import Iterator

from dpr.data import load
from dpr.model import Finding, Tag
from dpr.parsing.versions import Declared, declared_versions
from dpr.redact import snippet
from dpr.reviews.paths import is_test
from dpr.rules import Context, make_finding, rule

SEVERITY = {"framework": "high", "runtime": "medium", "image": "medium"}


def _key(cycle: str) -> tuple[int, ...]:
    return tuple(int(part) for part in cycle.split("."))


def end_of_support(component: str, cycle: str) -> tuple[datetime.date, bool] | None:
    """The last day of security fixes for a cycle, and whether it is only a bound (a cycle
    older than the oldest one the table lists)."""
    entry = load("eol.yaml")["components"].get(component)
    if entry is None:
        return None
    cycles = {str(k): v for k, v in entry["cycles"].items()}
    if cycle in cycles:
        return cycles[cycle], False
    oldest = min(cycles, key=_key)
    if _key(cycle) < _key(oldest):
        return cycles[oldest], True
    return None


@rule(
    "OWASP-A06-EOL-COMPONENT", review="owasp", severity="high", exploitability="medium", owasp="A06"
)
def eol_component(ctx: Context) -> Iterator[Finding]:
    table = load("eol.yaml")
    today = ctx.options.today or datetime.date.today()
    groups: dict[tuple[str, str], list[Declared]] = {}
    for item in declared_versions(ctx.index):
        if not is_test(item.location.file):
            groups.setdefault((item.component, item.cycle), []).append(item)
    for (component, cycle), items in sorted(groups.items()):
        ended = end_of_support(component, cycle)
        if ended is None or ended[0] > today:
            continue
        entry = table["components"][component]
        per_file = {i.location.file: i.location for i in reversed(items)}
        locations = sorted(per_file.values(), key=lambda loc: (loc.file, loc.line))
        when = f"no later than {ended[0]}" if ended[1] else f"on {ended[0]}"
        yield make_finding(
            "OWASP-A06-EOL-COMPONENT",
            tag=Tag.CONFIRMED,
            locations=locations,
            snippet=snippet(ctx.index.text(locations[0].file), locations[0].line),
            severity=SEVERITY[entry["kind"]],
            component=entry["label"],
            version=cycle,
            when=when,
            source=entry["source"],
            table_date=table["as_of"],
            today=today,
        )
