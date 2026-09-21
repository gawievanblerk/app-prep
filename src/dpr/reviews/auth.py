"""Review 3, failure path test plan: ten fixed cases plus cases for flows the repository has."""

from __future__ import annotations

from dataclasses import dataclass

from dpr.data import load
from dpr.model import EXPLOIT_ORDER, Finding, Location, Part, ReviewSection, Tag
from dpr.reviews.auth_flows import flows, flows_of, lifetimes, managed_provider
from dpr.rules import Context

INTRO = (
    "Each case states what a secure app does, what this repository shows, the risk and a test "
    "to write. Failing cases come first, ordered by exploitability. A case is UNVERIFIED when a "
    "managed provider handles it, and UNKNOWN when the flow it needs was not found in code."
)
TAG_ORDER = (Tag.CONFIRMED, Tag.INFERRED, Tag.UNVERIFIED)


@dataclass(frozen=True)
class Outcome:
    result: str  # "FAILS" | "PASSES" | "UNVERIFIED" | "UNKNOWN"
    tag: str
    text: str
    order: int


def record_pass(ctx: Context, case: int | str, tag: Tag, text: str, location: Location) -> None:
    """Rules call this with evidence that a case holds, so the section can say PASSES."""
    ctx.facts.setdefault("auth_passes", {}).setdefault(case, []).append((tag, text, location))


def _flow_lines(ctx: Context) -> str:
    lines = []
    provider = managed_provider(ctx)
    if provider:
        lines.append(f"- Managed provider: {provider}.")
    for flow in flows(ctx):
        route = flow.route
        lines.append(f"- {flow.kind}: {route.method} {route.path} (`{flow.location}`)")
    for name, value, location in lifetimes(ctx)[:8]:
        lines.append(f"- Lifetime setting {name} = {value} (`{location}`)")
    return "\n".join(lines) or "No sign-in, signup, reset or session code was found."


def _outcome(ctx: Context, key: int | str, case: dict, findings: list[Finding]) -> Outcome:
    mine = [f for f in findings if f.rule_id in case["rules"]]
    passes = ctx.facts.get("auth_passes", {}).get(key, [])
    found_flows = flows_of(ctx, *case["kinds"]) if case["kinds"] else []
    if mine:
        tag = min((f.tag for f in mine), key=TAG_ORDER.index).value
        text = " ".join(
            f"{f.title} (`{f.locations[0]}`, {f.rule_id})." if f.locations else f"{f.title}."
            for f in mine
        )
        order = min(EXPLOIT_ORDER.index(f.exploitability.value) for f in mine)
        return Outcome("FAILS", tag, text, order)
    if passes:
        tag = min((t for t, _, _ in passes), key=TAG_ORDER.index).value
        text = " ".join(f"{text} (`{loc}`)." for _, text, loc in passes)
        return Outcome("PASSES", tag, text, 9)
    provider = managed_provider(ctx)
    if provider and not found_flows:
        text = f"Handled by {provider}; check the provider settings for this case."
        return Outcome("UNVERIFIED", "UNVERIFIED", text, 9)
    if found_flows:
        where = ", ".join(f"`{f.location}`" for f in found_flows[:3])
        text = f"The flow is at {where}, but this case could not be decided from the code."
        return Outcome("UNKNOWN", "UNKNOWN", text, 9)
    kinds = ", ".join(case["kinds"]) or "matching"
    return Outcome("UNKNOWN", "UNKNOWN", f"No {kinds} route was found.", 9)


def _block(label: str, case: dict, outcome: Outcome) -> str:
    return "\n".join(
        [
            f"#### {label}: {case['title']} ({outcome.result})",
            "",
            f"Expected: {case['expected']}",
            "",
            f"This app: {outcome.tag}. {outcome.text}",
            "",
            f"Risk: {case['risk']}",
            "",
            f"Test: {case['test']}",
        ]
    )


def _extra_relevant(ctx: Context, case: dict, findings: list[Finding]) -> bool:
    if any(f.rule_id in case["rules"] for f in findings):
        return True
    if case["key"] in ctx.facts.get("auth_passes", {}):
        return True
    return bool(case["kinds"]) and bool(flows_of(ctx, *case["kinds"]))


def case_blocks(ctx: Context, findings: list[Finding]) -> str:
    data = load("auth_cases.yaml")
    blocks = []
    for case in data["cases"]:
        outcome = _outcome(ctx, case["number"], case, findings)
        blocks.append(
            (outcome.order, case["number"], _block(f"CASE {case['number']}", case, outcome))
        )
    for position, case in enumerate(data["extra"], start=len(data["cases"]) + 1):
        if _extra_relevant(ctx, case, findings):
            outcome = _outcome(ctx, case["key"], case, findings)
            blocks.append((outcome.order, position, _block(f"CASE {position}", case, outcome)))
    return "\n\n".join(text for _, _, text in sorted(blocks))


def run(ctx: Context) -> ReviewSection | None:
    if not flows(ctx) and not ctx.detection.auth_providers:
        ctx.not_covered.append(
            "Review 3 (auth): not applicable, no sign-in, signup or reset routes and no auth "
            "provider found"
        )
        return None
    return ReviewSection(
        "auth",
        [
            Part("text", "How to read the cases", body=INTRO),
            Part("text", "Flows read", body=_flow_lines(ctx)),
            Part("findings", "Findings"),
        ],
    )


def finish(ctx: Context, section: ReviewSection, findings: list[Finding]) -> None:
    position = next(i for i, p in enumerate(section.parts) if p.kind == "findings")
    section.parts.insert(position, Part("text", "Cases", body=case_blocks(ctx, findings)))
    if ctx.detection.test_frameworks:
        frameworks = ", ".join(ctx.detection.test_frameworks)
        note = (
            f"The repository has {frameworks}. The failing cases can be written as executable "
            "tests there; this review did not write them."
        )
        section.parts.append(Part("text", "Executable tests", body=note))
