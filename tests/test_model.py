import dataclasses

import pytest

from dpr.model import Exploitability, Finding, Location, Severity, Tag


def make(**over):
    base = dict(
        rule_id="X-1",
        review="leaks",
        title="t",
        tag=Tag.CONFIRMED,
        severity=Severity.HIGH,
        exploitability=Exploitability.HIGH,
        effort_minutes=5,
        locations=(Location("a.ts", 3),),
        detail="d",
        fix="f",
    )
    base.update(over)
    return Finding(**base)


def test_confirmed_requires_location():
    with pytest.raises(ValueError, match="CONFIRMED"):
        make(locations=())


def test_inferred_requires_proof_needed():
    with pytest.raises(ValueError, match="proof_needed"):
        make(tag=Tag.INFERRED)
    assert make(tag=Tag.INFERRED, proof_needed="p").tag is Tag.INFERRED


def test_unknown_is_not_a_finding():
    with pytest.raises(ValueError, match="UNKNOWN"):
        make(tag=Tag.UNKNOWN)


def test_strings_are_coerced_to_enums():
    f = make(tag="CONFIRMED", severity="critical", exploitability="low")
    assert f.tag is Tag.CONFIRMED
    assert f.severity is Severity.CRITICAL
    assert f.exploitability is Exploitability.LOW


def test_finding_is_frozen():
    f = make()
    with pytest.raises(dataclasses.FrozenInstanceError):
        f.tag = Tag.INFERRED


def test_location_str():
    assert str(Location("src/a.ts", 12)) == "src/a.ts:12"
