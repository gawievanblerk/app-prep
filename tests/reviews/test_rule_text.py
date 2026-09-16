from importlib.resources import files

from dpr import reviews, rules
from dpr.reviews.leaks import ROTATE

KEY_RULES = ("LEAK-PUBLIC-SECRET", "LEAK-HARDCODED-KEY", "LEAK-KEY-IN-BUILD",
             "LEAK-ENV-TRACKED", "LEAK-ENV-IN-HISTORY")


def test_rule_text_matches_registered_rules():
    reviews.available()
    assert set(rules._all_rule_text()) == set(rules.SPECS)


def test_every_key_fix_starts_with_rotate():
    reviews.available()
    for rule_id in KEY_RULES:
        if rule_id in rules.SPECS:
            assert rules.rule_text(rule_id).fix.startswith(ROTATE), rule_id


def test_rule_text_has_no_legal_verdicts_or_em_dashes():
    folder = files("dpr.data").joinpath("rule_text")
    for item in folder.iterdir():
        raw = item.read_text(encoding="utf-8")
        lowered = raw.lower()
        for phrase in ("compliant with", "complies with", "satisfies article",
                       "satisfies section", "lawful basis is"):
            assert phrase not in lowered, (item.name, phrase)
        assert "—" not in raw, item.name
