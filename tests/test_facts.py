from dpr import rules
from dpr.api import review
from dpr.facts import fact
from dpr.model import Finding, Location
from dpr.rank import dedupe
from tests.reviews.helpers import write


def test_fact_is_computed_once_per_context():
    calls = []
    ctx = rules.Context(index=None, detection=None)

    def compute(_ctx):
        calls.append(1)
        return [1, 2]

    assert fact(ctx, "k", compute) is fact(ctx, "k", compute)
    assert calls == [1]


def app(root):
    write(root, "requirements.txt", "fastapi\nsentry-sdk\n")
    write(
        root,
        "app/main.py",
        "import sentry_sdk\nsentry_sdk.init(dsn='x', send_default_pii=True)\n\n"
        "def notify(user):\n    logger.info('mailed %s', user.email)\n",
    )
    write(
        root,
        "app/models.py",
        "class User(Base):\n    __tablename__ = 'users'\n    email = Column(String)\n",
    )
    return root


def rows(report):
    parts = {p.title: p for p in report.sections["inventory"].parts}
    return {r[0]: r for r in parts["Personal data map"].rows}


def test_inventory_reads_log_and_error_tracker_facts_without_the_leaks_review(tmp_path):
    found = rows(review(app(tmp_path), reviews=["inventory"]))
    assert found["values written by log calls"][2] == "1 log calls (see review 6, LEAK-LOGGED-PII)"
    tracker = found["error events with request and user context"]
    assert tracker[4] == "sentry (sends default personal data)"


def test_inventory_facts_survive_a_failing_leaks_rule(tmp_path, monkeypatch):
    monkeypatch.delenv("DPR_STRICT")
    root = app(tmp_path)
    review(root, reviews=["leaks"])

    def boom(ctx):
        raise RuntimeError("x")

    checks = [(rid, boom if rid == "LEAK-LOGGED-PII" else fn) for rid, fn in rules.CHECKS["leaks"]]
    monkeypatch.setitem(rules.CHECKS, "leaks", checks)
    report = review(root)
    assert "rule LEAK-LOGGED-PII failed: RuntimeError" in report.not_covered
    assert "values written by log calls" in rows(report)


def finding(title, locations=()):
    return Finding(
        rule_id="R",
        review="leaks",
        title=title,
        tag="UNVERIFIED",
        severity="low",
        exploitability="low",
        effort_minutes=1,
        locations=locations,
        detail="d",
        fix="f",
    )


def test_dedupe_keeps_distinct_location_less_findings():
    items = [finding("a"), finding("b"), finding("a")]
    assert [f.title for f in dedupe(items)] == ["a", "b"]
    located = [finding("a", (Location("x.py", 1),)), finding("b", (Location("x.py", 1),))]
    assert [f.title for f in dedupe(located)] == ["a"]
