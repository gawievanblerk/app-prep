from dpr import reviews, rules
from dpr.discovery.detect import detect
from dpr.walk import RepoIndex


def write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def findings_for(root, review, rule_id, **options):
    reviews.available()
    index = RepoIndex(root)
    ctx = rules.Context(index=index, detection=detect(index), options=rules.Options(**options))
    return [f for f in rules.run_checks(review, ctx) if f.rule_id == rule_id]
