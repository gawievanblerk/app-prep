from dpr.api import review
from tests.reviews.helpers import findings_for, write

JQUERY = (
    "/*!\n * jQuery JavaScript Library v1.10.2\n */\n"
    "elem.innerHTML = value;\nvar fn = new Function(code);\n"
)


def vendored_app(root):
    write(root, "shop/static/js/jquery-1.10.2.js", JQUERY)
    write(root, "shop/static/js/jquery-1.10.2.min.js", "/*! jQuery v1.10.2 */\nx.innerHTML=y;")
    write(root, "shop/static/js/app.js", "el.innerHTML = message;\n")
    write(
        root,
        "docs/third-party/site/OneDrive.js",
        "var nonce = Math.random();\nvar u = '/api?token=' + t;\nel.innerHTML = x;\n",
    )
    write(root, "docs/third-party/site/page.html", '<script src="https://cdn.test/a.js"></script>')
    write(root, "shop/djangojs/LICENSE", "MIT")
    write(root, "shop/djangojs/__init__.py", '__version__ = "0.8.1"\n')
    write(root, "shop/djangojs/runner.py", "eval(page)\nprint(request.body)\n")
    write(root, "static/pdfjs/web/viewer.js", "viewer();\n")
    write(root, "static/pdfjs/build/pdf.js.map", "{}")


def test_each_vendored_library_is_reported_once_as_a_component(tmp_path):
    vendored_app(tmp_path)
    found = {f.title: f for f in findings_for(tmp_path, "owasp", "OWASP-A06-VENDORED-LIB")}
    assert sorted(found) == [
        "Third-party library PDF.js is copied into the repository",
        "Third-party library djangojs 0.8.1 is copied into the repository",
        "Third-party library jQuery 1.10.2 is copied into the repository",
        "Third-party library site is copied into the repository",
    ]
    jquery = found["Third-party library jQuery 1.10.2 is copied into the repository"]
    assert [str(loc) for loc in jquery.locations] == [
        "shop/static/js/jquery-1.10.2.js:1",
        "shop/static/js/jquery-1.10.2.min.js:1",
    ]
    assert (jquery.severity.value, jquery.tag.value, jquery.owasp) == ("low", "CONFIRMED", "A06")
    assert jquery.fix.startswith("Manage it as a dependency and keep it updated")
    site = found["Third-party library site is copied into the repository"]
    assert site.tag.value == "INFERRED" and "third-party folder" in site.detail


def test_sink_rules_skip_vendored_files(tmp_path):
    vendored_app(tmp_path)

    def files(review_slug, rule_id):
        return sorted({f.locations[0].file for f in findings_for(tmp_path, review_slug, rule_id)})

    assert files("owasp", "OWASP-A03-XSS-SINK") == ["shop/static/js/app.js"]
    assert files("owasp", "OWASP-A03-COMMAND") == []
    assert files("owasp", "OWASP-A02-WEAK-RANDOM-TOKEN") == []
    assert files("owasp", "OWASP-A02-SECRET-IN-URL") == []
    assert files("owasp", "OWASP-A08-NO-SRI") == []
    assert files("leaks", "LEAK-SOURCEMAP") == []
    assert files("leaks", "LEAK-LOGGED-PII") == []


def test_the_same_sinks_in_app_code_are_still_reported(tmp_path):
    write(
        tmp_path, "shop/static/js/app.js", "var nonce = Math.random();\nvar f = new Function(c);\n"
    )
    write(tmp_path, "shop/runner.py", "eval(page)\n")
    write(tmp_path, "shop/templates/page.html", '<script src="https://cdn.test/a.js"></script>')
    assert findings_for(tmp_path, "owasp", "OWASP-A06-VENDORED-LIB") == []
    assert len(findings_for(tmp_path, "owasp", "OWASP-A03-COMMAND")) == 2
    assert len(findings_for(tmp_path, "owasp", "OWASP-A02-WEAK-RANDOM-TOKEN")) == 1
    assert len(findings_for(tmp_path, "owasp", "OWASP-A08-NO-SRI")) == 1


def test_vendored_libraries_are_one_register_issue_per_app(tmp_path):
    vendored_app(tmp_path)
    report = review(tmp_path, reviews=["owasp"])
    [issue] = [i for i in report.register if "OWASP-A06-VENDORED-LIB" in i.findings]
    assert issue.title == "Third-party libraries are copied into the repository"
    assert (issue.count, issue.severity.value) == (4, "low")
    categories = next(p for p in report.sections["owasp"].parts if p.title == "Categories reviewed")
    assert "- A06 Vulnerable and outdated components: 4 finding(s) above." in categories.body
