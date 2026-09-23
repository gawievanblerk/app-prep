from dpr.vendored import detect_vendored, is_vendored, split_name
from dpr.walk import RepoIndex
from tests.reviews.helpers import write

JQUERY_HEAD = "/*!\n * jQuery JavaScript Library v1.10.2\n * http://jquery.com/\n */\n"
BOOTSTRAP_HEAD = "/*!\n  * Bootstrap v5.1.3 (https://getbootstrap.com/)\n  */\n"
LONG = "var a=" + "1+" * 3000 + "1;"


def libraries(root):
    return {(lib.name, lib.version): lib for lib in detect_vendored(RepoIndex(root)).libraries}


def test_split_name_removes_markers_and_versions():
    assert split_name("jquery-1.10.2.min.js") == ("jquery", "1.10.2")
    assert split_name("jquery.dataTables.min.js") == ("jquery.datatables", None)
    assert split_name("bootstrap.bundle.min.css") == ("bootstrap.bundle", None)
    assert split_name("select2.full.js") == ("select2.full", None)
    assert split_name("jquery-ui-1.11.1.custom.css") == ("jquery-ui.custom", "1.11.1")


def test_plugins_and_custom_builds_are_named_by_their_library(tmp_path):
    write(tmp_path, "static/css/jquery-ui-1.11.1.custom.css", "/*! jQuery UI - v1.11.1 */\n")
    write(tmp_path, "static/js/jquery.iviewer.js", "(function($){})(jQuery);\n")
    found = libraries(tmp_path)
    assert ("jQuery UI", "1.11.1") in found
    assert ("jquery.iviewer (jQuery plugin)", None) in found


def test_known_library_files_are_one_library_per_name_and_version(tmp_path):
    write(tmp_path, "static/js/jquery-1.10.2.js", JQUERY_HEAD + "x.innerHTML = y;\n")
    write(tmp_path, "static/js/jquery-1.10.2.min.js", "/*! jQuery v1.10.2 */\nx.innerHTML=y;")
    write(tmp_path, "static/js/jquery.js", "/*!\n * jQuery JavaScript Library v3.6.0\n */\n")
    write(tmp_path, "theme/js/bootstrap5/bootstrap.bundle.js", BOOTSTRAP_HEAD)
    write(tmp_path, "static/js/jquery.dataTables.min.js", "/*! DataTables 1.10.20 */\n")
    found = libraries(tmp_path)
    assert found[("jQuery", "1.10.2")].files == (
        "static/js/jquery-1.10.2.js",
        "static/js/jquery-1.10.2.min.js",
    )
    assert found[("jQuery", "3.6.0")].known
    assert ("DataTables", "1.10.20") in found
    assert found[("Bootstrap", "5.1.3")].folder == "theme/js/bootstrap5"


def test_minified_banner_and_long_line_files_are_libraries(tmp_path):
    write(tmp_path, "static/js/flatpackr.min.js", "/*! flatpickr v4.6.3, @license MIT */\nf();")
    write(tmp_path, "static/js/bootsrap.min.js", "!function(){}();")
    write(tmp_path, "static/js/widget.js", "/*! Widget v1.2.0 | MIT */\nw();\n")
    write(tmp_path, "static/js/blob.js", LONG)
    found = libraries(tmp_path)
    assert found[("flatpickr", "4.6.3")].known
    assert not found[("bootsrap", None)].known
    assert found[("Widget", "1.2.0")].evidence == "licence banner"
    assert found[("blob", None)].evidence == "minified content (very long lines)"


def test_app_code_is_not_vendored(tmp_path):
    write(tmp_path, "static/js/app.js", "// Copyright (c) 2024 Our Company\nel.innerHTML = x;\n")
    write(tmp_path, "src/bootstrap/__init__.py", "")
    write(tmp_path, "src/bootstrap/start.js", "start();\n")
    write(tmp_path, "src/components/select2.tsx", "export {}\n")
    write(tmp_path, "lib/pdf.js", "export function pdf() {}\n")
    index = RepoIndex(tmp_path)
    assert detect_vendored(index).files == frozenset()
    assert not is_vendored(index, "static/js/app.js")


def test_third_party_and_library_named_folders(tmp_path):
    write(tmp_path, "web/third-party/site/OneDrive.js", "var nonce = Math.random();\n")
    write(tmp_path, "web/third-party/site/page.html", "<script src='https://x.test/a.js'>")
    write(tmp_path, "web/third-party/site/aa-notes.aux", "notes")
    write(tmp_path, "web/third-party/contacts.md", "# Suppliers\n")
    write(tmp_path, "static/pdfjs/web/viewer.js", "viewer();\n")
    write(tmp_path, "static/pdfjs/package.json", '{"name": "pdfjs-dist", "version": "2.6.347"}')
    write(tmp_path, "static/pdfjs/build/pdf.js.map", "{}")
    index = RepoIndex(tmp_path)
    found = {lib.folder: lib for lib in detect_vendored(index).libraries}
    assert found["web/third-party/site"].name == "site"
    assert found["web/third-party/site"].files[0] == "web/third-party/site/OneDrive.js"
    assert not is_vendored(index, "web/third-party/contacts.md")
    assert (found["static/pdfjs"].name, found["static/pdfjs"].version) == ("PDF.js", "2.6.347")
    assert is_vendored(index, "web/third-party/site/page.html")
    assert is_vendored(index, "static/pdfjs/build/pdf.js.map")


def test_copied_package_with_its_own_licence_is_one_library(tmp_path):
    write(tmp_path, "app/djangojs/LICENSE", "MIT")
    write(tmp_path, "app/djangojs/__init__.py", '__version__ = "0.8.1"\n')
    write(tmp_path, "app/djangojs/views.py", "x = 1\n")
    write(tmp_path, "app/djangojs/phantomjs/runner.js", "eval(page);\n")
    write(tmp_path, "app/djangojs/static/js/libs/jquery-1.9.1.js", JQUERY_HEAD)
    found = libraries(tmp_path)
    assert list(found) == [("djangojs", "0.8.1")]
    assert found[("djangojs", "0.8.1")].evidence == "own licence file and no project manifest"
    assert len(found[("djangojs", "0.8.1")].files) == 5


def test_licence_folder_with_a_manifest_below_is_a_project_not_a_copy(tmp_path):
    write(tmp_path, "backend/LICENSE", "MIT")
    write(tmp_path, "backend/app/requirements.txt", "django\n")
    write(tmp_path, "backend/app/views.py", "x = 1\n")
    write(tmp_path, "packages/ui/LICENSE", "MIT")
    write(tmp_path, "packages/ui/package.json", "{}")
    write(tmp_path, "packages/ui/index.js", "x()\n")
    assert detect_vendored(RepoIndex(tmp_path)).files == frozenset()


def test_collected_static_folder_is_skipped_and_only_its_libraries_are_named(tmp_path):
    write(tmp_path, "project/static/admin/js/core.js", "core();\n")
    write(tmp_path, "project/static/js/app.js", "el.innerHTML = x;\n")
    write(tmp_path, "project/static/js/jquery.min.js", "/*! jQuery v3.6.0 */\n")
    write(tmp_path, "staticfiles/js/app.js", "el.innerHTML = x;\n")
    write(tmp_path, "shop/static/js/app.js", "el.innerHTML = x;\n")
    index = RepoIndex(tmp_path)
    assert is_vendored(index, "project/static/js/app.js")
    assert is_vendored(index, "staticfiles/js/app.js")
    assert not is_vendored(index, "shop/static/js/app.js")
    assert [(lib.name, lib.version) for lib in detect_vendored(index).libraries] == [
        ("jQuery", "3.6.0")
    ]


def test_documentation_copies_are_vendored_but_not_libraries(tmp_path):
    write(tmp_path, "app/docs/third-party/flow_files/OneDrive.js", "var n = Math.random();\n")
    write(tmp_path, "app/docs/third-party/flow_files/jquery-1.7.1.min.js", "/*! jQuery v1.7.1 */")
    write(tmp_path, "app/docs/third-party/flow.html", "<script src='flow_files/app.js'>")
    write(tmp_path, "app/static/js/jquery-1.7.1.min.js", "/*! jQuery v1.7.1 */")
    index = RepoIndex(tmp_path)
    assert [lib.files for lib in detect_vendored(index).libraries] == [
        ("app/static/js/jquery-1.7.1.min.js",)
    ]
    assert is_vendored(index, "app/docs/third-party/flow_files/OneDrive.js")
    assert is_vendored(index, "app/docs/third-party/flow_files/jquery-1.7.1.min.js")


def test_version_constants_name_the_version(tmp_path):
    body = "/* Copyright 2019 Mozilla Foundation */\n" + "var x = 1;\n" * 400
    write(tmp_path, "static/pdfjs/build/pdf.worker.js", body + "var pdfjsVersion = '2.2.222';\n")
    write(tmp_path, "static/pdfjs/web/viewer.js", "viewer();\n")
    write(tmp_path, "static/js/jquery.js", "/* jQuery */\n" + body + 'version = "1.12.4",\n')
    write(tmp_path, "static/js/moment.js", body + 'var otherVersion = "9.9.9";\n')
    found = libraries(tmp_path)
    assert ("PDF.js", "2.2.222") in found
    assert ("jQuery", "1.12.4") in found
    assert ("Moment.js", None) in found
