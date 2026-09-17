from tests.reviews.helpers import findings_for, write


def locs(found):
    return sorted(str(loc) for f in found for loc in f.locations)


def test_no_sri_and_deserialise(tmp_path):
    write(
        tmp_path,
        "public/index.html",
        '<script src="https://cdn.example.com/a.js"></script>\n'
        '<script src="https://cdn.example.com/b.js" integrity="sha384-x" crossorigin="anonymous"></script>\n'
        '<script src="/local.js"></script>\n',
    )
    write(
        tmp_path,
        "app/cache.py",
        "import pickle, yaml\n"
        "data = pickle.loads(blob)\n"
        "cfg = yaml.load(text)\n"
        "ok = yaml.load(text, Loader=yaml.SafeLoader)\n"
        "ok2 = yaml.safe_load(text)\n",
    )
    assert locs(findings_for(tmp_path, "owasp", "OWASP-A08-NO-SRI")) == ["public/index.html:1"]
    assert locs(findings_for(tmp_path, "owasp", "OWASP-A08-UNSAFE-DESERIALISE")) == [
        "app/cache.py:2",
        "app/cache.py:3",
    ]


def test_ci_untrusted(tmp_path):
    write(
        tmp_path,
        ".github/workflows/pr.yml",
        "on: pull_request_target\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n"
        "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
    )
    write(
        tmp_path,
        ".github/workflows/ci.yml",
        "on: pull_request\njobs:\n  b:\n    steps:\n      - run: echo ${{ github.head_ref }}\n",
    )
    assert locs(findings_for(tmp_path, "owasp", "OWASP-A08-CI-UNTRUSTED")) == [
        ".github/workflows/pr.yml:7"
    ]


def test_unpinned_dependencies(tmp_path):
    write(tmp_path, "api/requirements.txt", "# core\nfastapi>=0.100\nuvicorn\nhttpx==0.27.0\n")
    write(tmp_path, "worker/requirements.txt", "celery>=5\n")
    write(tmp_path, "worker/requirements.lock", "celery==5.3.0\n")
    write(tmp_path, "tools/requirements.txt", "black==24.1.0\nruff==0.6.0\nmypy>=1\n")
    write(tmp_path, "web/package.json", '{"dependencies": {"react": "^18"}}')
    write(tmp_path, "site/package.json", '{"dependencies": {"vue": "^3"}}')
    write(tmp_path, "package-lock.json", "{}")
    write(tmp_path, "site/.keep", "")
    found = findings_for(tmp_path, "owasp", "OWASP-A08-UNPINNED-DEPS")
    assert locs(found) == ["api/requirements.txt:2"]
    (tmp_path / "package-lock.json").unlink()
    assert locs(findings_for(tmp_path, "owasp", "OWASP-A08-UNPINNED-DEPS")) == [
        "api/requirements.txt:2",
        "site/package.json:1",
        "web/package.json:1",
    ]


def test_unpinned_install(tmp_path):
    write(
        tmp_path,
        "api/startup.sh",
        "#!/bin/bash\n# pip install nothing\npip install --quiet pysqlite3-binary\npip install -r requirements.txt\n"
        "pip install tool==1.0\n",
    )
    write(
        tmp_path,
        "azure-pipelines.yml",
        "steps:\n  - script: |\n      npm install\n      npm ci\n      npx tsc --noEmit\n"
        "      npx @azure/static-web-apps-cli deploy dist\n      npx @scope/tool@1.2.3 run\n"
        "      pip install --quiet ruff\n",
    )
    found = {
        f.locations[0].file: f
        for f in findings_for(tmp_path, "owasp", "OWASP-A08-UNPINNED-INSTALL")
    }
    assert [str(loc) for loc in found["api/startup.sh"].locations] == ["api/startup.sh:3"]
    assert "at start-up" in found["api/startup.sh"].detail
    assert [str(loc) for loc in found["azure-pipelines.yml"].locations] == [
        "azure-pipelines.yml:3",
        "azure-pipelines.yml:6",
        "azure-pipelines.yml:8",
    ]


def test_auth_failure_logging(tmp_path):
    write(
        tmp_path,
        "api/auth.py",
        "from fastapi import APIRouter\nrouter = APIRouter()\n"
        "@router.post('/login')\nasync def login(data):\n"
        "    if not ok:\n        raise HTTPException(status_code=401)\n"
        "@router.post('/signin')\nasync def signin(data):\n"
        "    if not ok:\n        logger.warning('failed sign-in')\n        raise HTTPException(status_code=401)\n",
    )
    assert locs(findings_for(tmp_path, "owasp", "OWASP-A09-NO-AUTH-FAIL-LOG")) == ["api/auth.py:4"]


def test_xml_parser_without_defusedxml(tmp_path):
    write(tmp_path, "requirements.txt", "openpyxl==3.1.2\n")
    write(
        tmp_path,
        "app/imports.py",
        "import openpyxl\nimport xml.etree.ElementTree as ET\n"
        "def read(data):\n    wb = openpyxl.load_workbook(data)\n    root = ET.fromstring(data)\n",
    )
    assert locs(findings_for(tmp_path, "owasp", "OWASP-A05-XML-PARSER")) == [
        "app/imports.py:4",
        "app/imports.py:5",
    ]
    write(tmp_path, "requirements.txt", "openpyxl==3.1.2\ndefusedxml==0.7.1\n")
    assert findings_for(tmp_path, "owasp", "OWASP-A05-XML-PARSER") == []
