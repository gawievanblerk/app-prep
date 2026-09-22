import json

from dpr.cli import main
from tests.reviews.helpers import write


def test_scan_writes_sarif(tmp_path, capsys):
    root = tmp_path / "app"
    write(root, ".env.example", "NEXT_PUBLIC_ADMIN_SECRET=\n")
    write(root, "app/page.tsx", "export default function Page() { return null }\n")
    out = tmp_path / "out"
    assert main(["scan", str(root), "--format", "md,sarif", "--out", str(out)]) == 0
    [sarif] = list(out.glob("report-*.sarif"))
    data = json.loads(sarif.read_text())
    assert data["version"] == "2.1.0"
    assert any(r["ruleId"] == "LEAK-PUBLIC-SECRET" for r in data["runs"][0]["results"])
    assert sorted(p.suffix for p in out.iterdir()) == [".md", ".sarif"]
    assert main(["scan", str(root), "--format", "xml", "--out", str(out)]) == 2
    assert "unknown format: xml (supported: md, json, sarif)" in capsys.readouterr().err
