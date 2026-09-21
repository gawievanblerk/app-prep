from tests.reviews.helpers import findings_for, write

VITE_JS = "export default {\n  build: {\n    sourcemap: true,\n  },\n}\n"
VITE_TS = "import { defineConfig } from 'vite'\nexport default defineConfig({\n  build: { sourcemap: true },\n})\n"


def test_vite_config_twins_collapse_to_the_file_vite_loads(tmp_path):
    write(tmp_path, "web/vite.config.ts", VITE_TS)
    write(tmp_path, "web/vite.config.js", VITE_JS)
    write(
        tmp_path,
        "web/vite.config.d.ts",
        "declare const _default: unknown\nexport default _default\n",
    )
    write(tmp_path, "admin/vite.config.ts", VITE_TS)
    found = {f.locations[0].file: f for f in findings_for(tmp_path, "leaks", "LEAK-SOURCEMAP")}
    assert set(found) == {"web/vite.config.js", "admin/vite.config.ts"}
    web = found["web/vite.config.js"]
    assert [str(loc) for loc in web.locations] == ["web/vite.config.js:3", "web/vite.config.ts:3"]
    assert "The same setting is in vite.config.ts, which vite does not load" in web.detail
    assert "does not load" not in found["admin/vite.config.ts"].detail


def test_values_escaped_in_joined_loops_and_numbers_are_safe(tmp_path):
    write(
        tmp_path,
        "app/services/email_service.py",
        "import html\n"
        "def rows(columns, items):\n"
        "    head = ''.join(f'<th>{html.escape(h)}</th>' for _, h in columns)\n"
        "    body = ''.join('<tr>' + ''.join(f'<td>{html.escape(str(i.get(k)))}</td>' for k, _ in columns) + '</tr>' for i in items)\n"
        "    return f'<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>'\n"
        "def alert(name: str, threshold: int, days: int | None):\n"
        "    return f'<p>{html.escape(name)} ends within {threshold} days, {days} left</p>'\n",
    )
    assert findings_for(tmp_path, "owasp", "OWASP-A03-HTML-EMAIL") == []


def test_joined_loop_with_a_raw_value_is_still_reported(tmp_path):
    write(
        tmp_path,
        "app/services/email_service.py",
        "def rows(items):\n"
        "    table = ''.join(f'<tr><td>{item.name}</td></tr>' for item in items)\n"
        "    return f'<table>{table}</table>'\n",
    )
    [finding] = findings_for(tmp_path, "owasp", "OWASP-A03-HTML-EMAIL")
    assert [str(loc) for loc in finding.locations] == [
        "app/services/email_service.py:2",
        "app/services/email_service.py:3",
    ]


def test_shell_operators_are_not_package_names(tmp_path):
    write(
        tmp_path,
        "api/startup.sh",
        'pip install --quiet pysqlite3-binary 2>&1 || echo "skipped"\n'
        "pip install -r requirements.txt && echo done\n",
    )
    write(tmp_path, "azure-pipelines.yml", "steps:\n  - script: npm install && npm run build\n")
    found = {
        f.locations[0].file: f
        for f in findings_for(tmp_path, "owasp", "OWASP-A08-UNPINNED-INSTALL")
    }
    assert found["api/startup.sh"].detail.startswith(
        "pip installs pysqlite3-binary without a pinned version at start-up."
    )
    assert (
        "2>&1" not in found["api/startup.sh"].detail and "||" not in found["api/startup.sh"].detail
    )
    assert [str(loc) for loc in found["api/startup.sh"].locations] == ["api/startup.sh:1"]
    assert "npm ci installs what is locked" in found["azure-pipelines.yml"].detail
