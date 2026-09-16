from dpr.model import Tag
from dpr.reviews.leaks import ROTATE
from tests.reviews.helpers import findings_for, write

LIVE = "sk_" + "live_" + "a1B2c3D4e5F6g7H8i9J0k1L2"
TEST = "sk_" + "test_" + "a1B2c3D4e5F6g7H8i9J0k1L2"


def test_public_secret(tmp_path):
    write(tmp_path, ".env.example",
          "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=\nNEXT_PUBLIC_SUPABASE_ANON_KEY=\nSUPABASE_SERVICE_ROLE_KEY=\n")
    write(tmp_path, "lib/a.ts", "const k = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY\n")
    [f] = findings_for(tmp_path, "leaks", "LEAK-PUBLIC-SECRET")
    assert [str(loc) for loc in f.locations] == [".env.example:1", "lib/a.ts:1"]
    assert (f.tag, f.severity.value) == (Tag.CONFIRMED, "critical")
    assert f.fix.startswith(ROTATE)
    assert "rename NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY to SUPABASE_SERVICE_ROLE_KEY" in f.fix
    assert f.snippet is None


def test_hardcoded_key_live_and_test(tmp_path):
    write(tmp_path, "lib/stripe.ts", f'import Stripe from "stripe"\nexport const s = new Stripe("{LIVE}")\n')
    write(tmp_path, "scripts/seed.py", f'KEY = "{TEST}"\n')
    found = {f.locations[0].file: f for f in findings_for(tmp_path, "leaks", "LEAK-HARDCODED-KEY")}
    live = found["lib/stripe.ts"]
    assert (live.locations[0].line, live.severity.value) == (2, "critical")
    assert "stripe-live-secret" in live.title
    assert LIVE not in (live.snippet or "") and "<redacted:stripe-live-secret>" in live.snippet
    assert found["scripts/seed.py"].severity.value == "high"


def test_key_in_build_output(tmp_path):
    write(tmp_path, "src/a.ts", "export {}\n")
    write(tmp_path, "dist/assets/main.js", f'var a="x";var k="{LIVE}";')
    [f] = findings_for(tmp_path, "leaks", "LEAK-KEY-IN-BUILD")
    assert str(f.locations[0]) == "dist/assets/main.js:1"
    assert f.snippet is None


def test_sourcemaps(tmp_path):
    write(tmp_path, "next.config.js", "module.exports = {\n  productionBrowserSourceMaps: true,\n}\n")
    write(tmp_path, ".next/static/chunks/main.js.map", "{}")
    found = findings_for(tmp_path, "leaks", "LEAK-SOURCEMAP")
    assert sorted(str(f.locations[0]) for f in found) == [
        ".next/static/chunks/main.js.map:1", "next.config.js:2",
    ]


def test_sentry_pii(tmp_path):
    write(tmp_path, "sentry.client.config.ts",
          'import * as Sentry from "@sentry/nextjs"\nSentry.init({\n  dsn: "x",\n  sendDefaultPii: true,\n})\n')
    write(tmp_path, "sentry.server.config.ts",
          'import * as Sentry from "@sentry/nextjs"\nSentry.init({ dsn: "x" })\n')
    write(tmp_path, "sentry.edge.config.ts",
          'import * as Sentry from "@sentry/nextjs"\n'
          'Sentry.init({ dsn: "x", beforeSend(event) { return event } })\n')
    write(tmp_path, "app/settings.py",
          "import sentry_sdk\nsentry_sdk.init(\n    dsn='x',\n    send_default_pii=True,\n)\n")
    found = sorted((f.locations[0].file, f.locations[0].line) for f in
                   findings_for(tmp_path, "leaks", "LEAK-SENTRY-PII"))
    assert found == [
        ("app/settings.py", 4), ("sentry.client.config.ts", 4), ("sentry.server.config.ts", 2),
    ]
