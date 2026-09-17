from tests.reviews.helpers import findings_for, write


def locs(found):
    return sorted((str(f.locations[0]), f.tag.value) for f in found)


def test_raw_sql(tmp_path):
    write(
        tmp_path,
        "app/api/search/route.ts",
        "export async function GET(req: Request) {\n"
        "  const q = new URL(req.url).searchParams.get('q')\n"
        "  await prisma.$queryRawUnsafe(`select * from notes where body like '%${q}%'`)\n"
        "  await prisma.$queryRaw`select * from notes where id = ${q}`\n"
        "  await pool.query('select 1')\n"
        "}\n",
    )
    write(
        tmp_path,
        "shop/views.py",
        "def search(request):\n"
        "    term = request.GET['q']\n"
        "    cursor.execute(f\"select * from orders where name = '{term}'\")\n"
        "    cursor.execute('select * from orders where id = %s', [term])\n"
        "def report(table):\n    return db.execute(text('select * from ' + table))\n",
    )
    write(
        tmp_path,
        "shop/charts.py",
        "def label(ax, height):\n    ax.text(1, height, f'{height:.2f}')\n",
    )
    write(
        tmp_path,
        "alembic/versions/001_add.py",
        "def upgrade():\n    for name in COLUMNS:\n        op.execute(f'ALTER TABLE t ADD COLUMN {name} text')\n",
    )
    assert locs(findings_for(tmp_path, "owasp", "OWASP-A03-RAW-SQL")) == [
        ("app/api/search/route.ts:3", "CONFIRMED"),
        ("shop/views.py:3", "CONFIRMED"),
        ("shop/views.py:6", "INFERRED"),
    ]


def test_xss_sinks(tmp_path):
    write(
        tmp_path,
        "src/Bio.tsx",
        "export const Bio = ({ bio }) => (\n  <div>\n    <p dangerouslySetInnerHTML={{ __html: bio }} />\n"
        "    <p dangerouslySetInnerHTML={{ __html: '<b>static</b>' }} />\n  </div>\n)\n",
    )
    write(
        tmp_path,
        "src/Note.vue",
        '<template>\n  <div v-html="note.body"></div>\n</template>\n<script>\nexport default {}\n</script>\n',
    )
    write(
        tmp_path,
        "src/render.js",
        "el.innerHTML = `<p>${comment}</p>`\nel.innerHTML = '<p>ok</p>'\n",
    )
    write(
        tmp_path,
        "web/views.py",
        "from markupsafe import Markup\ndef show(bio):\n    return Markup(bio)\nsafe = Markup('<b>x</b>')\n",
    )
    assert [loc for loc, _ in locs(findings_for(tmp_path, "owasp", "OWASP-A03-XSS-SINK"))] == [
        "src/Bio.tsx:3",
        "src/Note.vue:2",
        "src/render.js:1",
        "web/views.py:3",
    ]


def test_command_execution(tmp_path):
    write(
        tmp_path,
        "server/convert.js",
        "const { exec } = require('child_process')\n"
        "exec(`convert ${req.body.file} out.png`)\nexec('ls -la')\nconst fn = new Function(code)\n",
    )
    write(
        tmp_path,
        "tools/run.py",
        "import os, subprocess\n"
        "subprocess.run(f'tar -xf {name}', shell=True)\n"
        "subprocess.run(['tar', '-xf', name])\n"
        "os.system('make build')\n"
        "eval(user_expression)\n",
    )
    assert [loc for loc, _ in locs(findings_for(tmp_path, "owasp", "OWASP-A03-COMMAND"))] == [
        "server/convert.js:2",
        "server/convert.js:4",
        "tools/run.py:2",
        "tools/run.py:5",
    ]


def test_html_email(tmp_path):
    write(
        tmp_path,
        "app/services/email_service.py",
        "import html\n"
        "def welcome(first_name, url):\n"
        "    body = f'<h2>Welcome, {first_name}!</h2><a href=\"{url}\">Go</a>'\n"
        "    safe = html.escape(first_name)\n"
        "    ok = f'<p>Hi {safe}</p>'\n"
        "    plain = f'Hi {first_name}'\n"
        "    also_ok = f'<p>{html.escape(url)}</p>'\n"
        "    return body, ok, plain, also_ok\n"
        "def rows(values):\n"
        "    detail = [('Name', values['name']), ('Note', values['note'])]\n"
        "    items_html = ''.join(f'<li>{label}: {html.escape(value)}</li>' for label, value in detail)\n"
        "    return f'<ul>{items_html}</ul><p>{FOOTER}</p>'\n"
        "def base(content, preview):\n"
        "    name = settings.app_name\n"
        "    return f'<html><body><h1>{name}</h1>{content}<p>{self._settings.footer}</p></body></html>'\n",
    )
    write(tmp_path, "app/services/report.py", "def page(name):\n    return f'<p>{name}</p>'\n")
    [f] = findings_for(tmp_path, "owasp", "OWASP-A03-HTML-EMAIL")
    assert [str(loc) for loc in f.locations] == ["app/services/email_service.py:3"]


def test_weak_random_and_secret_urls(tmp_path):
    write(
        tmp_path,
        "lib/tokens.ts",
        "const resetToken = Math.random().toString(36)\nconst jitter = Math.random() * 10\n"
        "const url = `${base}/api?apikey=${key}`\n"
        "const link = `${base}/reset-password?token=${token}`\n"
        "const doc = 'https://example.com/?token=abc'\n",
    )
    write(
        tmp_path,
        "app/codes.py",
        "import random\notp_code = random.randint(100000, 999999)\nshuffle = random.random()\n",
    )
    assert [
        loc for loc, _ in locs(findings_for(tmp_path, "owasp", "OWASP-A02-WEAK-RANDOM-TOKEN"))
    ] == [
        "app/codes.py:2",
        "lib/tokens.ts:1",
    ]
    assert [loc for loc, _ in locs(findings_for(tmp_path, "owasp", "OWASP-A02-SECRET-IN-URL"))] == [
        "lib/tokens.ts:3"
    ]


def test_client_price_and_ssrf(tmp_path):
    write(
        tmp_path,
        "app/api/checkout/route.ts",
        "export async function POST(req: Request) {\n  const body = await req.json()\n"
        "  await stripe.paymentIntents.create({ amount: body.amount, currency: 'usd' })\n"
        "  await stripe.paymentIntents.create({ amount: PRICES[body.productId], currency: 'usd' })\n}\n",
    )
    write(
        tmp_path,
        "app/api/preview/route.ts",
        "export async function GET(req: Request) {\n"
        "  const target = new URL(req.url).searchParams.get('url')\n  return fetch(target)\n}\n",
    )
    write(
        tmp_path,
        "api/main.py",
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "@app.get('/fetch')\nasync def fetch_url(url: str):\n    return httpx.get(url)\n"
        "@app.get('/safe')\nasync def safe(url: str):\n"
        "    if urlparse(url).hostname not in ALLOWED_HOSTS:\n        raise ValueError()\n"
        "    return httpx.get(url)\n",
    )
    [price] = findings_for(tmp_path, "owasp", "OWASP-A04-CLIENT-PRICE")
    assert str(price.locations[0]) == "app/api/checkout/route.ts:3"
    assert [loc for loc, _ in locs(findings_for(tmp_path, "owasp", "OWASP-A10-SSRF"))] == [
        "api/main.py:5",
        "app/api/preview/route.ts:3",
    ]
