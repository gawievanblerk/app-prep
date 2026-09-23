import base64
import dataclasses
import json

from dpr.redact import KeyHit, find_keys, is_secret_name, public_prefix, redact, snippet

LIVE = "sk_" + "live_" + "a1B2c3D4e5F6g7H8i9J0k1L2"
TEST = "sk_" + "test_" + "a1B2c3D4e5F6g7H8i9J0k1L2"
AWS = "AKIA" + "ABCDEFGHIJKLMNOP"


def b64(obj):
    raw = json.dumps(obj).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def jwt(role):
    return ".".join([b64({"alg": "HS256", "typ": "JWT"}), b64({"role": role}), "s1gnature_part"])


def test_keyhit_has_no_value_field():
    assert [f.name for f in dataclasses.fields(KeyHit)] == ["kind", "live", "line"]


def test_find_keys_kinds_and_lines():
    text = f'const a = "{LIVE}"\nconst b = "{TEST}"\n\naws = "{AWS}"\n'
    hits = find_keys(text)
    assert [(h.kind, h.live, h.line) for h in hits] == [
        ("stripe-live-secret", True, 1),
        ("stripe-test-secret", False, 2),
        ("aws-access-key-id", True, 4),
    ]


def test_service_role_jwt_is_flagged_but_anon_is_not():
    text = f'const s = "{jwt("service_role")}"\nconst a = "{jwt("anon")}"\n'
    hits = find_keys(text)
    assert [(h.kind, h.line) for h in hits] == [("supabase-service-role-jwt", 1)]


def test_redact_masks_keys_jwts_and_url_passwords():
    text = f'k="{LIVE}" j="{jwt("anon")}" db="postgres://app:hunter2secret@db.local/x"'
    out = redact(text)
    assert LIVE not in out
    assert "hunter2secret" not in out
    assert "eyJ" not in out
    assert "<redacted:stripe-live-secret>" in out
    assert "postgres://app:<redacted:password>@db.local/x" in out


def test_snippet_is_redacted_capped_and_trimmed():
    lines = [f"line{i} {LIVE}" for i in range(10)]
    out = snippet("\n".join(lines), line=3, before=2, after=5)
    assert LIVE not in out
    assert len(out.splitlines()) == 5
    assert len(snippet("x" * 500, 1).splitlines()[0]) == 200


def test_names():
    assert public_prefix("NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY") == "NEXT_PUBLIC_"
    assert public_prefix("SUPABASE_SERVICE_ROLE_KEY") is None
    assert is_secret_name("NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY")
    assert is_secret_name("VITE_OPENAI_API_KEY")
    assert not is_secret_name("NEXT_PUBLIC_SUPABASE_ANON_KEY")


def test_snippet_counts_lines_by_newline_only():
    text = "first\fpage sep\rlone\nsecond line\r\nthird\x1cgroup\n"
    assert snippet(text, 1) == "first\fpage sep\rlone"
    assert snippet(text, 2) == "second line"
    assert snippet(text, 3) == "third\x1cgroup"


SECRET = "Seed" + "Val-" + "88231"


def test_snippet_masks_empty_user_url_credentials():
    line = f'limiter = Limiter(storage_uri="redis://:{SECRET}@cache:6379/0")'
    out = snippet(line, 1)
    assert SECRET not in out
    assert "redis://:<redacted:password>@cache:6379/0" in out


def test_snippet_masks_cli_password_flags():
    text = "\n".join(
        [
            f"python -m app.seed --admin-password {SECRET}",
            f"python seed.py --password={SECRET} && uvicorn app.main:app",
            f'node seed.js --db-password "{SECRET}"',
            "python -m app.seed --password $ADMIN_PASSWORD",
        ]
    )
    for number in (1, 2, 3):
        assert SECRET not in snippet(text, number)
        assert "<redacted:password>" in snippet(text, number)
    assert snippet(text, 4).endswith("--password $ADMIN_PASSWORD")


def test_snippet_masks_secret_query_parameters():
    line = f'const url = "https://api.example.invalid/v1?api_key={SECRET}&city=" + city'
    out = snippet(line, 1)
    assert SECRET not in out
    assert "?api_key=<redacted:secret>&city=" in out
    dynamic = "const url = `${base}/v1?token=${token}`"
    assert snippet(dynamic, 1) == dynamic


def test_snippet_masks_literals_assigned_to_secret_names():
    lines = [
        f'ADMIN_PASSWORD = "{SECRET}"',
        f"const apiKey = '{SECRET}'",
        f'{{"client_secret": "{SECRET}", "name": "demo"}}',
        f'login(user="admin", password="{SECRET}")',
        f'admin_password: str = "{SECRET}"',
        f"ADMIN_PASSWORD={SECRET} python -m app.seed",
        f'if (token === "{SECRET}") return true',
    ]
    for line in lines:
        out = snippet(line, 1)
        assert SECRET not in out, line
        assert "<redacted:" in out, line
    assert snippet("password_hash = get_password_hash(data.password)", 1) == (
        "password_hash = get_password_hash(data.password)"
    )


def test_snippet_masks_before_cutting_long_lines():
    line = "x = call(" + "a" * 174 + f', api_key="{SECRET}")'
    assert line.index(SECRET) == 194
    out = snippet(line, 1)
    assert len(out) <= 200
    assert SECRET[:4] not in out


def test_snippet_masks_concatenated_adjacent_escaped_and_triple_quoted_secrets():
    half_a, half_b = "Half" + "One-" + "7310", "Half" + "Two-" + "7311"
    lines = [
        f'const url = base + "?city=" + city + "&api_key=" + "{SECRET}"',
        f"url = BASE + '&token=' + '{SECRET}'",
        f'ADMIN_PASSWORD = "{half_a}" "{half_b}"',
        f'api_key = "{half_a}" + "{half_b}"',
        f'password = "it\\"s-{SECRET}"',
        f'SECRET_KEY = """{SECRET}"""',
        f"token = '''{SECRET}'''",
    ]
    for line in lines:
        out = snippet(line, 1)
        for value in (SECRET, half_a, half_b):
            assert value not in out, line
        assert "<redacted:" in out, line


def test_redaction_stays_linear_on_long_runs():
    import time

    cases = [
        "-" * 60000,
        "token" * 12000,
        "a.token" * 20000,
        "password-" * 20000,
        "api_key." * 20000,
        "secret: a.b[c]|d, " * 20000,
        "--token-" * 20000,
        "A_TOKEN=" * 50000,
        "TOKEN" * 50000,
        "&token=" * 50000,
        'password = "' + "a" * 60000,
        "x://a:" * 50000,
    ]
    for text in cases:
        started = time.perf_counter()
        redact(text)
        assert time.perf_counter() - started < 1.0, text[:20]


def test_snippet_masks_quoted_values_inside_query_and_form_strings():
    line = f"""curl -X POST "https://api.example.invalid/v1" -d "user=bob&password='{SECRET}'" """
    out = snippet(line, 1)
    assert SECRET not in out
    assert "&password='<redacted:secret>'" in out
    dynamic = 'url = "https://x.example/?token="+token+"&a=1"'
    assert snippet(dynamic, 1) == dynamic


def test_redact_masks_every_email_address_and_keeps_url_password_labels():
    address = "ana.fictional" + "@" + "corpmail.io"
    line = f"client.send(to='{address}', cc=\"{address.upper()}\")  # ops+{address}"
    out = snippet(line, 1)
    assert address not in out and address.upper() not in out
    assert out.count("<redacted:email>") == 3
    url = "postgres://app:" + "Hunter" + "2x@db.corpmail.io/main"
    assert redact(url) == "postgres://app:<redacted:password>@db.corpmail.io/main"
    assert redact("@router.get('/users/{user_id}')") == "@router.get('/users/{user_id}')"
    assert redact('"lodash": "npm:lodash@4.17.21"') == '"lodash": "npm:lodash@4.17.21"'


def test_env_defaults_auth_pairs_and_salts_are_masked():
    value = "fall" + "back-" + "90210x"
    lines = [
        f'SECRET_KEY = os.environ.get("SECRET_KEY", "{value}")',
        f"KEY = getenv('PARTNER_API_KEY', default='{value}')",
        f'PASSWORD = os.environ.get("SYNC_PASSWORD") or "{value}"',
        f'KEYS = {{"A": env.str("A_TOKEN", "{value}")}}',
        f'requests.post(url, auth=("api", "{value}"))',
        f'headers = {{"Authorization": "Bearer {value}"}}',
        f'HASHER = Hashids(salt="{value}", min_length=6)',
    ]
    for line in lines:
        masked = redact(line)
        assert value not in masked, line
        assert "<redacted:" in masked, line
    assert redact('DOMAIN = os.environ.get("DOMAIN", "app.example.invalid")').endswith(
        '"app.example.invalid")'
    )
    assert redact("auth = f'Bearer {token}'") == "auth = f'Bearer {token}'"
