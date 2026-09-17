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
