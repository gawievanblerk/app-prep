from tests.reviews.helpers import findings_for, write

COMPOSITION = "BASE-PASSWORD-COMPOSITION"
EXPIRY = "BASE-PASSWORD-EXPIRY"


def test_composition_message_is_confirmed(tmp_path):
    write(
        tmp_path,
        "api/schemas.py",
        "def validate_password(password):\n"
        "    if not any(c.isupper() for c in password):\n"
        '        raise ValueError("Password must contain at least one uppercase letter")\n',
    )
    [finding] = findings_for(tmp_path, "baseline", COMPOSITION)
    assert finding.tag.value == "CONFIRMED"
    assert str(finding.locations[0]) == "api/schemas.py:3"


def test_composition_regex_on_password_is_inferred(tmp_path):
    write(
        tmp_path,
        "src/signup.ts",
        "export const schema = z.object({\n  password: z.string().min(12).regex(/[A-Z]/),\n});\n",
    )
    [finding] = findings_for(tmp_path, "baseline", COMPOSITION)
    assert finding.tag.value == "INFERRED"
    assert finding.proof_needed


def test_custom_validator_class_is_confirmed(tmp_path):
    write(
        tmp_path,
        "web/settings.py",
        "AUTH_PASSWORD_VALIDATORS = [\n"
        "    {'NAME': 'accounts.validators.UppercaseValidator'},\n"
        "    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},\n"
        "]\n",
    )
    [finding] = findings_for(tmp_path, "baseline", COMPOSITION)
    assert [loc.line for loc in finding.locations] == [2]


def test_length_only_rules_and_tests_are_not_flagged(tmp_path):
    write(
        tmp_path,
        "web/settings.py",
        "AUTH_PASSWORD_VALIDATORS = [\n"
        "    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},\n"
        "    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},\n"
        "]\n",
    )
    write(
        tmp_path,
        "tests/test_signup.py",
        'MESSAGE = "Password must contain a number"\n',
    )
    assert findings_for(tmp_path, "baseline", COMPOSITION) == []


def test_message_away_from_any_password_is_not_flagged(tmp_path):
    write(
        tmp_path,
        "src/form.ts",
        "// password reset lives elsewhere\n\n\n\n\n\n"
        'const hint = "Username must contain a letter";\n',
    )
    assert findings_for(tmp_path, "baseline", COMPOSITION) == []


def test_scheduled_password_expiry_is_flagged(tmp_path):
    write(tmp_path, "web/settings.py", "PASSWORD_EXPIRY_DAYS = 90\n")
    write(tmp_path, "src/user.ts", "const passwordMaxAge = 60 * 24 * 3600;\n")
    [finding] = findings_for(tmp_path, "baseline", EXPIRY)
    assert finding.tag.value == "INFERRED"
    assert {str(loc) for loc in finding.locations} == {"web/settings.py:1", "src/user.ts:1"}


def test_reset_link_and_token_expiry_are_not_flagged(tmp_path):
    write(
        tmp_path,
        "src/models/user.ts",
        "const user = { resetPasswordExpires: Date.now() + 3600000 };\n"
        "const PASSWORD_RESET_TOKEN_EXPIRY = 3600;\n"
        "const password_reset_expires_at = null;\n",
    )
    write(tmp_path, "web/settings.py", "# PASSWORD_EXPIRY_DAYS = 90\n")
    assert findings_for(tmp_path, "baseline", EXPIRY) == []
