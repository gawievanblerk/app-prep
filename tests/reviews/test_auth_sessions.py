from tests.reviews.auth_app import ROUTES, SERVICE, auth_app
from tests.reviews.helpers import findings_for, write


def test_logout_that_only_deletes_cookies_is_confirmed(tmp_path):
    auth_app(tmp_path)
    [finding] = findings_for(tmp_path, "auth", "AUTH-LOGOUT-NO-REVOKE")
    assert (finding.tag.value, str(finding.locations[0])) == (
        "CONFIRMED",
        "api/app/routes/auth.py:27",
    )


def test_logout_with_a_helper_call_is_inferred(tmp_path):
    routes = ROUTES.replace(
        '    response.delete_cookie("access_token")\n',
        '    response.delete_cookie("access_token")\n    audit_logout(response)\n',
    )
    auth_app(tmp_path, routes=routes)
    [finding] = findings_for(tmp_path, "auth", "AUTH-LOGOUT-NO-REVOKE")
    assert finding.tag.value == "INFERRED" and finding.proof_needed


def test_logout_that_revokes_passes(tmp_path):
    routes = ROUTES.replace(
        '    response.delete_cookie("access_token")\n',
        '    response.delete_cookie("access_token")\n'
        "    current.tokens_invalidated_at = datetime.now(timezone.utc)\n",
    )
    auth_app(tmp_path, routes=routes)
    assert findings_for(tmp_path, "auth", "AUTH-LOGOUT-NO-REVOKE") == []
    write(
        tmp_path,
        "server/logout.js",
        "router.post('/logout', (req, res) => { req.session.destroy(() => res.json({})) })\n",
    )
    assert findings_for(tmp_path, "auth", "AUTH-LOGOUT-NO-REVOKE") == []


def refresh_app(root, body):
    routes = ROUTES.replace(
        'async def refresh(token: str):\n    return {"ok": True}\n',
        "async def refresh(token: str):\n    return AuthService().refresh(token)\n",
    )
    service = SERVICE + "\n    def refresh(self, token):\n" + body
    return auth_app(root, routes=routes, service=service)


def test_refresh_that_reissues_without_sign_in_time(tmp_path):
    refresh_app(
        tmp_path,
        "        payload = decode_token(token)\n"
        "        return create_refresh_token({'sub': payload['sub']})\n",
    )
    [finding] = findings_for(tmp_path, "auth", "AUTH-REFRESH-NO-ABSOLUTE-CAP")
    assert (finding.tag.value, str(finding.locations[0])) == (
        "INFERRED",
        "api/app/routes/auth.py:33",
    )


def test_refresh_that_keeps_auth_time_passes(tmp_path):
    refresh_app(
        tmp_path,
        "        payload = decode_token(token)\n"
        "        if now() - payload['auth_time'] > LIMIT:\n            raise Expired()\n"
        "        return create_refresh_token({'sub': payload['sub'], 'auth_time': payload['auth_time']})\n",
    )
    assert findings_for(tmp_path, "auth", "AUTH-REFRESH-NO-ABSOLUTE-CAP") == []


def test_refresh_that_issues_no_new_refresh_token_is_not_judged(tmp_path):
    refresh_app(
        tmp_path, "        return {'access_token': create_access_token(decode_token(token))}\n"
    )
    assert findings_for(tmp_path, "auth", "AUTH-REFRESH-NO-ABSOLUTE-CAP") == []


def test_sign_in_without_limit_or_lockout(tmp_path):
    auth_app(tmp_path)
    [finding] = findings_for(tmp_path, "auth", "AUTH-NO-LOCKOUT")
    assert (finding.tag.value, finding.severity.value) == ("INFERRED", "medium")
    assert str(finding.locations[0]) == "api/app/routes/auth.py:9"


def test_limiter_or_lockout_columns_pass_case_1(tmp_path):
    limited = ROUTES.replace(
        '@router.post("/login")\n', '@router.post("/login")\n@limiter.limit("5/minute")\n'
    )
    auth_app(tmp_path, routes=limited)
    assert findings_for(tmp_path, "auth", "AUTH-NO-LOCKOUT") == []
    auth_app(tmp_path, routes=ROUTES)
    write(
        tmp_path,
        "api/app/models.py",
        "class User(Base):\n    __tablename__ = 'users'\n    failed_login_attempts = Column(Integer)\n",
    )
    assert findings_for(tmp_path, "auth", "AUTH-NO-LOCKOUT") == []
