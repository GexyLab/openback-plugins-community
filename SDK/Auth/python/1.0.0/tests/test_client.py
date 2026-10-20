import base64
import hashlib
import json
import os
import stat
import threading
import time

import httpx
import pytest

from conftest import CLIENT_ID, ISSUER, USER, FakePool, b64url, json_response, query
from openback_app_auth import (AppAuthError, Client, FileStorage, MemoryStorage, MfaEnrollRequired, MfaRequired,
                               PasswordChangeRequired, SignedIn, VerificationRequired)


def make_client(pool: FakePool, **kwargs) -> Client:
    return Client(ISSUER + "/", CLIENT_ID, http_client=pool.http(), **kwargs)


def expire(client: Client) -> None:
    """Make the stored access token look about to expire."""
    client._save({**client._state, "expiresAt": int(time.time() * 1000) + 10_000})


# --- sign-in and outcomes ------------------------------------------------------------------------------------------------

def test_sign_in_keeps_session_and_notifies(pool):
    storage = MemoryStorage()
    client = make_client(pool, storage=storage)
    assert client.issuer == ISSUER  # trailing slash stripped
    seen = []
    client.on_auth_state_changed(lambda user, org: seen.append(user.id if user else None))
    assert seen == [None]

    outcome = client.sign_in_with_password("ada@example.com", "pw")
    assert isinstance(outcome, SignedIn) and outcome.status == "ok"
    assert outcome.user.id == "usr_1" and outcome.user.attributes == {"plan": "pro"}
    assert "access_token" not in outcome.raw and "refresh_token" not in outcome.raw
    assert client.is_signed_in and client.current_user.email == "ada@example.com"
    assert client.access_token_claims["sub"] == "usr_1"
    assert seen == [None, "usr_1"]

    stored = json.loads(storage.get(f"openback.auth.{CLIENT_ID}"))
    assert set(stored) == {"accessToken", "refreshToken", "idToken", "expiresAt", "user", "org"}
    assert stored["expiresAt"] > time.time() * 1000 + 800_000  # epoch ms

    req = pool.last("POST", "/api/v1/signin/password")
    assert req.headers["x-client-id"] == CLIENT_ID
    assert req.headers["accept"] == "application/json"
    assert req.headers["content-type"] == "application/json"
    assert "authorization" not in req.headers and "origin" not in req.headers
    assert json.loads(req.content) == {"email": "ada@example.com", "password": "pw"}  # no None fields


def test_unsubscribe_and_listener_errors_ignored(pool):
    client = make_client(pool)
    calls = []

    def bad(user, org):
        raise RuntimeError("boom")

    client.on_auth_state_changed(bad)
    unsubscribe = client.on_auth_state_changed(lambda u, o: calls.append(u))
    unsubscribe()
    client.sign_in_with_password("a@b.c", "pw")
    assert calls == [None]


@pytest.mark.parametrize("answer,cls", [
    ({"status": "verification_required"}, VerificationRequired),
    ({"status": "mfa_required", "mfa_token": "mfa_x"}, MfaRequired),
    ({"status": "mfa_enroll_required", "mfa_token": "mfa_y"}, MfaEnrollRequired),
    ({"status": "password_change_required", "change_token": "chg_z"}, PasswordChangeRequired),
])
def test_other_outcomes_do_not_sign_in(pool, answer, cls):
    pool.routes[("POST", "/api/v1/signin/password")] = json_response(200, answer)
    client = make_client(pool)
    outcome = client.sign_in_with_password("a@b.c", "pw")
    assert isinstance(outcome, cls) and outcome.status == answer["status"]
    assert not client.is_signed_in
    for secret in ("mfa_x", "mfa_y", "chg_z"):
        assert secret not in repr(outcome)


def test_mfa_branch(pool):
    pool.routes[("POST", "/api/v1/signin/password")] = json_response(200, {"status": "mfa_required", "mfa_token": "mfa_1"})
    client = make_client(pool)
    outcome = client.sign_in_with_password("a@b.c", "pw")
    assert isinstance(outcome, MfaRequired)
    outcome = client.verify_mfa(outcome.mfa_token, "123456")
    assert isinstance(outcome, SignedIn) and client.is_signed_in
    assert json.loads(pool.last("POST", "/api/v1/signin/mfa").content) == {"mfa_token": "mfa_1", "code": "123456"}


def test_mfa_enrollment_during_sign_in(pool):
    pool.routes[("POST", "/api/v1/mfa/enroll")] = json_response(200, {"secret": "SECRETBASE32", "otpauth_uri": "otpauth://totp/x"})
    pool.routes[("POST", "/api/v1/mfa/enroll/confirm")] = lambda r: json_response(
        200, {"status": "ok", **pool.tokens(), "user": USER, "org": None, "recovery_codes": ["r1", "r2"]})
    client = make_client(pool)
    enrollment = client.enroll_mfa("mfa_tok")
    assert enrollment.secret == "SECRETBASE32" and "SECRETBASE32" not in repr(enrollment)
    assert "authorization" not in pool.last("POST", "/api/v1/mfa/enroll").headers
    confirmation = client.confirm_mfa("123456", "mfa_tok")
    assert confirmation.recovery_codes == ["r1", "r2"] and isinstance(confirmation.outcome, SignedIn)
    assert client.is_signed_in


def test_other_api_calls(pool):
    client = make_client(pool)
    assert client.config()["mode"] == "b2c"
    assert client.send_email_code("a@b.c") is None
    assert client.send_password_reset("a@b.c") is None
    client.reset_password("New-Pass-1", email="a@b.c", code="123456")
    assert json.loads(pool.last("POST", "/api/v1/password/reset").content) == {
        "email": "a@b.c", "code": "123456", "new_password": "New-Pass-1"}
    client.change_forced_password("chg_1", "New-Pass-2")
    assert json.loads(pool.last("POST", "/api/v1/password/reset").content) == {
        "change_token": "chg_1", "new_password": "New-Pass-2"}
    assert isinstance(client.sign_in_anonymously(), SignedIn)
    assert pool.last("POST", "/api/v1/signin/anonymous").content == b""


# --- signed-in calls ------------------------------------------------------------------------------------------------------

def test_signed_in_calls_send_bearer(pool):
    client = make_client(pool)
    client.sign_in_with_password("a@b.c", "pw")
    user = client.me()
    assert user.has_password is True and user.roles == ["member"]
    assert pool.last("GET", "/api/v1/me").headers["authorization"].startswith("Bearer ey")
    updated = client.update_profile(display_name="Ada L.")
    assert updated.display_name == "Ada L." and client.current_user.display_name == "Ada L."
    assert json.loads(pool.last("PATCH", "/api/v1/me").content) == {"display_name": "Ada L."}


def test_not_signed_in(pool):
    client = make_client(pool)
    with pytest.raises(AppAuthError) as err:
        client.me()
    assert err.value.status == 401 and err.value.code == "not_signed_in"


def test_token_error_clears_session(pool):
    client = make_client(pool)
    client.sign_in_with_password("a@b.c", "pw")
    seen = []
    client.on_auth_state_changed(lambda u, o: seen.append(u))
    pool.routes[("GET", "/api/v1/me")] = json_response(401, {"detail": {"code": "token_revoked", "message": "x"}})
    with pytest.raises(AppAuthError) as err:
        client.me()
    assert err.value.code == "token_revoked" and err.value.session_ended
    assert not client.is_signed_in and seen[-1] is None


def test_change_password_and_delete_clear_session(pool):
    client = make_client(pool)
    client.sign_in_with_password("a@b.c", "pw")
    client.change_password("New-Pass-1", current_password="pw")
    assert not client.is_signed_in
    client.sign_in_with_password("a@b.c", "New-Pass-1")
    client.delete_account("New-Pass-1")
    assert not client.is_signed_in
    req = pool.last("DELETE", "/api/v1/me")
    assert json.loads(req.content) == {"password": "New-Pass-1"}


# --- refresh --------------------------------------------------------------------------------------------------------------

def test_fresh_token_reused_and_stale_token_refreshed(pool):
    storage = MemoryStorage()
    client = make_client(pool, storage=storage)
    client.sign_in_with_password("a@b.c", "pw")
    first = client.get_access_token()
    assert client.get_access_token() == first and pool.count("POST", "/api/v1/token/refresh") == 0
    expire(client)
    second = client.get_access_token()
    assert second != first and pool.count("POST", "/api/v1/token/refresh") == 1
    assert json.loads(pool.last("POST", "/api/v1/token/refresh").content) == {"refresh_token": "obur_1"}
    assert json.loads(storage.get(f"openback.auth.{CLIENT_ID}"))["refreshToken"] == "obur_2"
    assert client.current_user.id == "usr_1"  # the user is kept across refreshes


def test_single_flight_refresh(pool):
    client = make_client(pool)
    client.sign_in_with_password("a@b.c", "pw")
    expire(client)
    pool.refresh_delay = 0.2
    results, errors = [], []

    def worker():
        try:
            results.append(client.get_access_token())
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert pool.count("POST", "/api/v1/token/refresh") == 1
    assert len(set(results)) == 1


def test_refresh_rejected_signs_out(pool):
    client = make_client(pool)
    client.sign_in_with_password("a@b.c", "pw")
    pool.used_refresh.add("obur_1")
    expire(client)
    with pytest.raises(AppAuthError) as err:
        client.get_access_token()
    assert err.value.code == "invalid_refresh_token"
    assert not client.is_signed_in


def test_network_error_is_not_retried(pool):
    client = make_client(pool)
    client.sign_in_with_password("a@b.c", "pw")
    expire(client)

    def boom(request):
        raise httpx.ConnectError("down", request=request)

    pool.routes[("POST", "/api/v1/token/refresh")] = boom
    with pytest.raises(AppAuthError) as err:
        client.get_access_token()
    assert err.value.status == 0 and err.value.code == "network_error"
    assert pool.count("POST", "/api/v1/token/refresh") == 1
    assert client.is_signed_in  # the session stays: the next call may try again


def test_refresh_follows_other_process_in_shared_storage(pool):
    storage = MemoryStorage()
    a = make_client(pool, storage=storage)
    a.sign_in_with_password("a@b.c", "pw")
    b = make_client(pool, storage=storage)  # same storage, e.g. a second process with FileStorage
    expire(a)
    b._save({**b._state, "expiresAt": int(time.time() * 1000) + 10_000})
    token_b = b.get_access_token()           # b refreshes (obur_1 -> obur_2)
    token_a = a.get_access_token()           # a sees obur_2 in the storage: no second refresh with obur_1
    assert token_a == token_b
    assert pool.count("POST", "/api/v1/token/refresh") == 1


def test_switch_organization(pool):
    client = make_client(pool)
    client.sign_in_with_password("a@b.c", "pw")
    org = client.switch_organization("org_9")
    assert org.id == "org_9" and org.roles == ["admin"]
    assert json.loads(pool.last("POST", "/api/v1/orgs/switch").content) == {"org_id": "org_9", "refresh_token": "obur_1"}
    assert client._state["refreshToken"] == "obur_2"


def test_organizations_and_members(pool):
    client = make_client(pool)
    client.sign_in_with_password("a@b.c", "pw")
    orgs = client.organizations()
    assert orgs.active == "org_1" and orgs.orgs[0].name == "Acme"
    page = client.members("org/1", q="bo", skip=0, limit=10)
    assert page.total == 1 and page.items[0].email == "bob@example.com" and page.roles[0].key == "member"
    req = pool.last("GET", "/api/v1/orgs/org/1/members")
    assert b"/orgs/org%2F1/members?" in req.url.raw_path  # the id is one path segment
    assert req.url.params["q"] == "bo" and req.url.params["limit"] == "10"
    added = client.add_member("org_1", "carl@example.com", roles=["member"])
    assert added.temporary_password == "Temp-Secret-123" and "Temp-Secret-123" not in repr(added)


def test_sign_out_is_best_effort(pool):
    client = make_client(pool)
    client.sign_in_with_password("a@b.c", "pw")
    client.sign_out()
    req = pool.last("POST", "/api/v1/signout")
    assert json.loads(req.content) == {"refresh_token": "obur_1", "everywhere": False}
    assert req.headers["authorization"].startswith("Bearer ")
    assert not client.is_signed_in

    client.sign_in_with_password("a@b.c", "pw")
    pool.routes[("POST", "/api/v1/signout")] = json_response(500, {"detail": "oops"})
    client.sign_out(everywhere=True)
    assert not client.is_signed_in


def test_sign_out_with_expired_access_token_still_revokes_refresh_token(pool):
    client = make_client(pool)
    client.sign_in_with_password("a@b.c", "pw")
    expire(client)
    client.sign_out()
    req = pool.last("POST", "/api/v1/signout")
    assert "authorization" not in req.headers and json.loads(req.content)["refresh_token"] == "obur_1"


# --- errors ---------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("status,body,code,message", [
    (401, {"detail": {"code": "invalid_credentials", "message": "Wrong"}}, "invalid_credentials", "Wrong"),
    (422, {"detail": {"code": "weak_password", "message": "Weak", "problems": ["length"]}}, "weak_password", "Weak"),
    (422, {"detail": "invalid email"}, "http_422", "invalid email"),
    (422, {"detail": [{"msg": "field required"}]}, "validation_error", "field required"),
    (500, None, "http_500", "Internal Server Error"),
])
def test_error_mapping(pool, status, body, code, message):
    pool.routes[("POST", "/api/v1/signin/password")] = (
        json_response(status, body) if body is not None else httpx.Response(status, content=b"oops"))
    client = make_client(pool)
    with pytest.raises(AppAuthError) as err:
        client.sign_in_with_password("a@b.c", "pw")
    assert err.value.status == status and err.value.code == code and err.value.message == message
    if code == "weak_password":
        assert err.value.detail["problems"] == ["length"]


# --- OpenID Connect -------------------------------------------------------------------------------------------------------

def test_authorization_request(pool):
    storage = MemoryStorage()
    client = make_client(pool, storage=storage, redirect_uri="com.example.app:/callback")
    req = client.build_authorization_request(provider="google", org_id="org_1", prompt="login", screen_hint="signup",
                                             login_hint="ada@example.com", max_age=300, ui_locales="it")
    assert req.url.startswith(f"{ISSUER}/authorize?")
    q = query(req.url)
    assert q["response_type"] == "code" and q["client_id"] == CLIENT_ID and q["redirect_uri"] == "com.example.app:/callback"
    assert q["scope"] == "openid profile email" and q["code_challenge_method"] == "S256"
    assert q["code_challenge"] == b64url(hashlib.sha256(req.code_verifier.encode()).digest())
    assert q["state"] == req.state and q["nonce"] == req.nonce
    assert (q["provider"], q["org_id"], q["prompt"], q["screen_hint"], q["login_hint"], q["max_age"], q["ui_locales"]) == (
        "google", "org_1", "login", "signup", "ada@example.com", "300", "it")
    assert 43 <= len(req.code_verifier) <= 128
    assert json.loads(storage.get(f"openback.auth.{CLIENT_ID}.pkce"))["state"] == req.state
    assert req.code_verifier not in repr(req)


def test_redirect_callback_signs_in(pool):
    client = make_client(pool, redirect_uri="http://127.0.0.1:53682/callback")
    req = client.build_authorization_request()
    pool.code_challenge = query(req.url)["code_challenge"]
    pool.nonce = req.nonce
    user = client.handle_redirect_callback(f"http://127.0.0.1:53682/callback?code={pool.code}&state={req.state}&iss={ISSUER}")
    assert user.id == "usr_1" and client.is_signed_in and client.id_token
    form = query("http://x/?" + pool.last("POST", "/token").content.decode())
    assert form == {"grant_type": "authorization_code", "code": pool.code, "redirect_uri": "http://127.0.0.1:53682/callback",
                    "code_verifier": req.code_verifier, "client_id": CLIENT_ID}
    assert "authorization" not in pool.last("POST", "/token").headers  # public client
    # the transaction is single-use
    with pytest.raises(AppAuthError) as err:
        client.handle_redirect_callback(f"http://127.0.0.1:53682/callback?code={pool.code}&state={req.state}")
    assert err.value.code == "invalid_state"


@pytest.mark.parametrize("suffix,code", [
    ("code=code_abc&state=WRONG", "invalid_state"),
    ("code=code_abc&state={state}&iss=https://evil.example.com", "invalid_issuer"),
    ("error=access_denied&error_description=denied&state={state}", "access_denied"),
    ("error=login_required&state={state}", "login_required"),
])
def test_redirect_callback_checks(pool, suffix, code):
    client = make_client(pool, redirect_uri="http://127.0.0.1:53682/callback")
    req = client.build_authorization_request()
    with pytest.raises(AppAuthError) as err:
        client.handle_redirect_callback("http://127.0.0.1:53682/callback?" + suffix.format(state=req.state))
    assert err.value.code == code
    assert pool.count("POST", "/token") == 0


def test_redirect_callback_nonce_mismatch(pool):
    client = make_client(pool, redirect_uri="http://127.0.0.1:53682/callback")
    req = client.build_authorization_request()
    pool.id_token_nonce = "another-nonce"
    with pytest.raises(AppAuthError) as err:
        client.handle_redirect_callback(f"http://127.0.0.1:53682/callback?code={pool.code}&state={req.state}")
    assert err.value.code == "invalid_nonce" and not client.is_signed_in


@pytest.mark.parametrize("method", ["client_secret_basic", "client_secret_post"])
def test_confidential_code_exchange(pool, method):
    client = make_client(pool, redirect_uri="https://app.example.com/cb", client_secret="s3cr:et/+",
                         token_endpoint_auth_method=method)
    req = client.build_authorization_request()
    pool.nonce = req.nonce
    client.handle_redirect_callback(f"https://app.example.com/cb?code={pool.code}&state={req.state}")
    token_req = pool.last("POST", "/token")
    form = query("http://x/?" + token_req.content.decode())
    if method == "client_secret_basic":
        raw = base64.b64decode(token_req.headers["authorization"][6:]).decode()
        assert raw == f"{CLIENT_ID}:s3cr%3Aet%2F%2B" and "client_secret" not in form
    else:
        assert form["client_secret"] == "s3cr:et/+" and "authorization" not in token_req.headers


def test_logout_url(pool):
    client = make_client(pool)
    url = client.build_logout_url("https://app.example.com/bye", "st1")
    q = query(url)
    assert url.startswith(f"{ISSUER}/logout?") and q == {"client_id": CLIENT_ID,
                                                         "post_logout_redirect_uri": "https://app.example.com/bye",
                                                         "state": "st1"}


# --- authorized requests, storage, repr ---------------------------------------------------------------------------------

def test_authorized_request_helper(pool):
    seen = {}

    def api(request):
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"ok": True})

    pool.routes[("GET", "/orders")] = api
    client = make_client(pool)
    client.sign_in_with_password("a@b.c", "pw")
    response = client.request("GET", "https://my-api.example.com/orders")
    assert response.json() == {"ok": True} and seen["auth"] == f"Bearer {client.get_access_token()}"
    with httpx.Client(transport=pool.transport) as http:
        http.get("https://my-api.example.com/orders", auth=client.auth)
    assert seen["auth"].startswith("Bearer ")


def test_file_storage_persists_session(pool, tmp_path):
    path = tmp_path / "sub" / "session.json"
    client = make_client(pool, storage=FileStorage(path))
    client.sign_in_with_password("a@b.c", "pw")
    assert path.exists()
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    again = make_client(pool, storage=FileStorage(path))
    assert again.is_signed_in and again.current_user.id == "usr_1"
    again.sign_out()
    assert not path.exists() and not list(path.parent.glob("*.tmp"))


def test_repr_never_leaks_tokens(pool):
    client = make_client(pool)
    outcome = client.sign_in_with_password("a@b.c", "pw")
    token = client.get_access_token()
    for text in (repr(client), repr(outcome), str(outcome)):
        assert token not in text and "obur_" not in text


def test_constructor_validation():
    with pytest.raises(ValueError):
        Client("", CLIENT_ID)
    with pytest.raises(ValueError):
        Client(ISSUER, "")
    with pytest.raises(ValueError):
        Client("ftp://x", CLIENT_ID)
    with pytest.raises(ValueError):
        Client(ISSUER, CLIENT_ID).build_authorization_request()  # no redirect URI
