import asyncio
import base64
import json

import pytest

from conftest import CLIENT_ID, ISSUER, FakePool, json_response, query
from openback_app_auth import AppAuthError, AsyncOidcWebClient, AuthorizationRequest, OidcWebClient

REDIRECT = "https://app.example.com/callback"


def make(pool: FakePool, **kwargs) -> OidcWebClient:
    return OidcWebClient(ISSUER, CLIENT_ID, "web-secret", redirect_uri=REDIRECT, http_client=pool.http(), **kwargs)


def start(pool: FakePool, oidc) -> AuthorizationRequest:
    req = oidc.authorization_url(provider="google")
    pool.code_challenge = query(req.url)["code_challenge"]
    pool.nonce = req.nonce
    return req


def test_full_web_flow(pool):
    oidc = make(pool)
    req = start(pool, oidc)
    q = query(req.url)
    assert q["provider"] == "google" and q["redirect_uri"] == REDIRECT and q["code_challenge_method"] == "S256"
    # the transaction goes through a (JSON) session and back
    transaction = json.loads(json.dumps(req.to_dict()))
    tokens = oidc.handle_callback({"code": pool.code, "state": req.state, "iss": ISSUER}, transaction)
    assert tokens.id_token_claims["sub"] == "usr_1" and tokens.id_token_claims["nonce"] == req.nonce
    assert tokens.refresh_token == "obur_1" and tokens.expires_in == 900
    assert tokens.access_token not in repr(tokens)
    token_req = pool.last("POST", "/token")
    assert base64.b64decode(token_req.headers["authorization"][6:]).decode() == f"{CLIENT_ID}:web-secret"
    form = query("http://x/?" + token_req.content.decode())
    assert form["code_verifier"] == req.code_verifier and form["redirect_uri"] == REDIRECT
    assert pool.count("GET", "/.well-known/jwks.json") == 1  # the ID token's signature was checked

    renewed = oidc.refresh(tokens.refresh_token)
    assert renewed.refresh_token == "obur_2" and renewed.id_token is None
    oidc.revoke(renewed.refresh_token)
    revoke = pool.last("POST", "/revoke")
    assert query("http://x/?" + revoke.content.decode())["token"] == "obur_2"
    assert revoke.headers["authorization"].startswith("Basic ")
    info = oidc.userinfo(renewed.access_token)
    assert info["sub"] == "usr_1"
    assert pool.last("GET", "/userinfo").headers["authorization"] == f"Bearer {renewed.access_token}"


def test_callback_as_url_and_query_string(pool):
    oidc = make(pool)
    req = start(pool, oidc)
    assert oidc.handle_callback(f"{REDIRECT}?code={pool.code}&state={req.state}", req).refresh_token
    req = start(pool, oidc)
    assert oidc.handle_callback(f"code={pool.code}&state={req.state}", req).refresh_token


def test_client_secret_post(pool):
    oidc = make(pool, token_endpoint_auth_method="client_secret_post")
    req = start(pool, oidc)
    oidc.handle_callback({"code": pool.code, "state": req.state}, req)
    token_req = pool.last("POST", "/token")
    assert "authorization" not in token_req.headers
    assert query("http://x/?" + token_req.content.decode())["client_secret"] == "web-secret"


@pytest.mark.parametrize("params,code", [
    ({"code": "code_abc", "state": "wrong"}, "invalid_state"),
    ({"error": "access_denied", "state": "{state}"}, "access_denied"),
    ({"code": "code_abc", "state": "{state}", "iss": "https://other.example.com"}, "invalid_issuer"),
])
def test_callback_checks(pool, params, code):
    oidc = make(pool)
    req = start(pool, oidc)
    params = {k: v.format(state=req.state) for k, v in params.items()}
    with pytest.raises(AppAuthError) as err:
        oidc.handle_callback(params, req)
    assert err.value.code == code


def test_bad_nonce_refused(pool):
    oidc = make(pool)
    req = start(pool, oidc)
    pool.id_token_nonce = "forged"
    with pytest.raises(AppAuthError) as err:
        oidc.handle_callback({"code": pool.code, "state": req.state}, req)
    assert err.value.code == "invalid_id_token"


def test_missing_id_token_refused(pool):
    oidc = make(pool)
    req = start(pool, oidc)
    pool.routes[("POST", "/token")] = lambda r: json_response(200, {k: v for k, v in pool.tokens().items()})
    with pytest.raises(AppAuthError) as err:
        oidc.handle_callback({"code": pool.code, "state": req.state}, req)
    assert err.value.code == "invalid_id_token"


def test_token_endpoint_errors(pool):
    oidc = make(pool)
    req = start(pool, oidc)
    with pytest.raises(AppAuthError) as err:
        oidc.handle_callback({"code": "wrong-code", "state": req.state}, req)
    assert err.value.status == 400 and err.value.code == "invalid_grant"
    with pytest.raises(AppAuthError) as err:
        oidc.refresh("obur_unknown")
    assert err.value.code == "invalid_grant"


def test_logout_url(pool):
    url = make(pool).logout_url(id_token_hint="idt", post_logout_redirect_uri="https://app.example.com/", state="s")
    assert url.startswith(f"{ISSUER}/logout?")
    assert query(url) == {"client_id": CLIENT_ID, "id_token_hint": "idt",
                          "post_logout_redirect_uri": "https://app.example.com/", "state": "s"}


def test_async_web_flow(pool):
    async def main():
        async with AsyncOidcWebClient(ISSUER, CLIENT_ID, "web-secret", redirect_uri=REDIRECT,
                                      http_client=pool.ahttp()) as oidc:
            req = start(pool, oidc)
            tokens = await oidc.handle_callback({"code": pool.code, "state": req.state}, req.to_dict())
            assert tokens.id_token_claims["sub"] == "usr_1"
            renewed = await oidc.refresh(tokens.refresh_token)
            await oidc.revoke(renewed.refresh_token)
            assert (await oidc.userinfo(renewed.access_token))["sub"] == "usr_1"
    asyncio.run(main())
