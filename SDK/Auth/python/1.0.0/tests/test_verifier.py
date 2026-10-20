import asyncio
import json
import time

import httpx
import jwt
import pytest

from conftest import CLIENT_ID, ISSUER, FakePool, b64url, make_key
from openback_app_auth import JwksUnavailableError, TokenVerificationError, TokenVerifier


def make_verifier(pool: FakePool, **kwargs) -> TokenVerifier:
    return TokenVerifier(ISSUER, kwargs.pop("audience", CLIENT_ID), http_client=pool.http(),
                         async_http_client=pool.ahttp(), **kwargs)


def test_valid_access_token(pool):
    verifier = make_verifier(pool)
    user = verifier.verify(pool.access_token(permissions=["*"], anon=False, attr={"plan": "pro"}))
    assert user.id == "usr_1" and user.pool_id == "upool_1" and user.client_id == CLIENT_ID
    assert user.email == "ada@example.com" and user.email_verified and not user.anonymous
    assert user.org_id == "org_1" and user.session_id == "sess_1" and user.amr == ["pwd"]
    assert user.attributes == {"plan": "pro"} and user.claims["jti"]
    assert user.has_role("member") and not user.has_role("admin")
    assert user.has_permission("anything")  # "*"


def test_permissions_without_star(pool):
    user = make_verifier(pool).verify(pool.access_token())
    assert user.has_permission("orders.read") and not user.has_permission("orders.write")


def test_jwks_cached(pool):
    verifier = make_verifier(pool)
    for _ in range(3):
        verifier.verify(pool.access_token())
    assert pool.count("GET", "/.well-known/jwks.json") == 1


@pytest.mark.parametrize("change,code", [
    ({"exp": int(time.time()) - 120}, "token_expired"),
    ({"iss": "https://evil.example.com"}, "token_invalid"),
    ({"aud": "uapp_other"}, "token_invalid"),
    ({"iat": int(time.time()) + 3600}, "token_invalid"),
    ({"nbf": int(time.time()) + 3600}, "token_invalid"),
])
def test_claim_checks(pool, change, code):
    with pytest.raises(TokenVerificationError) as err:
        make_verifier(pool).verify(pool.access_token(**change))
    assert err.value.code == code and err.value.status == 401


def test_leeway(pool):
    token = pool.access_token(exp=int(time.time()) - 30)
    assert make_verifier(pool).verify(token).id == "usr_1"            # default leeway 60 s
    with pytest.raises(TokenVerificationError):
        make_verifier(pool, leeway=0).verify(token)


def test_multiple_audiences(pool):
    verifier = make_verifier(pool, audience=["uapp_web", CLIENT_ID])
    assert verifier.verify(pool.access_token()).client_id == CLIENT_ID


def test_missing_and_malformed(pool):
    verifier = make_verifier(pool)
    for token in (None, "", "not-a-jwt", "a.b.c"):
        with pytest.raises(TokenVerificationError):
            verifier.verify(token)


def test_typ_checks(pool):
    verifier = make_verifier(pool)
    assert verifier.verify(pool.sign(pool.access_claims(), typ="application/at+jwt")).id == "usr_1"
    assert verifier.verify(pool.sign(pool.access_claims(), typ="AT+JWT")).id == "usr_1"
    with pytest.raises(TokenVerificationError):
        verifier.verify(pool.sign(pool.access_claims(), typ="JWT"))  # an ID token is not an access token


def test_algorithm_confusion_refused(pool):
    verifier = make_verifier(pool)
    claims = pool.access_claims()
    # alg none
    header = b64url(b'{"alg":"none","typ":"at+jwt","kid":"k1"}')
    payload = b64url(json.dumps(claims).encode())
    with pytest.raises(TokenVerificationError):
        verifier.verify(f"{header}.{payload}.")
    # HS256 with a shared secret
    hs = jwt.encode(claims, "secret-key-that-is-long-enough-for-hs256", algorithm="HS256",
                    headers={"kid": "k1", "typ": "at+jwt"})
    with pytest.raises(TokenVerificationError):
        verifier.verify(hs)
    # ES384 / RS256 style header with the right kid
    from cryptography.hazmat.primitives.asymmetric import rsa
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rs = jwt.encode(claims, rsa_key, algorithm="RS256", headers={"kid": "k1", "typ": "at+jwt"})
    with pytest.raises(TokenVerificationError):
        verifier.verify(rs)
    # signed by another EC key
    with pytest.raises(TokenVerificationError):
        verifier.verify(pool.sign(claims, key=make_key()))


def test_unknown_kid_refetch_is_rate_limited(pool):
    verifier = make_verifier(pool, min_refetch_interval=30)
    verifier.verify(pool.access_token())
    assert pool.count("GET", "/.well-known/jwks.json") == 1
    # key rotation: a new key appears; the first token naming it triggers ONE refetch
    pool.keys["k2"] = make_key()
    verifier._attempted_at -= 31  # pretend 31 s passed since the last fetch
    assert verifier.verify(pool.sign(pool.access_claims(), kid="k2")).id == "usr_1"
    assert pool.count("GET", "/.well-known/jwks.json") == 2
    # an unknown kid right after: no new fetch (rate limit), refused
    for _ in range(3):
        with pytest.raises(TokenVerificationError):
            verifier.verify(pool.sign(pool.access_claims(), kid="k3", key=make_key()))
    assert pool.count("GET", "/.well-known/jwks.json") == 2


def test_cache_ttl_expiry_refetches(pool):
    verifier = make_verifier(pool, cache_ttl=600)
    verifier.verify(pool.access_token())
    verifier._fetched_at -= 601
    verifier._attempted_at -= 601
    verifier.verify(pool.access_token())
    assert pool.count("GET", "/.well-known/jwks.json") == 2


def test_jwks_unavailable(pool):
    pool.jwks_status = 503
    verifier = make_verifier(pool)
    with pytest.raises(JwksUnavailableError) as err:
        verifier.verify(pool.access_token())
    assert err.value.status == 503


def test_stale_keys_used_when_jwks_down(pool):
    verifier = make_verifier(pool)
    verifier.verify(pool.access_token())
    verifier._fetched_at -= 10_000
    verifier._attempted_at -= 10_000
    pool.jwks_status = 500
    assert verifier.verify(pool.access_token()).id == "usr_1"


def test_network_error_on_jwks(pool):
    def boom(request):
        raise httpx.ConnectError("down", request=request)
    pool.routes[("GET", "/.well-known/jwks.json")] = boom
    with pytest.raises(JwksUnavailableError):
        make_verifier(pool).verify(pool.access_token())


def test_custom_jwks_uri(pool):
    pool.routes[("GET", "/keys")] = lambda r: httpx.Response(200, json=pool.jwks())
    verifier = TokenVerifier(ISSUER, CLIENT_ID, jwks_uri="https://api.example.com/keys", http_client=pool.http())
    assert verifier.verify(pool.access_token()).id == "usr_1"
    assert pool.count("GET", "/keys") == 1


def test_async_verify(pool):
    async def main():
        verifier = make_verifier(pool)
        users = await asyncio.gather(*(verifier.verify_async(pool.access_token()) for _ in range(5)))
        assert {u.id for u in users} == {"usr_1"}
        assert pool.count("GET", "/.well-known/jwks.json") == 1
        with pytest.raises(TokenVerificationError):
            await verifier.verify_async(pool.access_token(aud="uapp_x"))
    asyncio.run(main())


def test_id_token(pool):
    pool.nonce = "n-123"
    tokens = pool.tokens(with_id_token=True)
    verifier = make_verifier(pool)
    claims = verifier.verify_id_token(tokens["id_token"], nonce="n-123", access_token=tokens["access_token"])
    assert claims["sub"] == "usr_1" and claims["nonce"] == "n-123"
    with pytest.raises(TokenVerificationError):
        verifier.verify_id_token(tokens["id_token"], nonce="other")
    with pytest.raises(TokenVerificationError):
        verifier.verify_id_token(tokens["id_token"], nonce="n-123", access_token="another-access-token")
    with pytest.raises(TokenVerificationError):
        verifier.verify_id_token(tokens["access_token"])  # an access token is not an ID token
    with pytest.raises(TokenVerificationError):
        verifier.verify(tokens["id_token"])               # and vice versa


def test_audience_required():
    with pytest.raises(ValueError):
        TokenVerifier(ISSUER, [])
