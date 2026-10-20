import asyncio
import json
import time

import pytest

from conftest import CLIENT_ID, ISSUER, FakePool, json_response, query
from openback_app_auth import AppAuthError, AsyncClient, MfaRequired, SignedIn


def make_client(pool: FakePool, **kwargs) -> AsyncClient:
    return AsyncClient(ISSUER, CLIENT_ID, http_client=pool.ahttp(), **kwargs)


def expire(client: AsyncClient) -> None:
    client._save({**client._state, "expiresAt": int(time.time() * 1000) + 10_000})


def test_async_sign_in_mfa_and_me(pool):
    async def main():
        pool.routes[("POST", "/api/v1/signin/password")] = json_response(200, {"status": "mfa_required", "mfa_token": "m1"})
        async with make_client(pool) as client:
            outcome = await client.sign_in_with_password("a@b.c", "pw")
            assert isinstance(outcome, MfaRequired)
            outcome = await client.verify_mfa(outcome.mfa_token, "123456")
            assert isinstance(outcome, SignedIn) and client.is_signed_in
            user = await client.me()
            assert user.id == "usr_1"
            orgs = await client.organizations()
            assert orgs.active == "org_1"
            await client.sign_out()
            assert not client.is_signed_in
    asyncio.run(main())


def test_async_single_flight_refresh(pool):
    async def main():
        client = make_client(pool)
        await client.sign_in_with_password("a@b.c", "pw")
        expire(client)
        tokens = await asyncio.gather(*(client.get_access_token() for _ in range(10)))
        assert len(set(tokens)) == 1
        assert pool.count("POST", "/api/v1/token/refresh") == 1
        await client.aclose()
    asyncio.run(main())


def test_async_refresh_rejected_signs_out(pool):
    async def main():
        client = make_client(pool)
        await client.sign_in_with_password("a@b.c", "pw")
        pool.used_refresh.add("obur_1")
        expire(client)
        with pytest.raises(AppAuthError) as err:
            await client.get_access_token()
        assert err.value.code == "invalid_refresh_token" and not client.is_signed_in
    asyncio.run(main())


def test_async_redirect_callback(pool):
    async def main():
        client = make_client(pool, redirect_uri="http://127.0.0.1:53682/callback")
        req = client.build_authorization_request()
        pool.code_challenge = query(req.url)["code_challenge"]
        pool.nonce = req.nonce
        user = await client.handle_redirect_callback(f"http://127.0.0.1:53682/callback?code={pool.code}&state={req.state}")
        assert user.id == "usr_1" and client.is_signed_in
        org = await client.switch_organization("org_7")
        assert org.id == "org_7"
        assert json.loads(pool.last("POST", "/api/v1/orgs/switch").content)["org_id"] == "org_7"
    asyncio.run(main())


def test_async_authorized_request(pool):
    seen = {}

    def api(request):
        seen["auth"] = request.headers.get("authorization")
        return json_response(200, {})

    pool.routes[("GET", "/orders")] = api

    async def main():
        client = make_client(pool)
        await client.sign_in_with_password("a@b.c", "pw")
        await client.request("GET", "https://my-api.example.com/orders")
        assert seen["auth"] == f"Bearer {await client.get_access_token()}"
    asyncio.run(main())
