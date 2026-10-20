import asyncio
import socket
import threading

import httpx
import pytest

from conftest import CLIENT_ID, ISSUER, query
from openback_app_auth import AppAuthError, AsyncClient, Client
from openback_app_auth.loopback import LoopbackServer, sign_in_with_browser, sign_in_with_browser_async


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def hit_later(url: str) -> None:
    def go():
        with httpx.Client(timeout=5) as http:  # a local request on 127.0.0.1 plays the browser's redirect
            http.get(url)
    threading.Thread(target=go, daemon=True).start()


def test_rejects_non_loopback_redirects():
    for uri in ("https://app.example.com/cb", "http://example.com:8080/cb", "http://127.0.0.1/cb", None):
        with pytest.raises(ValueError):
            LoopbackServer(uri)  # type: ignore[arg-type]


def test_server_waits_for_callback_and_ignores_other_paths():
    port = free_port()
    with LoopbackServer(f"http://127.0.0.1:{port}/callback") as server:
        def go():
            with httpx.Client(timeout=5) as http:
                assert http.get(f"http://127.0.0.1:{port}/favicon.ico").status_code == 404
                ok = http.get(f"http://127.0.0.1:{port}/callback?code=c1&state=s1")
                assert ok.status_code == 200 and "close this window" in ok.text
                assert ok.headers["cache-control"] == "no-store"
        t = threading.Thread(target=go)
        t.start()
        url = server.wait(timeout=10)
        t.join()
    assert url == f"http://127.0.0.1:{port}/callback?code=c1&state=s1"


def test_timeout():
    with LoopbackServer(f"http://127.0.0.1:{free_port()}/cb") as server:
        with pytest.raises(AppAuthError) as err:
            server.wait(timeout=0.3)
    assert err.value.code == "timeout"


def test_sign_in_with_browser(pool):
    port = free_port()
    redirect = f"http://127.0.0.1:{port}/callback"
    client = Client(ISSUER, CLIENT_ID, redirect_uri=redirect, http_client=pool.http())

    def on_url(url: str) -> None:
        q = query(url)
        pool.code_challenge, pool.nonce = q["code_challenge"], q["nonce"]
        hit_later(f"{redirect}?code={pool.code}&state={q['state']}&iss={ISSUER}")

    user = sign_in_with_browser(client, open_browser=False, on_url=on_url, timeout=10)
    assert user.id == "usr_1" and client.is_signed_in


def test_sign_in_with_browser_async(pool):
    port = free_port()
    redirect = f"http://127.0.0.1:{port}/callback"

    async def main():
        client = AsyncClient(ISSUER, CLIENT_ID, redirect_uri=redirect, http_client=pool.ahttp())

        def on_url(url: str) -> None:
            q = query(url)
            pool.code_challenge, pool.nonce = q["code_challenge"], q["nonce"]
            hit_later(f"{redirect}?code={pool.code}&state={q['state']}")

        user = await sign_in_with_browser_async(client, open_browser=False, on_url=on_url, timeout=10)
        assert user.id == "usr_1" and client.is_signed_in
    asyncio.run(main())


def test_sign_out_with_browser(pool):
    from openback_app_auth.loopback import sign_out_with_browser

    port = free_port()
    redirect = f"http://127.0.0.1:{port}/callback"
    client = Client(ISSUER, CLIENT_ID, redirect_uri=redirect, http_client=pool.http())

    def on_url(url: str) -> None:
        q = query(url)
        pool.code_challenge, pool.nonce = q["code_challenge"], q["nonce"]
        hit_later(f"{redirect}?code={pool.code}&state={q['state']}")

    sign_in_with_browser(client, open_browser=False, on_url=on_url, timeout=10)
    id_token = client.id_token
    url = sign_out_with_browser(client, post_logout_redirect_uri="http://127.0.0.1:53682/bye", open_browser=False)
    assert not client.is_signed_in and pool.count("POST", "/api/v1/signout") == 1
    assert query(url) == {"client_id": CLIENT_ID, "id_token_hint": id_token,
                          "post_logout_redirect_uri": "http://127.0.0.1:53682/bye"}
