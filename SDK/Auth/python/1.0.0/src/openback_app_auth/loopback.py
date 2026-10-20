"""OPTIONAL helper for desktop and CLI apps: sign in through the pool's hosted page with the system browser and a
one-shot loopback HTTP server (RFC 8252 "loopback interface redirection").

Register the exact redirect URI in the pool's Apps tab (kind ``native``), with a FIXED port, e.g.
``http://127.0.0.1:53682/callback`` -- the pool matches redirect URIs exactly, so the port cannot be random.

    from openback_app_auth import Client
    from openback_app_auth.loopback import sign_in_with_browser

    auth = Client(issuer, "uapp_...", redirect_uri="http://127.0.0.1:53682/callback")
    user = sign_in_with_browser(auth)                 # opens the browser, waits for the callback

The server listens only on the loopback interface, answers a single callback on the registered path, then stops.
Nothing it receives is logged.
"""
from __future__ import annotations

import asyncio
import socket
import socketserver
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING, Any, Callable, Optional, Tuple
from urllib.parse import parse_qs, urlsplit

from .errors import AppAuthError
from .models import PoolUser

if TYPE_CHECKING:  # pragma: no cover
    from .async_client import AsyncClient
    from .client import Client

__all__ = ["sign_in_with_browser", "sign_in_with_browser_async", "sign_out_with_browser", "sign_out_with_browser_async",
           "LoopbackServer"]

SUCCESS_HTML = ("<!doctype html><html><head><meta charset='utf-8'><title>Signed in</title></head>"
                "<body style='font-family:sans-serif;text-align:center;margin-top:15vh'>"
                "<h1>You can close this window</h1><p>Return to the application.</p></body></html>")
ERROR_HTML = ("<!doctype html><html><head><meta charset='utf-8'><title>Sign-in failed</title></head>"
              "<body style='font-family:sans-serif;text-align:center;margin-top:15vh'>"
              "<h1>Sign-in was not completed</h1><p>Return to the application.</p></body></html>")


def _parse_redirect(redirect_uri: Optional[str]) -> Tuple[str, int, str]:
    if not redirect_uri:
        raise ValueError("a loopback redirect_uri is required, e.g. http://127.0.0.1:53682/callback")
    parts = urlsplit(redirect_uri)
    host = (parts.hostname or "").lower()
    if parts.scheme != "http" or host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("the loopback helper needs an http://127.0.0.1:<port>/... (or localhost / [::1]) redirect URI")
    if not parts.port:
        raise ValueError("the loopback redirect URI needs an explicit port (registered exactly in the pool)")
    return host, parts.port, parts.path or "/"


class _Server(HTTPServer):
    allow_reuse_address = False

    def __init__(self, host: str, port: int, path: str, success_html: str, error_html: str) -> None:
        if host == "::1":
            self.address_family = socket.AF_INET6
        bind = "127.0.0.1" if host == "localhost" else host
        self.expected_path = path
        self.success_html = success_html
        self.error_html = error_html
        self.result: Optional[str] = None
        self.base = f"http://{'[::1]' if host == '::1' else host}:{port}"
        super().__init__((bind, port), _Handler)

    def server_bind(self) -> None:
        # HTTPServer.server_bind resolves the host's FQDN (a slow reverse DNS lookup on some systems): not needed here.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = str(self.server_address[0]), int(self.server_address[1])


class _Handler(BaseHTTPRequestHandler):
    server: _Server

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        parts = urlsplit(self.path)
        query = parse_qs(parts.query)
        if parts.path != self.server.expected_path or not ("code" in query or "error" in query):
            self._answer(404, "<!doctype html><title>Not found</title>")
            return
        if self.server.result is None:
            self.server.result = self.server.base + self.path
        self._answer(200, self.server.success_html if "code" in query else self.server.error_html)

    def _answer(self, status: int, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:  # never log the code
        return


class LoopbackServer:
    """A one-shot HTTP server on the loopback interface that waits for the OAuth callback."""

    def __init__(self, redirect_uri: str, *, success_html: str = SUCCESS_HTML, error_html: str = ERROR_HTML) -> None:
        host, port, path = _parse_redirect(redirect_uri)
        self._server = _Server(host, port, path, success_html, error_html)
        self._server.timeout = 0.25

    def wait(self, timeout: float = 300.0) -> str:
        """Serve until the callback arrives -> its full URL. Raises :class:`AppAuthError` ``timeout`` (408)."""
        deadline = time.monotonic() + timeout
        while self._server.result is None:
            if time.monotonic() >= deadline:
                raise AppAuthError(408, "timeout", "The sign-in in the browser was not completed in time")
            self._server.handle_request()
        return self._server.result

    def close(self) -> None:
        self._server.server_close()

    def __enter__(self) -> "LoopbackServer":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def sign_in_with_browser(client: "Client", *, redirect_uri: Optional[str] = None, open_browser: bool = True,
                         on_url: Optional[Callable[[str], None]] = None, timeout: float = 300.0,
                         success_html: str = SUCCESS_HTML, **options: Any) -> Optional[PoolUser]:
    """Sign in with the hosted page in the system browser; returns the user (the session is kept by ``client``).

    ``options`` go to :meth:`Client.build_authorization_request` (``provider``, ``org_id``, ``prompt``,
    ``screen_hint``, ``login_hint``, ``max_age``, ``scope``, ``ui_locales``). ``on_url(url)`` is called with the
    sign-in URL (e.g. to print it when no browser can be opened; ``open_browser=False`` skips opening one).
    """
    redirect = redirect_uri or client.redirect_uri
    with LoopbackServer(redirect, success_html=success_html) as server:  # type: ignore[arg-type]
        request = client.build_authorization_request(redirect_uri=redirect, **options)
        if on_url is not None:
            on_url(request.url)
        if open_browser:
            webbrowser.open(request.url)
        callback = server.wait(timeout)
    return client.handle_redirect_callback(callback, request)


async def sign_in_with_browser_async(client: "AsyncClient", *, redirect_uri: Optional[str] = None,
                                     open_browser: bool = True, on_url: Optional[Callable[[str], None]] = None,
                                     timeout: float = 300.0, success_html: str = SUCCESS_HTML,
                                     **options: Any) -> Optional[PoolUser]:
    """:func:`sign_in_with_browser` for :class:`AsyncClient` (the server waits in a worker thread)."""
    redirect = redirect_uri or client.redirect_uri
    with LoopbackServer(redirect, success_html=success_html) as server:  # type: ignore[arg-type]
        request = client.build_authorization_request(redirect_uri=redirect, **options)
        if on_url is not None:
            on_url(request.url)
        if open_browser:
            webbrowser.open(request.url)
        callback = await asyncio.to_thread(server.wait, timeout)
    return await client.handle_redirect_callback(callback, request)


def sign_out_with_browser(client: "Client", *, post_logout_redirect_uri: Optional[str] = None,
                          state: Optional[str] = None, everywhere: bool = False, open_browser: bool = True) -> str:
    """Sign the client out (``client.sign_out``) and end the hosted page's browser session too, by opening the pool's
    end-session URL in the system browser. Returns that URL (``open_browser=False`` only returns it)."""
    url = client.build_logout_url(post_logout_redirect_uri, state)  # built first: it uses the stored ID token
    client.sign_out(everywhere=everywhere)
    if open_browser:
        webbrowser.open(url)
    return url


async def sign_out_with_browser_async(client: "AsyncClient", *, post_logout_redirect_uri: Optional[str] = None,
                                      state: Optional[str] = None, everywhere: bool = False,
                                      open_browser: bool = True) -> str:
    """:func:`sign_out_with_browser` for :class:`AsyncClient`."""
    url = client.build_logout_url(post_logout_redirect_uri, state)
    await client.sign_out(everywhere=everywhere)
    if open_browser:
        webbrowser.open(url)
    return url
