"""OpenID Connect for ``web`` apps (a server with a client secret): sign-in through the pool's hosted page."""
from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, Union

import httpx

from ._base import (DEFAULT_SCOPE, build_authorization_request, callback_params, check_callback, logout_url,
                    network_error, token_request_args, token_result)
from ._util import normalize_issuer
from .errors import AppAuthError, error_from_response
from .models import AuthorizationRequest, TokenSet
from .verifier import TokenVerifier

__all__ = ["OidcWebClient", "AsyncOidcWebClient"]

Transaction = Union[AuthorizationRequest, Mapping[str, Any]]


class _OidcWebBase:
    def __init__(self, issuer: str, client_id: str, client_secret: Optional[str], *, redirect_uri: Optional[str] = None,
                 scope: str = DEFAULT_SCOPE, token_endpoint_auth_method: str = "client_secret_basic",
                 verifier: Optional[TokenVerifier] = None) -> None:
        if not client_id:
            raise ValueError("client_id is required")
        if token_endpoint_auth_method not in ("client_secret_basic", "client_secret_post"):
            raise ValueError("token_endpoint_auth_method must be 'client_secret_basic' or 'client_secret_post'")
        self.issuer = normalize_issuer(issuer)
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.scope = scope
        self._client_secret = client_secret
        self._auth_method = token_endpoint_auth_method
        self.verifier: TokenVerifier = verifier  # type: ignore[assignment]

    def __repr__(self) -> str:
        return f"{type(self).__name__}(issuer={self.issuer!r}, client_id={self.client_id!r})"

    def authorization_url(self, *, redirect_uri: Optional[str] = None, scope: Optional[str] = None,
                          provider: Optional[str] = None, org_id: Optional[str] = None, prompt: Optional[str] = None,
                          screen_hint: Optional[str] = None, login_hint: Optional[str] = None,
                          max_age: Optional[int] = None, ui_locales: Optional[str] = None,
                          extra_params: Optional[Mapping[str, str]] = None) -> AuthorizationRequest:
        """The hosted page's URL (code + PKCE S256, fresh state and nonce). Redirect the browser to ``.url`` and keep
        ``.to_dict()`` (the transaction) in the user's server-side session for :meth:`handle_callback`."""
        return build_authorization_request(
            self.issuer, self.client_id, redirect_uri=redirect_uri or self.redirect_uri, provider=provider, org_id=org_id,
            prompt=prompt, screen_hint=screen_hint, login_hint=login_hint, max_age=max_age, scope=scope or self.scope,
            ui_locales=ui_locales, extra_params=extra_params)

    def logout_url(self, *, id_token_hint: Optional[str] = None, post_logout_redirect_uri: Optional[str] = None,
                   state: Optional[str] = None) -> str:
        """The pool's end-session URL (ends the hosted page's session; ``post_logout_redirect_uri`` must be registered).
        Revoke the refresh token too (:meth:`revoke`)."""
        return logout_url(self.issuer, self.client_id, id_token_hint=id_token_hint,
                          post_logout_redirect_uri=post_logout_redirect_uri, state=state)

    def _token_args(self, form: Mapping[str, Optional[str]]) -> Dict[str, Any]:
        return token_request_args(self.issuer, self.client_id, self._client_secret, self._auth_method,
                                  {k: v for k, v in form.items() if v is not None})

    def _code_form(self, params: Any, transaction: Transaction) -> tuple:
        pending = transaction if isinstance(transaction, AuthorizationRequest) else (
            AuthorizationRequest.from_dict(transaction) if isinstance(transaction, Mapping) else None)
        code = check_callback(callback_params(params), pending, self.issuer)
        assert pending is not None
        form = {"grant_type": "authorization_code", "code": code, "redirect_uri": pending.redirect_uri,
                "code_verifier": pending.code_verifier}
        return form, pending

    @staticmethod
    def _need_id_token(data: Mapping[str, Any], pending: AuthorizationRequest) -> None:
        if "openid" in pending.scope.split() and not data.get("id_token"):
            raise AppAuthError(502, "invalid_id_token", "The token answer has no ID token")

    @staticmethod
    def _id_error(exc: AppAuthError) -> AppAuthError:
        return AppAuthError(400, "invalid_id_token", f"ID token refused: {exc.message}", exc.detail) \
            if exc.status == 401 else exc

    def _revoke_args(self, refresh_token: str) -> Dict[str, Any]:
        args = self._token_args({"token": refresh_token, "token_type_hint": "refresh_token"})
        args["url"] = f"{self.issuer}/revoke"
        return args

    def _userinfo_args(self, access_token: str) -> Dict[str, Any]:
        return {"method": "GET", "url": f"{self.issuer}/userinfo",
                "headers": {"Accept": "application/json", "Authorization": f"Bearer {access_token}"}}

    @staticmethod
    def _userinfo_result(response: httpx.Response) -> Dict[str, Any]:
        try:
            data = response.json()
        except ValueError:
            data = None
        if response.status_code >= 400:
            raise error_from_response(response.status_code, data, response.reason_phrase)
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _revoke_result(response: httpx.Response) -> None:
        if response.status_code >= 400:
            try:
                data = response.json()
            except ValueError:
                data = None
            raise error_from_response(response.status_code, data, response.reason_phrase)


class OidcWebClient(_OidcWebBase):
    """OpenID Connect for a ``web`` app (confidential client, authorization code + PKCE).

    >>> oidc = OidcWebClient(issuer, "uapp_...", client_secret, redirect_uri="https://app.example.com/callback")
    >>> req = oidc.authorization_url()                    # redirect to req.url, session["oidc"] = req.to_dict()
    >>> tokens = oidc.handle_callback(request.args, session.pop("oidc"))
    >>> tokens.id_token_claims["sub"], tokens.refresh_token

    The ID token is verified with the pool's JWKS (signature, issuer, audience = client ID, expiry, nonce, at_hash).
    Client authentication: ``client_secret_basic`` (default) or ``client_secret_post``.
    """

    def __init__(self, issuer: str, client_id: str, client_secret: Optional[str], *, redirect_uri: Optional[str] = None,
                 scope: str = DEFAULT_SCOPE, token_endpoint_auth_method: str = "client_secret_basic",
                 http_client: Optional[httpx.Client] = None, verifier: Optional[TokenVerifier] = None,
                 leeway: float = 60, timeout: float = 30.0) -> None:
        super().__init__(issuer, client_id, client_secret, redirect_uri=redirect_uri, scope=scope,
                         token_endpoint_auth_method=token_endpoint_auth_method)
        self._own_http = http_client is None
        self._http = http_client if http_client is not None else httpx.Client(timeout=timeout)
        self.verifier = verifier or TokenVerifier(self.issuer, client_id, leeway=leeway, http_client=self._http)

    def close(self) -> None:
        if self._own_http:
            self._http.close()

    def __enter__(self) -> "OidcWebClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def _send(self, args: Dict[str, Any]) -> httpx.Response:
        try:
            return self._http.request(**args)
        except httpx.HTTPError as exc:
            raise network_error(exc) from exc

    def handle_callback(self, params: Any, transaction: Transaction) -> TokenSet:
        """Finish the sign-in. ``params``: the callback's query (a mapping such as ``request.args``, a query string or
        the full URL); ``transaction``: what :meth:`authorization_url` returned (or its ``to_dict()``). Checks
        ``error``, ``state`` (constant time) and ``iss``, exchanges the code, verifies the ID token."""
        form, pending = self._code_form(params, transaction)
        data = token_result(self._send(self._token_args(form)))
        self._need_id_token(data, pending)
        claims = None
        if data.get("id_token"):
            try:
                claims = self.verifier.verify_id_token(data["id_token"], nonce=pending.nonce,
                                                       access_token=data.get("access_token"), audience=self.client_id)
            except AppAuthError as exc:
                raise self._id_error(exc) from None
        return TokenSet.from_response(data, claims)

    def refresh(self, refresh_token: str, *, org_id: Optional[str] = None) -> TokenSet:
        """New tokens (the refresh token is ROTATED: store the new one, the old one is dead). No ID token."""
        return TokenSet.from_response(token_result(self._send(self._token_args(
            {"grant_type": "refresh_token", "refresh_token": refresh_token, "org_id": org_id}))))

    def revoke(self, refresh_token: str) -> None:
        """Revoke a refresh token (and its whole rotation family) - RFC 7009."""
        self._revoke_result(self._send(self._revoke_args(refresh_token)))

    def userinfo(self, access_token: str) -> Dict[str, Any]:
        """``{sub, email, email_verified, name?, picture?, locale?, org_id, roles, attributes}``."""
        return self._userinfo_result(self._send(self._userinfo_args(access_token)))


class AsyncOidcWebClient(_OidcWebBase):
    """The ``async`` twin of :class:`OidcWebClient` (``http_client`` is an ``httpx.AsyncClient``)."""

    def __init__(self, issuer: str, client_id: str, client_secret: Optional[str], *, redirect_uri: Optional[str] = None,
                 scope: str = DEFAULT_SCOPE, token_endpoint_auth_method: str = "client_secret_basic",
                 http_client: Optional[httpx.AsyncClient] = None, verifier: Optional[TokenVerifier] = None,
                 leeway: float = 60, timeout: float = 30.0) -> None:
        super().__init__(issuer, client_id, client_secret, redirect_uri=redirect_uri, scope=scope,
                         token_endpoint_auth_method=token_endpoint_auth_method)
        self._own_http = http_client is None
        self._http = http_client if http_client is not None else httpx.AsyncClient(timeout=timeout)
        self.verifier = verifier or TokenVerifier(self.issuer, client_id, leeway=leeway, async_http_client=self._http)

    async def aclose(self) -> None:
        if self._own_http:
            await self._http.aclose()

    async def __aenter__(self) -> "AsyncOidcWebClient":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()

    async def _send(self, args: Dict[str, Any]) -> httpx.Response:
        try:
            return await self._http.request(**args)
        except httpx.HTTPError as exc:
            raise network_error(exc) from exc

    async def handle_callback(self, params: Any, transaction: Transaction) -> TokenSet:
        form, pending = self._code_form(params, transaction)
        data = token_result(await self._send(self._token_args(form)))
        self._need_id_token(data, pending)
        claims = None
        if data.get("id_token"):
            try:
                claims = await self.verifier.verify_id_token_async(data["id_token"], nonce=pending.nonce,
                                                                   access_token=data.get("access_token"),
                                                                   audience=self.client_id)
            except AppAuthError as exc:
                raise self._id_error(exc) from None
        return TokenSet.from_response(data, claims)

    async def refresh(self, refresh_token: str, *, org_id: Optional[str] = None) -> TokenSet:
        return TokenSet.from_response(token_result(await self._send(self._token_args(
            {"grant_type": "refresh_token", "refresh_token": refresh_token, "org_id": org_id}))))

    async def revoke(self, refresh_token: str) -> None:
        self._revoke_result(await self._send(self._revoke_args(refresh_token)))

    async def userinfo(self, access_token: str) -> Dict[str, Any]:
        return self._userinfo_result(await self._send(self._userinfo_args(access_token)))
