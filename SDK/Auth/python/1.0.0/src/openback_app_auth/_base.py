"""The I/O-free part of :class:`Client` and :class:`AsyncClient`: session state, listeners, request building, answer
parsing and the OpenID Connect transaction. The two clients only add the HTTP calls (sync or async)."""
from __future__ import annotations

import json
import threading
from typing import Any, Callable, Dict, Generator, List, Mapping, Optional, Tuple
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

import httpx

from ._util import basic_auth, compact, decode_jwt, normalize_issuer, now_ms, pkce_challenge, pkce_verifier, random_token, same
from .errors import AppAuthError, error_from_response
from .models import ActiveOrg, AuthorizationRequest, Outcome, PoolUser, parse_outcome
from .storage import MemoryStorage, Storage

API = "/api/v1"
SKEW_MS = 60_000
DEFAULT_SCOPE = "openid profile email"

Listener = Callable[[Optional[PoolUser], Optional[ActiveOrg]], None]


class _NoBody:
    pass


NO_BODY: Any = _NoBody()


class _ClientBase:
    """Shared state and helpers. Not public: use :class:`Client` or :class:`AsyncClient`."""

    def __init__(self, issuer: str, client_id: str, *, redirect_uri: Optional[str] = None,
                 storage: Optional[Storage] = None, storage_key: Optional[str] = None,
                 client_secret: Optional[str] = None, token_endpoint_auth_method: str = "client_secret_basic") -> None:
        if not client_id or not isinstance(client_id, str):
            raise ValueError("client_id is required")
        if token_endpoint_auth_method not in ("client_secret_basic", "client_secret_post"):
            raise ValueError("token_endpoint_auth_method must be 'client_secret_basic' or 'client_secret_post'")
        self.issuer: str = normalize_issuer(issuer)
        self.client_id: str = client_id
        self.redirect_uri: Optional[str] = redirect_uri
        self.storage_key: str = storage_key or f"openback.auth.{client_id}"
        self._storage: Storage = storage if storage is not None else MemoryStorage()
        self._client_secret = client_secret
        self._auth_method = token_endpoint_auth_method
        self._state_lock = threading.RLock()
        self._listeners: List[Listener] = []
        self._state: Dict[str, Any] = self._load()

    def __repr__(self) -> str:
        return f"{type(self).__name__}(issuer={self.issuer!r}, client_id={self.client_id!r}, signed_in={self.is_signed_in})"

    # --- session state ---------------------------------------------------------------------------------------------

    @property
    def _pkce_key(self) -> str:
        return f"{self.storage_key}.pkce"

    def _load(self) -> Dict[str, Any]:
        try:
            raw = self._storage.get(self.storage_key)
            data = json.loads(raw) if raw else None
        except (ValueError, TypeError):
            data = None
        return data if isinstance(data, dict) else {}

    def _save(self, nxt: Optional[Dict[str, Any]]) -> None:
        with self._state_lock:
            self._state = dict(nxt or {})
            if self._state.get("refreshToken"):
                self._storage.set(self.storage_key, json.dumps(self._state, separators=(",", ":")))
            else:
                self._storage.remove(self.storage_key)
        self._notify()

    def _notify(self) -> None:
        user, org = self.current_user, self.current_org
        with self._state_lock:
            listeners = list(self._listeners)
        for listener in listeners:
            try:
                listener(user, org)
            except Exception:  # a listener's error is its own
                pass

    def _latest(self) -> Dict[str, Any]:
        """The session, following another client or process that rotated it in the same storage."""
        stored = self._load()
        with self._state_lock:
            changed = bool(stored.get("refreshToken")) and stored.get("refreshToken") != self._state.get("refreshToken")
            if changed:
                self._state = stored
        if changed:
            self._notify()
        with self._state_lock:
            return dict(self._state) if self._state.get("refreshToken") else stored

    @staticmethod
    def _is_fresh(state: Mapping[str, Any]) -> bool:
        expires = state.get("expiresAt")
        return bool(state.get("accessToken")) and isinstance(expires, (int, float)) and expires - now_ms() > SKEW_MS

    def _session_from(self, data: Mapping[str, Any], user: Any) -> Dict[str, Any]:
        expires_in = data.get("expires_in")
        expires_in = int(expires_in) if isinstance(expires_in, (int, float)) and expires_in > 0 else 900
        return {"accessToken": data.get("access_token"), "refreshToken": data.get("refresh_token"),
                "idToken": data.get("id_token") or self._state.get("idToken"),
                "expiresAt": now_ms() + expires_in * 1000, "user": user,
                "org": data.get("org") if isinstance(data.get("org"), Mapping) else None}

    def _apply_outcome(self, data: Any) -> Outcome:
        """Keep the session on ``ok``; every outcome goes back to the app."""
        if not isinstance(data, Mapping):
            raise AppAuthError(502, "invalid_response", "Unexpected answer from the user pool")
        if data.get("status") == "ok" and data.get("access_token"):
            self._save(self._session_from(data, data.get("user") or self._state.get("user")))
        return parse_outcome(data)

    def _apply_tokens(self, data: Any) -> None:
        """A token answer (refresh, organization switch): rotate the stored tokens atomically."""
        if not isinstance(data, Mapping) or not data.get("access_token"):
            raise AppAuthError(502, "invalid_response", "Unexpected token answer from the user pool")
        self._save(self._session_from(data, self._state.get("user")))

    def _set_user(self, user: Any) -> None:
        if isinstance(user, Mapping) and self._state.get("refreshToken"):
            current = self._state.get("user") or {}
            if not current or current.get("id") in (None, user.get("id")):
                self._save({**self._state, "user": dict(user)})

    # --- public read-only state ------------------------------------------------------------------------------------

    @property
    def current_user(self) -> Optional[PoolUser]:
        """The signed-in user (as of the last sign-in, ``me()`` or profile change), or ``None``."""
        user = self._state.get("user")
        return PoolUser.from_dict(user) if isinstance(user, Mapping) and self.is_signed_in else None

    @property
    def current_org(self) -> Optional[ActiveOrg]:
        """The active organization (B2B pools), or ``None``."""
        org = self._state.get("org")
        return ActiveOrg.from_dict(org) if isinstance(org, Mapping) and self.is_signed_in else None

    @property
    def access_token_claims(self) -> Optional[Dict[str, Any]]:
        """The claims of the stored access token, decoded WITHOUT verification (display only; servers must verify)."""
        return decode_jwt(self._state.get("accessToken"))

    @property
    def is_signed_in(self) -> bool:
        return bool(self._state.get("refreshToken"))

    @property
    def id_token(self) -> Optional[str]:
        """The ID token of the last hosted-page sign-in (for ``build_logout_url``), or ``None``."""
        return self._state.get("idToken") or None

    def on_auth_state_changed(self, listener: Listener) -> Callable[[], None]:
        """Call ``listener(user, org)`` now and at every sign-in, renewal, change and sign-out. Returns a function that
        removes the listener. Listeners run on the thread that changed the state; their exceptions are ignored."""
        with self._state_lock:
            self._listeners.append(listener)
        try:
            listener(self.current_user, self.current_org)
        except Exception:
            pass

        def unsubscribe() -> None:
            with self._state_lock:
                if listener in self._listeners:
                    self._listeners.remove(listener)
        return unsubscribe

    # --- JSON API --------------------------------------------------------------------------------------------------

    def _api_args(self, method: str, path: str, body: Any, token: Optional[str]) -> Dict[str, Any]:
        headers = {"X-Client-Id": self.client_id, "Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        args: Dict[str, Any] = {"method": method, "url": f"{self.issuer}{API}{path}", "headers": headers}
        if body is not NO_BODY:
            headers["Content-Type"] = "application/json"
            args["content"] = json.dumps(compact(body) if isinstance(body, Mapping) else body).encode("utf-8")
        return args

    def _api_result(self, response: httpx.Response, *, signed_in: bool) -> Any:
        try:
            data = response.json()
        except ValueError:
            data = None
        if response.status_code >= 400:
            err = error_from_response(response.status_code, data, response.reason_phrase)
            if (signed_in and err.status == 401 and err.code.startswith("token_")) or err.code == "invalid_refresh_token":
                self._save(None)
            raise err
        return data

    # --- OpenID Connect ----------------------------------------------------------------------------------------------

    def build_authorization_request(self, *, redirect_uri: Optional[str] = None, provider: Optional[str] = None,
                                    org_id: Optional[str] = None, prompt: Optional[str] = None,
                                    screen_hint: Optional[str] = None, login_hint: Optional[str] = None,
                                    max_age: Optional[int] = None, scope: str = DEFAULT_SCOPE,
                                    ui_locales: Optional[str] = None,
                                    extra_params: Optional[Mapping[str, str]] = None) -> AuthorizationRequest:
        """The URL of the pool's hosted sign-in page (authorization code + PKCE S256), with fresh ``state``, ``nonce``
        and code verifier. The transaction is saved in the storage for :meth:`handle_redirect_callback`."""
        request = build_authorization_request(
            self.issuer, self.client_id, redirect_uri=redirect_uri or self.redirect_uri, provider=provider, org_id=org_id,
            prompt=prompt, screen_hint=screen_hint, login_hint=login_hint, max_age=max_age, scope=scope,
            ui_locales=ui_locales, extra_params=extra_params)
        self._storage.set(self._pkce_key, json.dumps(request.to_dict()))
        return request

    def _callback(self, url: str, authorization_request: Optional[AuthorizationRequest]) -> Tuple[str, AuthorizationRequest]:
        params = callback_params(url)
        pending = authorization_request
        if pending is None:
            try:
                raw = self._storage.get(self._pkce_key)
                pending = AuthorizationRequest.from_dict(json.loads(raw)) if raw else None
            except (ValueError, TypeError):
                pending = None
        try:
            code = check_callback(params, pending, self.issuer)
        finally:
            self._storage.remove(self._pkce_key)  # a transaction is used once, whatever the result
        assert pending is not None
        return code, pending

    def _token_args(self, form: Mapping[str, str]) -> Dict[str, Any]:
        return token_request_args(self.issuer, self.client_id, self._client_secret, self._auth_method, form)

    def _check_id_token(self, id_token: str, pending: AuthorizationRequest) -> None:
        """The ID token came straight from the token endpoint over TLS (OIDC Core 3.1.3.7): check its claims and the
        nonce. Servers wanting the signature checked too use :class:`OidcWebClient`."""
        claims = decode_jwt(id_token)
        if claims is None:
            raise AppAuthError(400, "invalid_id_token", "The ID token is not a JWT")
        aud = claims.get("aud")
        if claims.get("iss") != self.issuer or not (aud == self.client_id or (isinstance(aud, list) and self.client_id in aud)):
            raise AppAuthError(400, "invalid_id_token", "The ID token is not for this app")
        if not same(claims.get("nonce"), pending.nonce):
            raise AppAuthError(400, "invalid_nonce", "Nonce mismatch")

    def build_logout_url(self, post_logout_redirect_uri: Optional[str] = None, state: Optional[str] = None,
                         *, id_token_hint: Optional[str] = None) -> str:
        """The pool's end-session URL (ends the hosted page's browser session). It does not sign the client out:
        call ``sign_out()`` too."""
        return logout_url(self.issuer, self.client_id, id_token_hint=id_token_hint or self.id_token,
                          post_logout_redirect_uri=post_logout_redirect_uri, state=state)


# --- functions shared with OidcWebClient -------------------------------------------------------------------------------

def build_authorization_request(issuer: str, client_id: str, *, redirect_uri: Optional[str], provider: Optional[str] = None,
                                org_id: Optional[str] = None, prompt: Optional[str] = None,
                                screen_hint: Optional[str] = None, login_hint: Optional[str] = None,
                                max_age: Optional[int] = None, scope: str = DEFAULT_SCOPE,
                                ui_locales: Optional[str] = None,
                                extra_params: Optional[Mapping[str, str]] = None) -> AuthorizationRequest:
    if not redirect_uri:
        raise ValueError("redirect_uri is required (pass it here or to the constructor)")
    verifier = pkce_verifier()
    state = random_token(24)
    nonce = random_token(24)
    params: Dict[str, str] = {"response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri,
                              "scope": scope or DEFAULT_SCOPE, "state": state, "nonce": nonce,
                              "code_challenge": pkce_challenge(verifier), "code_challenge_method": "S256"}
    optional = {"provider": provider, "org_id": org_id, "prompt": prompt, "screen_hint": screen_hint,
                "login_hint": login_hint, "max_age": None if max_age is None else str(int(max_age)), "ui_locales": ui_locales}
    params.update({k: v for k, v in optional.items() if v})
    for key, value in (extra_params or {}).items():
        if key not in params and value is not None:
            params[key] = str(value)
    url = f"{issuer}/authorize?{urlencode(params, quote_via=quote)}"
    return AuthorizationRequest(url=url, state=state, nonce=nonce, code_verifier=verifier, redirect_uri=redirect_uri,
                                scope=params["scope"])


def callback_params(url_or_params: Any) -> Dict[str, str]:
    """The query parameters of a callback: a full URL, a query string, or a mapping (e.g. ``request.args``)."""
    if isinstance(url_or_params, Mapping):
        return {str(k): str(v) for k, v in url_or_params.items()}
    if hasattr(url_or_params, "items") and callable(url_or_params.items):  # MultiDict-like
        return {str(k): str(v) for k, v in url_or_params.items()}
    text = str(url_or_params or "")
    if "?" in text or "://" in text:
        text = urlsplit(text).query
    return dict(parse_qsl(text, keep_blank_values=True))


def check_callback(params: Mapping[str, str], pending: Optional[AuthorizationRequest], issuer: str) -> str:
    """Check a callback against its transaction (error, state in constant time, RFC 9207 ``iss``) -> the code."""
    if params.get("error"):
        raise AppAuthError(400, params["error"], params.get("error_description") or params["error"])
    if pending is None or not same(pending.state, params.get("state")):
        raise AppAuthError(400, "invalid_state", "Sign-in state mismatch")
    iss = params.get("iss")
    if iss is not None and iss.rstrip("/") != issuer:
        raise AppAuthError(400, "invalid_issuer", "Unexpected issuer in the callback")
    code = params.get("code")
    if not code:
        raise AppAuthError(400, "invalid_request", "The callback has no authorization code")
    return code


def token_request_args(issuer: str, client_id: str, client_secret: Optional[str], auth_method: str,
                       form: Mapping[str, str]) -> Dict[str, Any]:
    headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
    data = {k: v for k, v in form.items() if v is not None}
    data["client_id"] = client_id
    if client_secret:
        if auth_method == "client_secret_post":
            data["client_secret"] = client_secret
        else:
            headers["Authorization"] = basic_auth(client_id, client_secret)
    return {"method": "POST", "url": f"{issuer}/token", "headers": headers, "content": urlencode(data).encode("ascii")}


def token_result(response: httpx.Response) -> Dict[str, Any]:
    try:
        data = response.json()
    except ValueError:
        data = None
    if response.status_code >= 400:
        raise error_from_response(response.status_code, data, response.reason_phrase)
    if not isinstance(data, dict) or not data.get("access_token"):
        raise AppAuthError(502, "invalid_response", "Unexpected answer from the token endpoint")
    return data


def logout_url(issuer: str, client_id: str, *, id_token_hint: Optional[str] = None,
               post_logout_redirect_uri: Optional[str] = None, state: Optional[str] = None) -> str:
    params = compact({"client_id": client_id, "id_token_hint": id_token_hint,
                      "post_logout_redirect_uri": post_logout_redirect_uri, "state": state})
    return f"{issuer}/logout?{urlencode(params, quote_via=quote)}"


def network_error(exc: BaseException) -> AppAuthError:
    return AppAuthError(0, "network_error", f"Network error talking to the user pool ({type(exc).__name__})")


class BearerAuth(httpx.Auth):
    """``httpx`` auth adding ``Authorization: Bearer <access token>`` (renewed when about to expire)."""

    def __init__(self, sync_token: Optional[Callable[[], str]] = None, async_token: Optional[Callable[[], Any]] = None):
        self._sync = sync_token
        self._async = async_token

    def sync_auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        if self._sync is None:
            raise TypeError("this auth belongs to an AsyncClient: use it with httpx.AsyncClient")
        request.headers["Authorization"] = f"Bearer {self._sync()}"
        yield request

    async def async_auth_flow(self, request: httpx.Request):  # type: ignore[override]
        if self._async is None:
            raise TypeError("this auth belongs to a Client: use it with httpx.Client")
        request.headers["Authorization"] = f"Bearer {await self._async()}"
        yield request
