"""The asynchronous client of a user pool (asyncio apps and servers)."""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional, Sequence

import httpx

from ._base import NO_BODY, BearerAuth, _ClientBase, network_error, token_result
from .client import _added_member, _member_page, _members_path, _seg
from .errors import AppAuthError
from .models import (ActiveOrg, AddedMember, AuthorizationRequest, MemberPage, MfaConfirmation, MfaEnrollment,
                     Organization, OrganizationList, Outcome, PoolUser)
from .storage import Storage

__all__ = ["AsyncClient"]


class AsyncClient(_ClientBase):
    """The ``async`` twin of :class:`~openback_app_auth.Client`: same arguments, same methods, awaited.

    >>> auth = AsyncClient("https://api.example.com/gateway/shop/auth/main", "uapp_...")
    >>> outcome = await auth.sign_in_with_password("ada@example.com", "secret")
    >>> token = await auth.get_access_token()

    ``http_client`` is an ``httpx.AsyncClient``. Use the client from one event loop.
    """

    def __init__(self, issuer: str, client_id: str, *, redirect_uri: Optional[str] = None,
                 storage: Optional[Storage] = None, storage_key: Optional[str] = None,
                 http_client: Optional[httpx.AsyncClient] = None, client_secret: Optional[str] = None,
                 token_endpoint_auth_method: str = "client_secret_basic", timeout: float = 30.0) -> None:
        super().__init__(issuer, client_id, redirect_uri=redirect_uri, storage=storage, storage_key=storage_key,
                         client_secret=client_secret, token_endpoint_auth_method=token_endpoint_auth_method)
        self._own_http = http_client is None
        self._http = http_client if http_client is not None else httpx.AsyncClient(timeout=timeout)
        self._lock: Optional[asyncio.Lock] = None
        self._lock_loop: Optional[asyncio.AbstractEventLoop] = None

    def _refresh_lock(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        if self._lock is None or self._lock_loop is not loop:
            self._lock, self._lock_loop = asyncio.Lock(), loop
        return self._lock

    # --- lifecycle ---------------------------------------------------------------------------------------------------

    async def aclose(self) -> None:
        """Close the client's own HTTP connections (not an ``http_client`` you passed in)."""
        if self._own_http:
            await self._http.aclose()

    async def __aenter__(self) -> "AsyncClient":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()

    # --- plumbing ----------------------------------------------------------------------------------------------------

    async def _send(self, args: Dict[str, Any]) -> httpx.Response:
        try:
            return await self._http.request(**args)
        except httpx.HTTPError as exc:
            raise network_error(exc) from exc

    async def _call(self, method: str, path: str, body: Any = NO_BODY, *, auth: bool = False,
                    token: Optional[str] = None) -> Any:
        if auth and token is None:
            token = await self.get_access_token()
        response = await self._send(self._api_args(method, path, body, token if auth else None))
        return self._api_result(response, signed_in=auth)

    # --- tokens ------------------------------------------------------------------------------------------------------

    async def config(self) -> Dict[str, Any]:
        return await self._call("GET", "/config")

    async def get_access_token(self) -> str:
        state = dict(self._state)
        if self._is_fresh(state):
            return state["accessToken"]
        return await self.refresh()

    async def refresh(self, org_id: Optional[str] = None) -> str:
        before = self._state.get("refreshToken")
        async with self._refresh_lock():
            return await self._refresh_locked(before, org_id)

    async def _refresh_locked(self, before: Optional[str], org_id: Optional[str] = None) -> str:
        latest = self._latest()
        refresh_token = latest.get("refreshToken")
        if not refresh_token:
            raise AppAuthError(401, "not_signed_in", "Not signed in")
        if org_id is None and refresh_token != before and self._is_fresh(latest):
            return latest["accessToken"]
        try:
            data = await self._call("POST", "/token/refresh", {"refresh_token": refresh_token, "org_id": org_id})
        except AppAuthError as exc:
            if exc.status == 401:
                self._save(None)
            raise
        self._apply_tokens(data)
        return self._state["accessToken"]

    async def _token_locked(self) -> str:
        if self._is_fresh(self._state):
            return self._state["accessToken"]
        return await self._refresh_locked(self._state.get("refreshToken"))

    @property
    def auth(self) -> BearerAuth:
        """An ``httpx.Auth`` for ``httpx.AsyncClient``: ``await http.get(url, auth=client.auth)``."""
        return BearerAuth(async_token=self.get_access_token)

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Call YOUR API as the signed-in user (``Authorization: Bearer``)."""
        return await self._http.request(method, url, auth=self.auth, **kwargs)

    # --- sign-up and sign-in -----------------------------------------------------------------------------------------

    async def sign_up(self, email: str, password: str, *, display_name: Optional[str] = None,
                      locale: Optional[str] = None, org_id: Optional[str] = None) -> Outcome:
        return self._apply_outcome(await self._call("POST", "/signup", {"email": email, "password": password,
                                                                          "display_name": display_name or "",
                                                                          "locale": locale, "org_id": org_id}))

    async def sign_in_with_password(self, email: str, password: str, *, org_id: Optional[str] = None) -> Outcome:
        return self._apply_outcome(await self._call("POST", "/signin/password", {"email": email, "password": password,
                                                                                   "org_id": org_id}))

    async def send_email_code(self, email: str) -> None:
        await self._call("POST", "/signin/email-code", {"email": email})

    async def sign_in_with_email_code(self, email: Optional[str] = None, code: Optional[str] = None, *,
                                      token: Optional[str] = None, org_id: Optional[str] = None) -> Outcome:
        return self._apply_outcome(await self._call("POST", "/signin/email-code/verify",
                                                    {"email": email, "code": code, "token": token, "org_id": org_id}))

    async def sign_in_anonymously(self) -> Outcome:
        return self._apply_outcome(await self._call("POST", "/signin/anonymous"))

    async def verify_mfa(self, mfa_token: str, code: str) -> Outcome:
        return self._apply_outcome(await self._call("POST", "/signin/mfa", {"mfa_token": mfa_token, "code": code}))

    async def enroll_mfa(self, mfa_token: Optional[str] = None) -> MfaEnrollment:
        data = (await self._call("POST", "/mfa/enroll", {"mfa_token": mfa_token}) if mfa_token
                else await self._call("POST", "/mfa/enroll", {}, auth=True))
        return MfaEnrollment(secret=str(data.get("secret") or ""), otpauth_uri=str(data.get("otpauth_uri") or ""))

    async def confirm_mfa(self, code: str, mfa_token: Optional[str] = None) -> MfaConfirmation:
        if mfa_token:
            data = await self._call("POST", "/mfa/enroll/confirm", {"mfa_token": mfa_token, "code": code})
            outcome = self._apply_outcome(data)
            return MfaConfirmation(recovery_codes=list(data.get("recovery_codes") or []), outcome=outcome)
        data = await self._call("POST", "/mfa/enroll/confirm", {"code": code}, auth=True)
        return MfaConfirmation(recovery_codes=list(data.get("recovery_codes") or []))

    async def disable_mfa(self, code: str) -> None:
        await self._call("POST", "/mfa/disable", {"code": code}, auth=True)

    # --- passwords and emails ----------------------------------------------------------------------------------------

    async def send_password_reset(self, email: str) -> None:
        await self._call("POST", "/password/forgot", {"email": email})

    async def reset_password(self, new_password: str, *, token: Optional[str] = None, email: Optional[str] = None,
                             code: Optional[str] = None) -> None:
        await self._call("POST", "/password/reset", {"token": token, "email": email, "code": code,
                                                     "new_password": new_password})

    async def change_forced_password(self, change_token: str, new_password: str) -> None:
        await self._call("POST", "/password/reset", {"change_token": change_token, "new_password": new_password})

    async def verify_email(self, *, token: Optional[str] = None, email: Optional[str] = None,
                           code: Optional[str] = None) -> PoolUser:
        data = await self._call("POST", "/email/verify", {"token": token, "email": email, "code": code})
        self._set_user(data.get("user"))
        return PoolUser.from_dict(data.get("user") or {})

    async def resend_verification(self) -> None:
        await self._call("POST", "/email/verify/send", {}, auth=True)

    # --- the signed-in user ------------------------------------------------------------------------------------------

    async def me(self) -> PoolUser:
        data = await self._call("GET", "/me", auth=True)
        self._set_user(data)
        return PoolUser.from_dict(data)

    async def update_profile(self, *, display_name: Optional[str] = None, photo_url: Optional[str] = None,
                             locale: Optional[str] = None) -> PoolUser:
        data = await self._call("PATCH", "/me", {"display_name": display_name, "photo_url": photo_url, "locale": locale},
                                auth=True)
        self._set_user(data)
        return PoolUser.from_dict(data)

    async def change_password(self, new_password: str, current_password: Optional[str] = None) -> None:
        await self._call("POST", "/me/password", {"current_password": current_password, "new_password": new_password},
                         auth=True)
        self._save(None)

    async def change_email(self, new_email: str) -> None:
        await self._call("POST", "/me/email", {"new_email": new_email}, auth=True)

    async def confirm_email_change(self, *, code: Optional[str] = None, token: Optional[str] = None) -> PoolUser:
        data = await self._call("POST", "/me/email/confirm", {"code": code, "token": token}, auth=True)
        self._set_user(data.get("user"))
        return PoolUser.from_dict(data.get("user") or {})

    async def upgrade_anonymous(self, email: str, password: str) -> PoolUser:
        data = await self._call("POST", "/me/upgrade", {"email": email, "password": password}, auth=True)
        self._set_user(data.get("user"))
        return PoolUser.from_dict(data.get("user") or {})

    async def delete_account(self, password: Optional[str] = None) -> None:
        await self._call("DELETE", "/me", {"password": password}, auth=True)
        self._save(None)

    async def sign_out(self, everywhere: bool = False) -> None:
        async with self._refresh_lock():
            state = dict(self._state)
            try:
                if state.get("refreshToken"):
                    token = state.get("accessToken") if self._is_fresh(state) else None
                    if everywhere and token is None:
                        token = await self._refresh_locked(state.get("refreshToken"))
                    await self._call("POST", "/signout",
                                     {"refresh_token": self._state.get("refreshToken") or state.get("refreshToken"),
                                      "everywhere": everywhere}, auth=token is not None, token=token)
            except AppAuthError:
                pass
            finally:
                self._save(None)

    # --- organizations (B2B pools) -----------------------------------------------------------------------------------

    async def organizations(self) -> OrganizationList:
        data = await self._call("GET", "/orgs", auth=True)
        return OrganizationList(orgs=[Organization.from_dict(o) for o in data.get("orgs") or []], active=data.get("active"))

    async def create_organization(self, name: str) -> Organization:
        return Organization.from_dict(await self._call("POST", "/orgs", {"name": name}, auth=True))

    async def switch_organization(self, org_id: str) -> Optional[ActiveOrg]:
        async with self._refresh_lock():
            token = await self._token_locked()
            data = await self._call("POST", "/orgs/switch",
                                    {"org_id": org_id, "refresh_token": self._state.get("refreshToken")}, auth=True, token=token)
            self._apply_tokens(data)
        return self.current_org

    async def members(self, org_id: str, *, q: str = "", skip: int = 0, limit: int = 50) -> MemberPage:
        return _member_page(await self._call("GET", _members_path(org_id, q, skip, limit), auth=True))

    async def add_member(self, org_id: str, email: str, *, display_name: Optional[str] = None,
                         password: Optional[str] = None, roles: Optional[Sequence[str]] = None) -> AddedMember:
        data = await self._call("POST", f"/orgs/{_seg(org_id)}/members",
                                {"email": email, "display_name": display_name or "", "password": password,
                                 "roles": list(roles or [])}, auth=True)
        return _added_member(data)

    async def set_member_roles(self, org_id: str, user_id: str, roles: Sequence[str]) -> List[str]:
        data = await self._call("PATCH", f"/orgs/{_seg(org_id)}/members/{_seg(user_id)}", {"roles": list(roles)}, auth=True)
        return list((data or {}).get("roles") or [])

    async def remove_member(self, org_id: str, user_id: str) -> None:
        await self._call("DELETE", f"/orgs/{_seg(org_id)}/members/{_seg(user_id)}", auth=True)

    # --- OpenID Connect (hosted page) --------------------------------------------------------------------------------

    async def handle_redirect_callback(self, url: str,
                                       authorization_request: Optional[AuthorizationRequest] = None) -> Optional[PoolUser]:
        code, pending = self._callback(url, authorization_request)
        data = token_result(await self._send(self._token_args({"grant_type": "authorization_code", "code": code,
                                                               "redirect_uri": pending.redirect_uri,
                                                               "code_verifier": pending.code_verifier})))
        if data.get("id_token"):
            self._check_id_token(data["id_token"], pending)
        async with self._refresh_lock():
            self._save(self._session_from(data, None))
        try:
            return await self.me()
        except AppAuthError:
            return None
