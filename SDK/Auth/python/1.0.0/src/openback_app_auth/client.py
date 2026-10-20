"""The synchronous client of a user pool (CLI, desktop, scripts, synchronous servers)."""
from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import quote, urlencode

import httpx

from ._base import NO_BODY, BearerAuth, _ClientBase, network_error, token_result
from .errors import AppAuthError
from .models import (ActiveOrg, AddedMember, AuthorizationRequest, MemberPage, Member, MfaConfirmation, MfaEnrollment,
                     Organization, OrganizationList, OrgRole, Outcome, PoolUser)
from .storage import Storage

__all__ = ["Client"]


class Client(_ClientBase):
    """A user pool's client.

    >>> auth = Client("https://api.example.com/gateway/shop/auth/main", "uapp_...")
    >>> outcome = auth.sign_in_with_password("ada@example.com", "secret")
    >>> if outcome.status == "mfa_required":
    ...     outcome = auth.verify_mfa(outcome.mfa_token, input("Code: "))
    >>> token = auth.get_access_token()

    Args:
        issuer: the pool's address (its OIDC issuer), e.g. ``https://api.example.com/gateway/shop/auth/main``.
        client_id: the app's client ID (``uapp_...``), registered in the pool's Apps tab.
        redirect_uri: default redirect URI for the hosted-page sign-in (must match a registered one exactly).
        storage: where the session is kept (default: in memory). See :class:`~openback_app_auth.FileStorage`.
        storage_key: the storage key (default ``openback.auth.<client_id>``).
        http_client: an ``httpx.Client`` to use (proxies, certificates, tests); the client does not close it.
        client_secret: only for ``web``/``backend`` apps: authenticates the code exchange at ``/token``.
        token_endpoint_auth_method: ``client_secret_basic`` (default) or ``client_secret_post``.
        timeout: timeout in seconds of the client's own ``httpx.Client``.
    """

    def __init__(self, issuer: str, client_id: str, *, redirect_uri: Optional[str] = None,
                 storage: Optional[Storage] = None, storage_key: Optional[str] = None,
                 http_client: Optional[httpx.Client] = None, client_secret: Optional[str] = None,
                 token_endpoint_auth_method: str = "client_secret_basic", timeout: float = 30.0) -> None:
        super().__init__(issuer, client_id, redirect_uri=redirect_uri, storage=storage, storage_key=storage_key,
                         client_secret=client_secret, token_endpoint_auth_method=token_endpoint_auth_method)
        self._own_http = http_client is None
        self._http = http_client if http_client is not None else httpx.Client(timeout=timeout)
        self._refresh_lock = threading.RLock()

    # --- lifecycle ---------------------------------------------------------------------------------------------------

    def close(self) -> None:
        """Close the client's own HTTP connections (not an ``http_client`` you passed in)."""
        if self._own_http:
            self._http.close()

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # --- plumbing ----------------------------------------------------------------------------------------------------

    def _send(self, args: Dict[str, Any]) -> httpx.Response:
        try:
            return self._http.request(**args)
        except httpx.HTTPError as exc:
            raise network_error(exc) from exc

    def _call(self, method: str, path: str, body: Any = NO_BODY, *, auth: bool = False, token: Optional[str] = None) -> Any:
        if auth and token is None:
            token = self.get_access_token()
        return self._api_result(self._send(self._api_args(method, path, body, token if auth else None)), signed_in=auth)

    # --- tokens ------------------------------------------------------------------------------------------------------

    def config(self) -> Dict[str, Any]:
        """The pool's public configuration: methods, sign-up, password policy, MFA mode, providers, branding."""
        return self._call("GET", "/config")

    def get_access_token(self) -> str:
        """A valid access token: the stored one if it expires in more than 60 s, else a renewed one (one refresh at a
        time). Raises :class:`AppAuthError` ``not_signed_in`` (401) without a session."""
        with self._state_lock:
            state = dict(self._state)
        if self._is_fresh(state):
            return state["accessToken"]
        return self.refresh()

    def refresh(self, org_id: Optional[str] = None) -> str:
        """Renew the access token now (rotating the refresh token); ``org_id`` asks for another organization's
        tokens. Single-flight: concurrent callers wait for the one refresh in progress and share its result. A network
        error is raised as is and never retried (the request may have reached the server)."""
        before = self._state.get("refreshToken")
        with self._refresh_lock:
            return self._refresh_locked(before, org_id)

    def _refresh_locked(self, before: Optional[str], org_id: Optional[str] = None) -> str:
        latest = self._latest()
        refresh_token = latest.get("refreshToken")
        if not refresh_token:
            raise AppAuthError(401, "not_signed_in", "Not signed in")
        if org_id is None and refresh_token != before and self._is_fresh(latest):
            return latest["accessToken"]  # another caller renewed it meanwhile
        try:
            data = self._call("POST", "/token/refresh", {"refresh_token": refresh_token, "org_id": org_id})
        except AppAuthError as exc:
            if exc.status == 401:
                self._save(None)
            raise
        self._apply_tokens(data)
        return self._state["accessToken"]

    def _token_locked(self) -> str:
        if self._is_fresh(self._state):
            return self._state["accessToken"]
        return self._refresh_locked(self._state.get("refreshToken"))

    @property
    def auth(self) -> BearerAuth:
        """An ``httpx.Auth`` adding the user's bearer token: ``httpx.get(url, auth=client.auth)``."""
        return BearerAuth(sync_token=self.get_access_token)

    def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Call YOUR API as the signed-in user (``Authorization: Bearer``), with the client's ``httpx.Client``."""
        return self._http.request(method, url, auth=self.auth, **kwargs)

    # --- sign-up and sign-in -----------------------------------------------------------------------------------------

    def sign_up(self, email: str, password: str, *, display_name: Optional[str] = None, locale: Optional[str] = None,
                org_id: Optional[str] = None) -> Outcome:
        """Create an account with email and password."""
        return self._apply_outcome(self._call("POST", "/signup", {"email": email, "password": password,
                                                                    "display_name": display_name or "", "locale": locale,
                                                                    "org_id": org_id}))

    def sign_in_with_password(self, email: str, password: str, *, org_id: Optional[str] = None) -> Outcome:
        return self._apply_outcome(self._call("POST", "/signin/password", {"email": email, "password": password,
                                                                             "org_id": org_id}))

    def send_email_code(self, email: str) -> None:
        """Email a one-time sign-in code and link (always succeeds, whether the account exists or not)."""
        self._call("POST", "/signin/email-code", {"email": email})

    def sign_in_with_email_code(self, email: Optional[str] = None, code: Optional[str] = None, *,
                                token: Optional[str] = None, org_id: Optional[str] = None) -> Outcome:
        """Sign in with the emailed code (``email`` + ``code``) or the link's ``token``."""
        return self._apply_outcome(self._call("POST", "/signin/email-code/verify", {"email": email, "code": code,
                                                                                      "token": token, "org_id": org_id}))

    def sign_in_anonymously(self) -> Outcome:
        """A guest account (if the pool allows it); ``upgrade_anonymous`` turns it into a real one later."""
        return self._apply_outcome(self._call("POST", "/signin/anonymous"))

    def verify_mfa(self, mfa_token: str, code: str) -> Outcome:
        """The second factor of a sign-in: a TOTP code or a recovery code."""
        return self._apply_outcome(self._call("POST", "/signin/mfa", {"mfa_token": mfa_token, "code": code}))

    def enroll_mfa(self, mfa_token: Optional[str] = None) -> MfaEnrollment:
        """Start a TOTP enrollment: during a sign-in (``mfa_token`` of ``mfa_enroll_required``) or signed in."""
        data = (self._call("POST", "/mfa/enroll", {"mfa_token": mfa_token}) if mfa_token
                else self._call("POST", "/mfa/enroll", {}, auth=True))
        return MfaEnrollment(secret=str(data.get("secret") or ""), otpauth_uri=str(data.get("otpauth_uri") or ""))

    def confirm_mfa(self, code: str, mfa_token: Optional[str] = None) -> MfaConfirmation:
        """Confirm the enrollment with a code from the authenticator app. With ``mfa_token`` the sign-in completes
        (``outcome``); the recovery codes are returned once."""
        if mfa_token:
            data = self._call("POST", "/mfa/enroll/confirm", {"mfa_token": mfa_token, "code": code})
            outcome = self._apply_outcome(data)
            return MfaConfirmation(recovery_codes=list(data.get("recovery_codes") or []), outcome=outcome)
        data = self._call("POST", "/mfa/enroll/confirm", {"code": code}, auth=True)
        return MfaConfirmation(recovery_codes=list(data.get("recovery_codes") or []))

    def disable_mfa(self, code: str) -> None:
        self._call("POST", "/mfa/disable", {"code": code}, auth=True)

    # --- passwords and emails ----------------------------------------------------------------------------------------

    def send_password_reset(self, email: str) -> None:
        """Email a reset code and link (always succeeds)."""
        self._call("POST", "/password/forgot", {"email": email})

    def reset_password(self, new_password: str, *, token: Optional[str] = None, email: Optional[str] = None,
                       code: Optional[str] = None) -> None:
        """Set a new password with the emailed link ``token`` or ``email`` + ``code``. Sign in again afterwards."""
        self._call("POST", "/password/reset", {"token": token, "email": email, "code": code, "new_password": new_password})

    def change_forced_password(self, change_token: str, new_password: str) -> None:
        """Answer ``password_change_required``: set the user's own password, then sign in again with it."""
        self._call("POST", "/password/reset", {"change_token": change_token, "new_password": new_password})

    def verify_email(self, *, token: Optional[str] = None, email: Optional[str] = None,
                     code: Optional[str] = None) -> PoolUser:
        """Verify the email address with the link ``token`` or ``email`` + ``code``."""
        data = self._call("POST", "/email/verify", {"token": token, "email": email, "code": code})
        self._set_user(data.get("user"))
        return PoolUser.from_dict(data.get("user") or {})

    def resend_verification(self) -> None:
        """Send the verification email again (signed in)."""
        self._call("POST", "/email/verify/send", {}, auth=True)

    # --- the signed-in user ------------------------------------------------------------------------------------------

    def me(self) -> PoolUser:
        """The signed-in user, fresh from the pool (also updates ``current_user``)."""
        data = self._call("GET", "/me", auth=True)
        self._set_user(data)
        return PoolUser.from_dict(data)

    def update_profile(self, *, display_name: Optional[str] = None, photo_url: Optional[str] = None,
                       locale: Optional[str] = None) -> PoolUser:
        """Change profile fields (only those given; pass ``""`` to clear one)."""
        data = self._call("PATCH", "/me", {"display_name": display_name, "photo_url": photo_url, "locale": locale}, auth=True)
        self._set_user(data)
        return PoolUser.from_dict(data)

    def change_password(self, new_password: str, current_password: Optional[str] = None) -> None:
        """Change the password. Every session of the user ends, this one too: the client is signed out."""
        self._call("POST", "/me/password", {"current_password": current_password, "new_password": new_password}, auth=True)
        self._save(None)

    def change_email(self, new_email: str) -> None:
        """Send a confirmation code to the new address; finish with :meth:`confirm_email_change`."""
        self._call("POST", "/me/email", {"new_email": new_email}, auth=True)

    def confirm_email_change(self, *, code: Optional[str] = None, token: Optional[str] = None) -> PoolUser:
        data = self._call("POST", "/me/email/confirm", {"code": code, "token": token}, auth=True)
        self._set_user(data.get("user"))
        return PoolUser.from_dict(data.get("user") or {})

    def upgrade_anonymous(self, email: str, password: str) -> PoolUser:
        """Turn the guest account into a real one (same user id); a verification email is sent."""
        data = self._call("POST", "/me/upgrade", {"email": email, "password": password}, auth=True)
        self._set_user(data.get("user"))
        return PoolUser.from_dict(data.get("user") or {})

    def delete_account(self, password: Optional[str] = None) -> None:
        """Delete the user's account (``password`` required when the account has one). Signs the client out."""
        self._call("DELETE", "/me", {"password": password}, auth=True)
        self._save(None)

    def sign_out(self, everywhere: bool = False) -> None:
        """End the session on the pool (best effort; ``everywhere`` ends all the user's sessions) and always clear it
        locally."""
        with self._refresh_lock:
            state = dict(self._state)
            try:
                if state.get("refreshToken"):
                    token = state.get("accessToken") if self._is_fresh(state) else None
                    if everywhere and token is None:
                        token = self._refresh_locked(state.get("refreshToken"))
                    self._call("POST", "/signout", {"refresh_token": self._state.get("refreshToken") or state.get("refreshToken"),
                                                    "everywhere": everywhere}, auth=token is not None, token=token)
            except AppAuthError:
                pass  # signed out locally anyway
            finally:
                self._save(None)

    # --- organizations (B2B pools) -----------------------------------------------------------------------------------

    def organizations(self) -> OrganizationList:
        data = self._call("GET", "/orgs", auth=True)
        return OrganizationList(orgs=[Organization.from_dict(o) for o in data.get("orgs") or []], active=data.get("active"))

    def create_organization(self, name: str) -> Organization:
        """Create an organization (if the pool allows self-service); the user becomes its owner."""
        return Organization.from_dict(self._call("POST", "/orgs", {"name": name}, auth=True))

    def switch_organization(self, org_id: str) -> Optional[ActiveOrg]:
        """Get tokens for another organization of the user; returns the new active organization."""
        with self._refresh_lock:
            token = self._token_locked()
            data = self._call("POST", "/orgs/switch", {"org_id": org_id, "refresh_token": self._state.get("refreshToken")},
                              auth=True, token=token)
            self._apply_tokens(data)
        return self.current_org

    def members(self, org_id: str, *, q: str = "", skip: int = 0, limit: int = 50) -> MemberPage:
        """The members of an organization (its owners and admins only)."""
        data = self._call("GET", _members_path(org_id, q, skip, limit), auth=True)
        return _member_page(data)

    def add_member(self, org_id: str, email: str, *, display_name: Optional[str] = None, password: Optional[str] = None,
                   roles: Optional[Sequence[str]] = None) -> AddedMember:
        data = self._call("POST", f"/orgs/{_seg(org_id)}/members",
                          {"email": email, "display_name": display_name or "", "password": password, "roles": list(roles or [])},
                          auth=True)
        return _added_member(data)

    def set_member_roles(self, org_id: str, user_id: str, roles: Sequence[str]) -> List[str]:
        data = self._call("PATCH", f"/orgs/{_seg(org_id)}/members/{_seg(user_id)}", {"roles": list(roles)}, auth=True)
        return list((data or {}).get("roles") or [])

    def remove_member(self, org_id: str, user_id: str) -> None:
        self._call("DELETE", f"/orgs/{_seg(org_id)}/members/{_seg(user_id)}", auth=True)

    # --- OpenID Connect (hosted page) --------------------------------------------------------------------------------

    def handle_redirect_callback(self, url: str, authorization_request: Optional[AuthorizationRequest] = None) -> Optional[PoolUser]:
        """Finish a hosted-page sign-in: check ``error``, ``state`` and ``iss`` of the callback URL, exchange the code
        (PKCE), check the ID token's nonce, keep the session and return the user. The transaction comes from the
        storage unless given."""
        code, pending = self._callback(url, authorization_request)
        data = token_result(self._send(self._token_args({"grant_type": "authorization_code", "code": code,
                                                         "redirect_uri": pending.redirect_uri,
                                                         "code_verifier": pending.code_verifier})))
        if data.get("id_token"):
            self._check_id_token(data["id_token"], pending)
        with self._refresh_lock:
            self._save(self._session_from(data, None))
        try:
            return self.me()
        except AppAuthError:
            return None


# --- helpers shared with AsyncClient -------------------------------------------------------------------------------------

def _seg(value: str) -> str:
    return quote(str(value), safe="")


def _members_path(org_id: str, q: str, skip: int, limit: int) -> str:
    return f"/orgs/{_seg(org_id)}/members?{urlencode({'q': q or '', 'skip': int(skip), 'limit': int(limit)})}"


def _member_page(data: Any) -> MemberPage:
    data = data or {}
    roles = [OrgRole(key=str(r.get("key") or ""), label=str(r.get("label") or "")) for r in data.get("roles") or []
             if isinstance(r, dict)]
    total = data.get("total")
    return MemberPage(items=[Member.from_dict(m) for m in data.get("items") or [] if isinstance(m, dict)],
                      total=int(total) if isinstance(total, int) else None, roles=roles)


def _added_member(data: Any) -> AddedMember:
    data = data or {}
    return AddedMember(user_id=str(data.get("user_id") or ""), email=data.get("email"), roles=list(data.get("roles") or []),
                       created=bool(data.get("created")), temporary_password=data.get("temporary_password"))

