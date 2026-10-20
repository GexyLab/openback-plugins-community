"""Typed results returned by the SDK.

Every object keeps the service's answer in ``raw`` (hidden from ``repr``) so fields added by later versions of the
service stay reachable. Secrets (tokens, MFA tokens, change tokens, TOTP secrets, temporary passwords) never appear in
``repr``.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Mapping, Optional, Union


__all__ = [
    "PoolUser", "ActiveOrg", "SignedIn", "VerificationRequired", "MfaRequired", "MfaEnrollRequired",
    "PasswordChangeRequired", "OtherOutcome", "Outcome", "parse_outcome", "MfaEnrollment", "MfaConfirmation",
    "Organization", "OrganizationList", "OrgRole", "Member", "MemberPage", "AddedMember", "AuthorizationRequest",
    "TokenSet", "AppUser",
]


def _list(value: Any) -> List[Any]:
    return list(value) if isinstance(value, (list, tuple)) else []


def _dict(value: Any) -> Dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


# --- users and organizations -----------------------------------------------------------------------------------------

@dataclass(frozen=True)
class PoolUser:
    """A user of the pool, as the user sees themselves (``GET /me`` and sign-in answers)."""

    id: str
    email: Optional[str] = None
    email_verified: bool = False
    display_name: str = ""
    photo_url: Optional[str] = None
    locale: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    anonymous: bool = False
    created_at: Optional[str] = None
    last_login_at: Optional[str] = None
    mfa: Dict[str, Any] = field(default_factory=dict)
    #: Only in ``me()``: the token's active organization and roles, the linked providers, whether a password is set.
    org_id: Optional[str] = None
    roles: List[str] = field(default_factory=list)
    providers: List[Dict[str, Any]] = field(default_factory=list)
    has_password: Optional[bool] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @property
    def mfa_enabled(self) -> bool:
        return bool(self.mfa.get("totp"))

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "PoolUser":
        return cls(
            id=str(data.get("id") or ""),
            email=data.get("email"),
            email_verified=bool(data.get("email_verified")),
            display_name=data.get("display_name") or "",
            photo_url=data.get("photo_url"),
            locale=data.get("locale"),
            attributes=_dict(data.get("attributes")),
            anonymous=bool(data.get("anonymous")),
            created_at=_iso(data.get("created_at")),
            last_login_at=_iso(data.get("last_login_at")),
            mfa=_dict(data.get("mfa")),
            org_id=data.get("org_id"),
            roles=_list(data.get("roles")),
            providers=_list(data.get("providers")),
            has_password=data.get("has_password") if isinstance(data.get("has_password"), bool) else None,
            raw=dict(data),
        )


@dataclass(frozen=True)
class ActiveOrg:
    """The organization of the session (B2B pools; ``None`` in B2C pools)."""

    id: str
    name: Optional[str] = None
    roles: List[str] = field(default_factory=list)
    #: The organizations the user may switch to: ``[{"id", "name"}]``.
    choices: List[Dict[str, Any]] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ActiveOrg":
        return cls(id=str(data.get("id") or ""), name=data.get("name"), roles=_list(data.get("roles")),
                   choices=_list(data.get("choices")), raw=dict(data))


def _iso(value: Any) -> Optional[str]:
    if value is None:
        return None
    return value if isinstance(value, str) else str(value)


# --- outcomes of a sign-in ---------------------------------------------------------------------------------------------

_SECRET_KEYS = ("access_token", "refresh_token", "id_token", "mfa_token", "change_token")


def _public(data: Mapping[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in data.items() if k not in _SECRET_KEYS}


@dataclass(frozen=True)
class SignedIn:
    """``status == "ok"``: signed in; the SDK keeps the session (tokens are in the storage, not here)."""

    status: Literal["ok"] = field(default="ok", init=False)
    user: Optional[PoolUser] = None
    org: Optional[ActiveOrg] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False, compare=False)


@dataclass(frozen=True)
class VerificationRequired:
    """The email address must be verified first: a code and a link were sent to it."""

    status: Literal["verification_required"] = field(default="verification_required", init=False)
    raw: Dict[str, Any] = field(default_factory=dict, repr=False, compare=False)


@dataclass(frozen=True)
class MfaRequired:
    """The second factor is due: call ``verify_mfa(mfa_token, code)`` with a TOTP or a recovery code."""

    status: Literal["mfa_required"] = field(default="mfa_required", init=False)
    mfa_token: str = field(default="", repr=False)
    raw: Dict[str, Any] = field(default_factory=dict, repr=False, compare=False)


@dataclass(frozen=True)
class MfaEnrollRequired:
    """Two factors are required and the user has none yet: ``enroll_mfa(mfa_token)`` then
    ``confirm_mfa(code, mfa_token)``."""

    status: Literal["mfa_enroll_required"] = field(default="mfa_enroll_required", init=False)
    mfa_token: str = field(default="", repr=False)
    raw: Dict[str, Any] = field(default_factory=dict, repr=False, compare=False)


@dataclass(frozen=True)
class PasswordChangeRequired:
    """A password set by an administrator must be changed first: ``change_forced_password(change_token, new)``."""

    status: Literal["password_change_required"] = field(default="password_change_required", init=False)
    change_token: str = field(default="", repr=False)
    raw: Dict[str, Any] = field(default_factory=dict, repr=False, compare=False)


@dataclass(frozen=True)
class OtherOutcome:
    """A status this SDK version does not know (a newer service)."""

    status: str = ""
    raw: Dict[str, Any] = field(default_factory=dict, repr=False, compare=False)


Outcome = Union[SignedIn, VerificationRequired, MfaRequired, MfaEnrollRequired, PasswordChangeRequired, OtherOutcome]


def parse_outcome(data: Mapping[str, Any]) -> Outcome:
    """Turn a sign-in answer into its typed outcome (tokens are NOT copied into the result)."""
    status = data.get("status")
    raw = _public(data)
    if status == "ok":
        user = data.get("user")
        org = data.get("org")
        return SignedIn(user=PoolUser.from_dict(user) if isinstance(user, Mapping) else None,
                        org=ActiveOrg.from_dict(org) if isinstance(org, Mapping) else None, raw=raw)
    if status == "verification_required":
        return VerificationRequired(raw=raw)
    if status == "mfa_required":
        return MfaRequired(mfa_token=str(data.get("mfa_token") or ""), raw=raw)
    if status == "mfa_enroll_required":
        return MfaEnrollRequired(mfa_token=str(data.get("mfa_token") or ""), raw=raw)
    if status == "password_change_required":
        return PasswordChangeRequired(change_token=str(data.get("change_token") or ""), raw=raw)
    return OtherOutcome(status=str(status or ""), raw=raw)


# --- two-step verification ---------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class MfaEnrollment:
    """A new (pending) TOTP secret: show ``otpauth_uri`` as a QR code, then confirm with a code."""

    secret: str = field(repr=False)
    otpauth_uri: str = field(repr=False)


@dataclass(frozen=True)
class MfaConfirmation:
    """Two-step verification enabled. ``recovery_codes`` are shown ONCE: let the user save them. ``outcome`` is the
    sign-in outcome when the enrollment was part of a sign-in (``mfa_token`` given), else ``None``."""

    recovery_codes: List[str] = field(repr=False)
    outcome: Optional[Outcome] = None


# --- organizations (B2B) -----------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Organization:
    id: str
    name: Optional[str] = None
    roles: List[str] = field(default_factory=list)
    disabled: bool = False

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Organization":
        return cls(id=str(data.get("id") or ""), name=data.get("name"), roles=_list(data.get("roles")),
                   disabled=bool(data.get("disabled")))


@dataclass(frozen=True)
class OrganizationList:
    """The user's organizations and the active one's id (B2C pools: empty list)."""

    orgs: List[Organization] = field(default_factory=list)
    active: Optional[str] = None


@dataclass(frozen=True)
class OrgRole:
    key: str
    label: str = ""


@dataclass(frozen=True)
class Member:
    user_id: str
    email: Optional[str] = None
    display_name: Optional[str] = None
    disabled: bool = False
    roles: List[str] = field(default_factory=list)
    created_at: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Member":
        return cls(user_id=str(data.get("user_id") or ""), email=data.get("email"), display_name=data.get("display_name"),
                   disabled=bool(data.get("disabled")), roles=_list(data.get("roles")), created_at=_iso(data.get("created_at")))


@dataclass(frozen=True)
class MemberPage:
    items: List[Member] = field(default_factory=list)
    total: Optional[int] = None
    roles: List[OrgRole] = field(default_factory=list)


@dataclass(frozen=True)
class AddedMember:
    """A member added by an organization admin. ``temporary_password`` is set when a new account was created without a
    password: hand it over once; the user must change it at the first sign-in."""

    user_id: str
    email: Optional[str] = None
    roles: List[str] = field(default_factory=list)
    created: bool = False
    temporary_password: Optional[str] = field(default=None, repr=False)


# --- OpenID Connect ----------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class AuthorizationRequest:
    """A sign-in through the hosted page in progress: send the browser to ``url``; keep the rest (the "transaction")
    for the callback. ``to_dict()`` / ``from_dict()`` store it in a server-side session."""

    url: str
    state: str = field(repr=False)
    nonce: str = field(repr=False)
    code_verifier: str = field(repr=False)
    redirect_uri: str = ""
    scope: str = "openid profile email"
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {"url": self.url, "state": self.state, "nonce": self.nonce, "code_verifier": self.code_verifier,
                "redirect_uri": self.redirect_uri, "scope": self.scope, "created_at": self.created_at}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AuthorizationRequest":
        return cls(url=str(data.get("url") or ""), state=str(data.get("state") or ""), nonce=str(data.get("nonce") or ""),
                   code_verifier=str(data.get("code_verifier") or ""), redirect_uri=str(data.get("redirect_uri") or ""),
                   scope=str(data.get("scope") or "openid profile email"),
                   created_at=float(data.get("created_at") or time.time()))


@dataclass(frozen=True)
class TokenSet:
    """An answer of the token endpoint (``OidcWebClient``)."""

    access_token: str = field(repr=False)
    token_type: str = "Bearer"
    expires_in: int = 0
    #: Epoch seconds when the access token expires (computed locally).
    expires_at: float = 0.0
    scope: str = ""
    refresh_token: Optional[str] = field(default=None, repr=False)
    refresh_expires_in: Optional[int] = None
    id_token: Optional[str] = field(default=None, repr=False)
    #: The VERIFIED claims of the ID token (``None`` on a refresh: no ID token then).
    id_token_claims: Optional[Dict[str, Any]] = None
    org: Optional[ActiveOrg] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_response(cls, data: Mapping[str, Any], id_token_claims: Optional[Dict[str, Any]] = None) -> "TokenSet":
        expires_in = int(data.get("expires_in") or 0)
        org = data.get("org")
        return cls(access_token=str(data.get("access_token") or ""), token_type=str(data.get("token_type") or "Bearer"),
                   expires_in=expires_in, expires_at=time.time() + expires_in, scope=str(data.get("scope") or ""),
                   refresh_token=data.get("refresh_token"),
                   refresh_expires_in=int(data["refresh_expires_in"]) if data.get("refresh_expires_in") is not None else None,
                   id_token=data.get("id_token"), id_token_claims=id_token_claims,
                   org=ActiveOrg.from_dict(org) if isinstance(org, Mapping) else None, raw=dict(data))

    def to_dict(self) -> Dict[str, Any]:
        """JSON-friendly form, e.g. for a server-side session. It holds secrets: never put it in a cookie unencrypted."""
        return {"access_token": self.access_token, "token_type": self.token_type, "expires_in": self.expires_in,
                "expires_at": self.expires_at, "scope": self.scope, "refresh_token": self.refresh_token,
                "refresh_expires_in": self.refresh_expires_in, "id_token": self.id_token,
                "id_token_claims": self.id_token_claims, "org": self.org.raw if self.org else None}


# --- server-side verification ------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class AppUser:
    """The user behind a verified access token."""

    id: str
    pool_id: Optional[str]
    client_id: Optional[str]
    email: Optional[str] = None
    email_verified: bool = False
    anonymous: bool = False
    org_id: Optional[str] = None
    roles: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)
    session_id: Optional[str] = None
    amr: List[str] = field(default_factory=list)
    scope: str = ""
    claims: Dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    def has_role(self, role: str) -> bool:
        return role in self.roles

    def has_any_role(self, *roles: str) -> bool:
        return any(r in self.roles for r in roles)

    def has_permission(self, permission: str) -> bool:
        """True when the token grants ``permission`` (or ``"*"``, every permission)."""
        return "*" in self.permissions or permission in self.permissions

    @classmethod
    def from_claims(cls, claims: Mapping[str, Any]) -> "AppUser":
        aud = claims.get("aud")
        client_id = aud if isinstance(aud, str) else (claims.get("azp") or (aud[0] if isinstance(aud, list) and aud else None))
        return cls(id=str(claims.get("sub") or ""), pool_id=claims.get("pool"), client_id=client_id,
                   email=claims.get("email"), email_verified=bool(claims.get("email_verified")),
                   anonymous=bool(claims.get("anon")), org_id=claims.get("org_id"), roles=_list(claims.get("roles")),
                   permissions=_list(claims.get("permissions")), attributes=_dict(claims.get("attr")),
                   session_id=claims.get("sid"), amr=_list(claims.get("amr")), scope=str(claims.get("scope") or ""),
                   claims=dict(claims))
