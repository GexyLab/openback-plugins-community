"""Framework-neutral request guard used by the FastAPI, Flask and Django integrations."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Optional, Tuple

from .errors import JwksUnavailableError, TokenVerificationError
from .models import AppUser
from .verifier import TokenVerifier

__all__ = ["GuardOptions", "GuardFailure", "bearer_token", "check_user", "authenticate", "authenticate_async"]


@dataclass(frozen=True)
class GuardOptions:
    """What a protected route requires beyond a valid token.

    ``require_roles``: at least ONE of these roles; ``require_permissions``: ALL of these permissions (``"*"`` grants
    all); ``require_verified_email``; ``allow_anonymous`` (guest tokens, ``anon: true``, are refused by default).
    The same rules as the OpenBack gateway's "Authenticated app user" check.
    """

    require_roles: Tuple[str, ...] = ()
    require_permissions: Tuple[str, ...] = ()
    require_verified_email: bool = False
    allow_anonymous: bool = False

    @classmethod
    def of(cls, require_roles: Optional[Iterable[str]] = None, require_permissions: Optional[Iterable[str]] = None,
           require_verified_email: bool = False, allow_anonymous: bool = False) -> "GuardOptions":
        return cls(tuple(r for r in (require_roles or ()) if r), tuple(p for p in (require_permissions or ()) if p),
                   bool(require_verified_email), bool(allow_anonymous))


class GuardFailure(Exception):
    """A refused request: ``status`` 401 (``invalid_token``), 403 (``insufficient_scope``) or 503."""

    def __init__(self, status: int, error: str, description: str = "") -> None:
        super().__init__(description or error)
        self.status = status
        self.error = error
        self.description = description

    @property
    def body(self) -> Dict[str, str]:
        return {"error": self.error}

    @property
    def headers(self) -> Dict[str, str]:
        if self.status in (401, 403):
            return {"WWW-Authenticate": f'Bearer error="{self.error}"', "Cache-Control": "no-store"}
        return {"Retry-After": "30", "Cache-Control": "no-store"}


def bearer_token(header: Optional[str]) -> Optional[str]:
    """The token of an ``Authorization: Bearer <token>`` header (scheme case-insensitive), or ``None``."""
    if not header:
        return None
    scheme, _, value = header.strip().partition(" ")
    value = value.strip()
    if scheme.lower() != "bearer" or not value or " " in value:
        return None
    return value


def check_user(user: AppUser, options: GuardOptions) -> None:
    """Raise :class:`GuardFailure` 403 when the user does not meet ``options``."""
    if user.anonymous and not options.allow_anonymous:
        raise GuardFailure(403, "insufficient_scope", "Guest accounts are not allowed")
    if options.require_verified_email and not user.email_verified:
        raise GuardFailure(403, "insufficient_scope", "Email not verified")
    if options.require_roles and not any(r in user.roles for r in options.require_roles):
        raise GuardFailure(403, "insufficient_scope", "Missing role")
    if any(not user.has_permission(p) for p in options.require_permissions):
        raise GuardFailure(403, "insufficient_scope", "Missing permission")


def authenticate(verifier: TokenVerifier, authorization: Optional[str], options: GuardOptions) -> AppUser:
    token = bearer_token(authorization)
    if token is None:
        raise GuardFailure(401, "invalid_token", "Missing bearer token")
    try:
        user = verifier.verify(token)
    except JwksUnavailableError:
        raise GuardFailure(503, "temporarily_unavailable", "Token keys unavailable") from None
    except TokenVerificationError as exc:
        raise GuardFailure(401, "invalid_token", exc.message) from None
    check_user(user, options)
    return user


async def authenticate_async(verifier: TokenVerifier, authorization: Optional[str], options: GuardOptions) -> AppUser:
    token = bearer_token(authorization)
    if token is None:
        raise GuardFailure(401, "invalid_token", "Missing bearer token")
    try:
        user = await verifier.verify_async(token)
    except JwksUnavailableError:
        raise GuardFailure(503, "temporarily_unavailable", "Token keys unavailable") from None
    except TokenVerificationError as exc:
        raise GuardFailure(401, "invalid_token", exc.message) from None
    check_user(user, options)
    return user
