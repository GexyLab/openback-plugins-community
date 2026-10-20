"""Errors raised by the SDK."""
from __future__ import annotations

from typing import Any, Mapping, Optional

__all__ = ["AppAuthError", "TokenVerificationError", "JwksUnavailableError", "error_from_response"]


class AppAuthError(Exception):
    """An error answered by the user pool, or met by the SDK.

    Attributes:
        status: the HTTP status (``0`` for a network error that never got an answer).
        code: a stable machine code, e.g. ``invalid_credentials``, ``token_expired``, ``invalid_grant``; ``http_<status>``
            when the service gave none.
        message: a human readable message (may be bilingual Italian / English, as the service sends it).
        detail: the raw ``detail`` of the answer (e.g. ``{"code": "weak_password", "problems": [...]}``), or ``None``.
    """

    def __init__(self, status: int, code: str, message: str = "", detail: Any = None) -> None:
        super().__init__(message or code or f"HTTP {status}")
        self.status = status
        self.code = code
        self.message = message or code or f"HTTP {status}"
        self.detail = detail

    def __repr__(self) -> str:
        return f"{type(self).__name__}(status={self.status!r}, code={self.code!r}, message={self.message!r})"

    @property
    def session_ended(self) -> bool:
        """True when the error means the local session is dead (the SDK already cleared it)."""
        return (self.status == 401 and self.code.startswith("token_")) or self.code == "invalid_refresh_token"


class TokenVerificationError(AppAuthError):
    """A token refused by :class:`~openback_app_auth.TokenVerifier` (status 401; code ``token_invalid``,
    ``token_expired`` or ``token_missing``)."""

    def __init__(self, code: str = "token_invalid", message: str = "Invalid token") -> None:
        super().__init__(401, code, message)


class JwksUnavailableError(AppAuthError):
    """The pool's public keys could not be fetched and none are cached (status 503)."""

    def __init__(self, message: str = "The pool's public keys are not reachable") -> None:
        super().__init__(503, "jwks_unavailable", message)


def error_from_response(status: int, data: Any, reason: str = "") -> AppAuthError:
    """Map an error answer to an :class:`AppAuthError`.

    Handles the JSON API shape ``{"detail": {"code", "message"}}``, ``{"detail": "text"}``, FastAPI validation lists
    ``{"detail": [{"msg": ...}]}`` and the OAuth shape ``{"error", "error_description"}``.
    """
    code: Optional[str] = None
    message: Optional[str] = None
    detail: Any = None
    if isinstance(data, Mapping):
        if "detail" in data:
            detail = data.get("detail")
            if isinstance(detail, Mapping):
                code = _str(detail.get("code"))
                message = _str(detail.get("message"))
            elif isinstance(detail, str):
                message = detail
            elif isinstance(detail, list):
                parts = [str(item.get("msg")) for item in detail if isinstance(item, Mapping) and item.get("msg")]
                message = "; ".join(parts) or None
                code = "validation_error" if status == 422 else None
        elif "error" in data:
            code = _str(data.get("error"))
            message = _str(data.get("error_description")) or code
            detail = dict(data)
    return AppAuthError(status, code or f"http_{status}", message or reason or f"HTTP {status}", detail)


def _str(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value else None
