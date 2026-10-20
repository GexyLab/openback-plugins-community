"""Django integration (``pip install "openback-app-auth-python[django]"``).

settings.py::

    OPENBACK_APP_AUTH = {
        "issuer": "https://api.example.com/gateway/shop/auth/main",
        "audience": ["uapp_..."],          # client IDs whose tokens are accepted
        # optional: "leeway": 60, "cache_ttl": 600, "jwks_uri": "..."
    }
    MIDDLEWARE = [..., "openback_app_auth.django.AppAuthMiddleware"]

views.py::

    from openback_app_auth.django import require_app_user

    @require_app_user(require_roles=["admin"])
    def orders(request):
        return JsonResponse({"user": request.app_user.id})

The middleware sets ``request.app_user`` (an :class:`AppUser`, or ``None`` without a valid token) and never refuses a
request by itself; the decorator refuses: 401 ``{"error": "invalid_token"}`` with ``WWW-Authenticate: Bearer
error="invalid_token"``, 403 ``{"error": "insufficient_scope"}``. The decorator also works without the middleware.
``OPENBACK_APP_AUTH`` may also be a ready :class:`TokenVerifier`.
"""
from __future__ import annotations

import functools
import threading
from typing import Any, Callable, Iterable, Optional

try:
    from django.conf import settings
    from django.core.exceptions import ImproperlyConfigured
    from django.http import JsonResponse
except ImportError as exc:  # pragma: no cover
    raise ImportError('openback_app_auth.django needs Django: pip install "openback-app-auth-python[django]"') from exc

from ._guard import GuardFailure, GuardOptions, authenticate, bearer_token, check_user
from .errors import JwksUnavailableError, TokenVerificationError
from .verifier import TokenVerifier

__all__ = ["AppAuthMiddleware", "require_app_user", "get_verifier", "reset_verifier"]

_verifier: Optional[TokenVerifier] = None
_lock = threading.Lock()
_UNSET = object()


def get_verifier() -> TokenVerifier:
    """The :class:`TokenVerifier` built once from ``settings.OPENBACK_APP_AUTH``."""
    global _verifier
    if _verifier is None:
        with _lock:
            if _verifier is None:
                conf = getattr(settings, "OPENBACK_APP_AUTH", None)
                if isinstance(conf, TokenVerifier):
                    _verifier = conf
                elif isinstance(conf, dict) and conf.get("issuer") and conf.get("audience"):
                    kwargs = {k: v for k, v in conf.items() if k not in ("issuer", "audience")}
                    _verifier = TokenVerifier(conf["issuer"], conf["audience"], **kwargs)
                else:
                    raise ImproperlyConfigured("settings.OPENBACK_APP_AUTH needs 'issuer' and 'audience'")
    return _verifier


def reset_verifier() -> None:
    """Forget the cached verifier (tests, settings changes)."""
    global _verifier
    with _lock:
        _verifier = None


def _refusal(failure: GuardFailure) -> JsonResponse:
    response = JsonResponse(failure.body, status=failure.status)
    for key, value in failure.headers.items():
        response[key] = value
    return response


class AppAuthMiddleware:
    """Sets ``request.app_user`` from a valid ``Authorization: Bearer`` token (``None`` otherwise)."""

    sync_capable = True
    async_capable = False

    def __init__(self, get_response: Callable[[Any], Any]) -> None:
        self.get_response = get_response

    def __call__(self, request: Any) -> Any:
        request.app_user = None
        request.app_user_error = None
        header = request.headers.get("Authorization")
        if header:
            token = bearer_token(header)
            try:
                if token is None:
                    raise TokenVerificationError("token_invalid", "Malformed Authorization header")
                request.app_user = get_verifier().verify(token)
            except JwksUnavailableError:
                request.app_user_error = GuardFailure(503, "temporarily_unavailable")
            except TokenVerificationError as exc:
                request.app_user_error = GuardFailure(401, "invalid_token", exc.message)
        return self.get_response(request)


def require_app_user(view: Optional[Callable[..., Any]] = None, *, require_roles: Optional[Iterable[str]] = None,
                     require_permissions: Optional[Iterable[str]] = None, require_verified_email: bool = False,
                     allow_anonymous: bool = False, verifier: Optional[TokenVerifier] = None) -> Any:
    """View decorator, usable bare (``@require_app_user``) or with options (``@require_app_user(require_roles=[...])``).
    Uses ``request.app_user`` when :class:`AppAuthMiddleware` ran, else verifies the token itself."""
    options = GuardOptions.of(require_roles, require_permissions, require_verified_email, allow_anonymous)

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(request: Any, *args: Any, **kwargs: Any) -> Any:
            try:
                user = getattr(request, "app_user", _UNSET)
                if user is _UNSET or verifier is not None:
                    user = authenticate(verifier or get_verifier(), request.headers.get("Authorization"), options)
                    request.app_user = user
                elif user is None:
                    raise getattr(request, "app_user_error", None) or GuardFailure(401, "invalid_token", "Missing bearer token")
                else:
                    check_user(user, options)
            except GuardFailure as failure:
                return _refusal(failure)
            return func(request, *args, **kwargs)
        return wrapper

    if view is not None and callable(view):
        return decorator(view)
    return decorator
