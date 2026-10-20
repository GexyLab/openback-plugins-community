"""Flask integration (``pip install "openback-app-auth-python[flask]"``).

    from flask import Flask, g
    from openback_app_auth import TokenVerifier
    from openback_app_auth.flask import require_app_user

    verifier = TokenVerifier(ISSUER, "uapp_...")
    app = Flask(__name__)

    @app.get("/orders")
    @require_app_user(verifier, require_permissions=["orders.read"])
    def orders():
        return {"user": g.app_user.id}

Missing or invalid token: 401 ``{"error": "invalid_token"}`` + ``WWW-Authenticate: Bearer error="invalid_token"``;
options not met: 403 ``{"error": "insufficient_scope"}``. The verified :class:`AppUser` is in ``g.app_user``.
"""
from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, Iterable, Optional, TypeVar

try:
    from flask import g, jsonify, make_response, request
except ImportError as exc:  # pragma: no cover
    raise ImportError('openback_app_auth.flask needs Flask: pip install "openback-app-auth-python[flask]"') from exc

from ._guard import GuardFailure, GuardOptions, authenticate
from .models import AppUser
from .verifier import TokenVerifier

__all__ = ["require_app_user", "current_app_user", "refusal_response"]

F = TypeVar("F", bound=Callable[..., Any])


def refusal_response(failure: GuardFailure) -> Any:
    response = make_response(jsonify(failure.body), failure.status)
    for key, value in failure.headers.items():
        response.headers[key] = value
    return response


def require_app_user(verifier: TokenVerifier, *, require_roles: Optional[Iterable[str]] = None,
                     require_permissions: Optional[Iterable[str]] = None, require_verified_email: bool = False,
                     allow_anonymous: bool = False) -> Callable[[F], F]:
    """Decorator: verify the bearer token, put the :class:`AppUser` in ``g.app_user``, else answer 401/403."""
    options = GuardOptions.of(require_roles, require_permissions, require_verified_email, allow_anonymous)

    def decorator(view: F) -> F:
        if inspect.iscoroutinefunction(view):  # Flask[async] views
            @functools.wraps(view)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                try:
                    g.app_user = authenticate(verifier, request.headers.get("Authorization"), options)
                except GuardFailure as failure:
                    return refusal_response(failure)
                return await view(*args, **kwargs)
            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(view)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                g.app_user = authenticate(verifier, request.headers.get("Authorization"), options)
            except GuardFailure as failure:
                return refusal_response(failure)
            return view(*args, **kwargs)
        return wrapper  # type: ignore[return-value]

    return decorator


def current_app_user() -> Optional[AppUser]:
    """The :class:`AppUser` of the current request (set by :func:`require_app_user`), or ``None``."""
    return g.get("app_user")
