"""FastAPI / Starlette integration (``pip install "openback-app-auth-python[fastapi]"``).

    from fastapi import Depends, FastAPI
    from openback_app_auth import AppUser, TokenVerifier
    from openback_app_auth.fastapi import install_error_handler, require_app_user

    verifier = TokenVerifier(ISSUER, "uapp_...")
    app = FastAPI()
    install_error_handler(app)            # optional: bodies exactly {"error": "..."}

    @app.get("/orders")
    async def orders(user: AppUser = Depends(require_app_user(verifier, require_roles=["admin"]))):
        return {"user": user.id}

Missing or invalid token: 401 + ``WWW-Authenticate: Bearer error="invalid_token"``; options not met: 403 +
``Bearer error="insufficient_scope"``. Without :func:`install_error_handler` FastAPI's default handler answers
``{"detail": {"error": "..."}}`` with the same status and headers.
"""
from typing import Any, Awaitable, Callable, Iterable, Optional

try:
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import JSONResponse
except ImportError as exc:  # pragma: no cover
    raise ImportError('openback_app_auth.fastapi needs FastAPI: pip install "openback-app-auth-python[fastapi]"') from exc

from ._guard import GuardFailure, GuardOptions, authenticate_async
from .models import AppUser
from .verifier import TokenVerifier

__all__ = ["require_app_user", "optional_app_user", "install_error_handler", "AppAuthHTTPException"]


class AppAuthHTTPException(HTTPException):
    """A refusal of :func:`require_app_user` (an ``HTTPException``: FastAPI's default handler works too)."""

    def __init__(self, failure: GuardFailure) -> None:
        super().__init__(status_code=failure.status, detail=failure.body, headers=failure.headers)
        self.error = failure.error


def require_app_user(verifier: TokenVerifier, *, require_roles: Optional[Iterable[str]] = None,
                     require_permissions: Optional[Iterable[str]] = None, require_verified_email: bool = False,
                     allow_anonymous: bool = False) -> Callable[[Request], Awaitable[AppUser]]:
    """A dependency returning the verified :class:`AppUser` (also put in ``request.state.app_user``)."""
    options = GuardOptions.of(require_roles, require_permissions, require_verified_email, allow_anonymous)

    async def app_user(request: Request) -> AppUser:
        try:
            user = await authenticate_async(verifier, request.headers.get("authorization"), options)
        except GuardFailure as failure:
            raise AppAuthHTTPException(failure) from None
        request.state.app_user = user
        return user

    return app_user


def optional_app_user(verifier: TokenVerifier, **options: Any) -> Callable[[Request], Awaitable[Optional[AppUser]]]:
    """Like :func:`require_app_user`, but ``None`` when the request carries no ``Authorization`` header (an invalid
    token is still refused with 401)."""
    required = require_app_user(verifier, **options)

    async def maybe_app_user(request: Request) -> Optional[AppUser]:
        if not request.headers.get("authorization"):
            request.state.app_user = None
            return None
        return await required(request)

    return maybe_app_user


def install_error_handler(app: FastAPI) -> None:
    """Answer the refusals with exactly ``{"error": "invalid_token" | "insufficient_scope" | ...}``."""

    async def handler(request: Request, exc: Exception) -> JSONResponse:
        assert isinstance(exc, AppAuthHTTPException)
        return JSONResponse({"error": exc.error}, status_code=exc.status_code, headers=exc.headers)

    app.add_exception_handler(AppAuthHTTPException, handler)
