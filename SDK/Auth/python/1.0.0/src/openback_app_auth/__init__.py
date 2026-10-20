"""openback-app-auth-python: the Python SDK of OpenBack's App authenticator (users-service user pools).

- :class:`Client` / :class:`AsyncClient` -- sign users in from apps (CLI, desktop, scripts, servers acting for a user):
  sign-up, password, email code, guests, two-step verification, hosted page (OIDC + PKCE), profile, organizations.
- :class:`TokenVerifier` -> :class:`AppUser` -- verify the pool's access tokens in your API, locally (JWKS, ES256).
- :class:`OidcWebClient` / :class:`AsyncOidcWebClient` -- hosted-page sign-in for ``web`` apps with a client secret.
- Framework integrations (imported on demand): ``openback_app_auth.fastapi``, ``openback_app_auth.flask``,
  ``openback_app_auth.django``; desktop/CLI browser sign-in: ``openback_app_auth.loopback``.
"""
from ._util import decode_jwt
from .async_client import AsyncClient
from .client import Client
from .errors import AppAuthError, JwksUnavailableError, TokenVerificationError
from .models import (ActiveOrg, AddedMember, AppUser, AuthorizationRequest, Member, MemberPage, MfaConfirmation,
                     MfaEnrollment, MfaEnrollRequired, MfaRequired, Organization, OrganizationList, OrgRole,
                     OtherOutcome, Outcome, PasswordChangeRequired, PoolUser, SignedIn, TokenSet, VerificationRequired,
                     parse_outcome)
from .oidc_web import AsyncOidcWebClient, OidcWebClient
from .storage import FileStorage, MemoryStorage, Storage
from .verifier import TokenVerifier

__version__ = "1.0.0"

__all__ = [
    "__version__",
    # clients
    "Client", "AsyncClient", "OidcWebClient", "AsyncOidcWebClient", "TokenVerifier",
    # storage
    "Storage", "MemoryStorage", "FileStorage",
    # errors
    "AppAuthError", "TokenVerificationError", "JwksUnavailableError",
    # results
    "PoolUser", "ActiveOrg", "Outcome", "SignedIn", "VerificationRequired", "MfaRequired", "MfaEnrollRequired",
    "PasswordChangeRequired", "OtherOutcome", "parse_outcome", "MfaEnrollment", "MfaConfirmation", "Organization",
    "OrganizationList", "OrgRole", "Member", "MemberPage", "AddedMember", "AuthorizationRequest", "TokenSet", "AppUser",
    # helpers
    "decode_jwt",
]
