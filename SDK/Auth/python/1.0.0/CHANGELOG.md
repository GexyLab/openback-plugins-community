# Changelog

All notable changes to `openback-app-auth-python` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the package uses [Semantic Versioning](https://semver.org/).

## 1.0.0 — 2026-10-20

First release.

- `Client` (sync, `httpx.Client`) and `AsyncClient` (`httpx.AsyncClient`): the whole JSON API of a user pool —
  sign-up, password, email code, guests, two-step verification (verify, enroll, confirm, disable), password reset and
  forced change, email verification and change, profile, account deletion, sign-out, organizations and members.
- Typed sign-in outcomes (`SignedIn`, `VerificationRequired`, `MfaRequired`, `MfaEnrollRequired`,
  `PasswordChangeRequired`, `OtherOutcome`) and `AppAuthError(status, code, message, detail)`.
- Session storage protocol with `MemoryStorage` (default) and `FileStorage` (0600, atomic writes); the stored JSON is
  shared with the other OpenBack App Auth SDKs.
- Single-flight refresh (`threading.RLock` / `asyncio.Lock`), refresh-token rotation stored atomically, no automatic
  retry after a network error, session cleared on `token_*` 401 and `invalid_refresh_token`.
- `on_auth_state_changed` listeners, `httpx.Auth` bearer helper and `request()` for calling your own API.
- Hosted page (OpenID Connect, code + PKCE S256): `build_authorization_request`, `handle_redirect_callback` (state in
  constant time, RFC 9207 `iss`, ID-token nonce), `build_logout_url`; optional loopback helper for desktop/CLI apps
  (`openback_app_auth.loopback`).
- `TokenVerifier` + `AppUser`: local ES256-only verification with a cached JWKS, rate-limited refetch on unknown `kid`,
  sync and async.
- `OidcWebClient` / `AsyncOidcWebClient` for `web` apps: authorization URL + transaction, callback with verified ID
  token, refresh, revoke, userinfo, logout URL; `client_secret_basic` or `client_secret_post`.
- Integrations: FastAPI (`require_app_user` dependency), Flask (`require_app_user` decorator, `g.app_user`), Django
  (`AppAuthMiddleware` + `require_app_user`).
