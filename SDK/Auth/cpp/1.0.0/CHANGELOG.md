# Changelog

## 1.0.0 — 2026-10-20

First release.

- `Client`: the pool's JSON API (sign-up, password / email code / anonymous sign-in, MFA enroll / verify / disable,
  password reset and forced change, email verification and change, profile, account deletion, guest upgrade,
  organizations and members), typed `Outcome`s, `AppAuthError`, session in a pluggable `TokenStorage`
  (in memory by default), listeners, single-flight refresh with rotation, `authorized_request`.
- Hosted sign-in (OpenID Connect, code + PKCE S256): `build_authorization_request`, `handle_redirect_callback`
  (state, iss, nonce checks), `build_logout_url`, `sign_out_redirect`.
- `TokenVerifier` + `AppUser`: ES256-only verification with OpenSSL (3.x EVP API, 1.1.1 fallback), JWKS cache with
  rate-limited refetch on an unknown `kid`, typ / iss / aud / exp / nbf / iat checks with leeway.
- `BearerGuard`: framework-independent middleware decision (401 / 403 / 503 answers per the OpenBack convention).
- `OidcWebClient` for confidential web apps: authorization URL, callback with verified ID token, refresh, revoke,
  userinfo, logout URL; `client_secret_basic` (default) or `client_secret_post`.
- `HttpTransport` interface with a libcurl implementation (optional at build time).
- CMake package `openback-app-auth-cpp` (target `openback::app_auth`), `vcpkg.json`, `conanfile.py`, Catch2 tests,
  examples.
