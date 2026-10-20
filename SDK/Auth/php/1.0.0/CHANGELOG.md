# Changelog

## 1.0.0 — 2026-10-20

First release.

- `TokenVerifier` + `AppUser`: local verification of the pool's access tokens and ID tokens (ES256 only, with
  ext-openssl and no JWT library; `typ`, `iss`, `aud`, `exp`/`nbf`/`iat` with leeway), JWKS cache (PSR-16, APCu or
  in-process) with a rate-limited refetch on an unknown `kid`.
- `Middleware\RequireAppUser`: PSR-15 middleware (401 `invalid_token`, 403 `insufficient_scope`), options
  `requireRoles`, `requirePermissions`, `requireVerifiedEmail`, `allowAnonymous`.
- `OidcWebClient`: hosted sign-in for `web` apps (code + PKCE S256, state, nonce, `iss`, `at_hash` checks,
  `client_secret_basic` / `client_secret_post`), refresh, revocation, userinfo, end-session URL.
- `Client`: the pool's JSON API (sign-up, password, email code, guest, MFA, password reset, email verification,
  account, organizations and members) with a typed `Outcome`, session storage (`MemoryStorage`, `SessionStorage` or
  your own), single-flight refresh with an optional cross-process `RefreshLock`, hosted sign-in helpers.
- HTTP through any PSR-18 client or the built-in ext-curl transport.
