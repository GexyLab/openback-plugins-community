# Changelog

## 1.0.0 — 2026-10-20

First release of `openback-app-auth-javascript` (successor of the monorepo's `@openback/auth` 0.1.0, same API names).

- JSON API client: sign-up, password, email code, guest, two-step verification (verify, enroll, confirm, disable),
  password reset and forced change, email verification and change, profile, guest upgrade, account deletion,
  sign-out (also everywhere), B2B organizations and members.
- Session in `localStorage` (memory fallback, pluggable sync or async storage) as one JSON under
  `openback.auth.<clientId>`; `onAuthStateChanged` notified on user/organization/sign-in changes, also across tabs.
- Access token renewed 60 s before expiry; single-flight refresh and organization switch (queue + Web Locks), rotated
  refresh token stored at once, no automatic retry after network errors.
- `invalid_refresh_token` and `token_*` 401s clear the session and notify the listeners.
- OpenID Connect: `buildAuthorizationRequest` (PKCE S256, state, nonce, OpenBack extras), `signInWithRedirect`,
  `handleRedirectCallback` (constant-time state, `iss` check, ID token `iss`/`aud`/`nonce` check; returns `null` on a
  non-callback URL), `buildLogoutUrl`, `signOutRedirect`.
- `isSignedIn`, `createClient(issuer, clientId, options)`, `memoryStorage()`, typed `AuthError` (`network_error`).
- Pre-built `dist/` bundles: ESM, UMD (global `OpenBackAppAuth`), light-minified UMD; zero-dependency build script.
