# Changelog

## 1.0.0 — 2026-10-20

First release.

- Sign-in with an OpenBack user pool through its hosted page (OpenID Connect authorization code + PKCE S256), state,
  nonce and verifier kept server-side (transient keyed by an HttpOnly cookie), ID token verified locally (ES256).
- "Sign in with ..." button on wp-login.php, shortcode `[openback_app_auth_login]`, block
  `openback-app-auth/login-button`; optional hiding of the password form.
- Account linking by user meta (`openback_app_auth_sub` + issuer + pool id), account creation, linking by verified
  email (off by default, never administrators), "Link my OpenBack account" on the profile.
- Role mapping OpenBack role → WordPress role, default role, optional update at every sign-in.
- Single logout through the pool's end-session endpoint.
- Optional REST API authentication with the pool's access tokens (`Authorization: Bearer`), off by default.
- Bundles openback-app-auth-php 1.0.0 (MIT) with a prefixed namespace (`OpenBackAppAuthWp\Sdk`).
