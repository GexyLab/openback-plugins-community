# Changelog

## 1.0.0 — 2026-10-20

First release.

- Package `pkg_openbackappauth` for Joomla 4.2+ and 5.x: library, system plugin, authentication plugin, API
  authentication plugin, site module.
- Sign-in with an OpenBack user pool through its hosted page (OpenID Connect authorization code + PKCE S256), state,
  nonce and verifier kept in the server-side session, ID token verified locally (ES256).
- Account linking in `#__user_profiles` (`openback.sub`, `openback.iss`, `openback.pool`), account creation, linking by
  verified email (off by default, never Super Users), "Link my OpenBack account" for signed-in users.
- Group mapping OpenBack role → Joomla groups, default group, optional synchronization at every sign-in.
- Single logout through the pool's end-session endpoint.
- Optional Web Services API authentication with the pool's access tokens (plugin disabled by default).
- Languages en-GB and it-IT. Bundles openback-app-auth-php 1.0.0 (MIT) with a prefixed namespace
  (`OpenBackAppAuthJoomla\Sdk`).
