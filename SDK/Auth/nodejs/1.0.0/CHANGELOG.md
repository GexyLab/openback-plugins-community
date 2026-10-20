# Changelog

## 1.0.0 — 2026-10-20

First release of `openback-app-auth-nodejs`.

- `TokenVerifier` + `AppUser`: local verification of access tokens (ES256 only, `typ` at+jwt, exact `iss`, `aud` among
  the configured client IDs, `exp`/`nbf`/`iat` with leeway), JWKS cached 10 minutes, unknown `kid` refetch at most
  every 30 s, cached keys kept while the pool is unreachable; `verifyIdToken` (typ JWT, nonce, azp, at_hash).
- Guards: `requireAppUser` (Express/Connect), `requireAppUserHttp` (`node:http`), `fastifyRequireAppUser` and the
  `fastifyAppUser` plugin; options `requireRoles`, `requirePermissions`, `requireVerifiedEmail`, `allowAnonymous`;
  401 `invalid_token` / 403 `insufficient_scope` / 503 `temporarily_unavailable`.
- `OidcWebClient` for confidential web apps: authorization URL with PKCE S256, callback checks (state in constant time,
  `iss`, verified ID token), `client_secret_basic` (default) / `client_secret_post`, `refresh`, `revoke`, `userinfo`,
  `logoutUrl`.
- `createAuth` / `createClient`: the pool's client with the browser SDK's API, in-memory storage by default (pluggable,
  sync or async), single-flight refresh, session cleared on `invalid_refresh_token` and `token_*` 401s.
