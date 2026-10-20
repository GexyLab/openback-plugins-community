# Changelog

## 1.0.0 — 2026-10-20

First release.

- Setup guide: an OpenBack user pool as the third-party identity provider (OIDC) of a Shopify Plus store's new
  customer accounts.
- `checkPool()`: pass/warn/fail report of a pool against Shopify's requirements (discovery, JWKS, optional pool
  settings with a client ID).
- `ssoLoginUrl()`: Shopify single sign-on links (`/customer_authentication/login?login_hint=&return_to=`) with shop
  domain and relative return-path validation.
- CLI `openback-app-auth-shopify` (`check`, `sso-url`).
- Example external site signing in on the pool's hosted page and linking customers to the store.
