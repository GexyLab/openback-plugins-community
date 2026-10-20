# openback-app-auth-shopify

Use an OpenBack **user pool** (App authenticator) as the **third-party identity provider of a Shopify Plus store's new
customer accounts** — setup guide, a pool checker, single sign-on links from your other sites, and a CLI.

Version 1.0.0 · License MIT · Node.js >= 18, ESM, zero dependencies, TypeScript types included.

- [What it does](#what-it-does)
- [Requirements](#requirements)
- [Installation](#installation)
- [Setup, step by step](#setup-step-by-step)
- [Testing the connection](#testing-the-connection)
- [Single sign-on from an external site](#single-sign-on-from-an-external-site)
- [Logout behaviour](#logout-behaviour)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)
- [API reference](#api-reference)
- [Errors](#errors)
- [Security notes](#security-notes)
- [License](#license)

## What it does

Shopify Plus lets a store replace Shopify's own customer sign-in with an OpenID Connect identity provider. With this
setup the pool becomes that provider:

```
 customer ── "Sign in" on the store ──► Shopify ──► <issuer>/authorize (pool's hosted sign-in page)
                                           ◄── code ──┘
           Shopify ──► <issuer>/token (client_secret_post) ──► ID token (ES256): sub, email, email_verified=true
           Shopify finds or creates the customer by email + sub, and signs them in.
```

The package itself is a small helper library, not a Shopify app:

| | |
|---|---|
| `checkPool()` / `openback-app-auth-shopify check` | reads the pool's discovery document (and keys and settings) and tells you, check by check, whether Shopify can use it |
| `ssoLoginUrl()` / `openback-app-auth-shopify sso-url` | builds Shopify's SSO address so a customer signed in on **your other site** lands on the store already signed in |
| `examples/external-site/` | a runnable site (no dependencies) that signs people in on the pool's hosted page and links them to the store |

Everything else is configuration, described below. Nothing needs to be installed in Shopify.

## Requirements

- **Shopify Plus.** Connecting your own identity provider is available only to Plus stores.
- **New customer accounts** enabled on the store (Settings › Customer accounts). Classic accounts and Multipass are not
  involved.
- **A user pool reachable from the internet over https.** Shopify's servers call the discovery, JWKS and token
  endpoints, so the issuer must be the gateway's public address (set the Platform package's `gateway_public_url` /
  `GATEWAY_PUBLIC_URL`; with it empty the issuer becomes the address each client used and will not match). Shopify
  requires the token, discovery and userinfo endpoints to answer **within 1 second**.
- **Hosted sign-in on** (pool settings › Hosted login). Shopify signs customers in on the pool's hosted page; with it
  off, `/authorize` always answers `login_required` and nobody can sign in to the store.
- **Verified emails.** Shopify identifies the customer by `sub` + `email` and **blocks the sign-in unless
  `email_verified` is `true`** in the ID token. In the pool:
  - keep **Sign-up › Require email verification** on (the default). Then a new account can only sign in after
    confirming its email, so every customer who reaches Shopify has `email_verified: true`;
  - with verification off, people who sign up and have not verified their email are signed in by the pool but
    **refused by Shopify** ("email not verified" error page);
  - users created by an administrator or imported without a verified email, and accounts from a social provider that
    does not vouch for the email (e.g. some OAuth providers without a verified-email flag), are refused too until they
    verify (the app sends a new verification email with `POST /email/verify/send`, or an administrator marks the
    email verified on the user in the portal);
  - **guest (anonymous) accounts** have no email: they can never sign in to Shopify. They must be upgraded
    (`POST /me/upgrade`) and verified first. The hosted page never creates guests, so this only matters for accounts
    your apps created through the JSON API.
  - Signing in with an **email code** verifies the email automatically.
- For the helper library and CLI: **Node.js 18 or later**.

## Installation

The package is not published yet. Once published:

```sh
npm install openback-app-auth-shopify
npx openback-app-auth-shopify check https://api.example.com/gateway/shop/auth/main
```

From this repository (no install step, no dependencies):

```sh
node SDK/Auth/shopify/1.0.0/bin/openback-app-auth-shopify.mjs check https://api.example.com/gateway/shop/auth/main
# or, in your project:  npm install ./path/to/openback-plugins-community/SDK/Auth/shopify/1.0.0
```

## Setup, step by step

### 1. Check the pool

```sh
npx openback-app-auth-shopify check https://api.example.com/gateway/shop/auth/main --client-id uapp_...
```

It prints the **Discovery URL** to paste into Shopify and one line per check (`PASS` / `WARN` / `FAIL`): https and
public reachability, issuer match, response time, endpoints, authorization code grant, refresh tokens,
`client_secret_post`, `prompt=none`, `email` / `email_verified` claims, `openid` / `email` scopes, end-session endpoint,
PKCE, ID token algorithm, JWKS; with `--client-id` (any app of the pool; the ID is public) also hosted sign-in, email
verification, guests, B2B and required two-step verification. Exit code 1 when something fails. An OpenBack pool with
default settings passes, with two expected warnings: the ES256-only ID tokens (see [Limitations](#limitations)) and
nothing for Shopify's claim import.

### 2. Start the connection in Shopify and copy its URLs

In the Shopify admin: **Settings › Customer accounts › Identity provider › Manage › Connect to provider** (Shopify's
guides also call the section "Third-party identity provider"; the labels move from time to time).

1. Enter an **Identity provider name** (e.g. "OpenBack").
2. Keep the page open and copy, from **Setup configurations**:
   - the **Callback URL** — e.g. `https://account.your-store.com/authentication/login/external/callback`;
   - the **Logout URL(s)** — e.g. `https://account.your-store.com/logout_callback`.

   Copy the exact values Shopify shows; the examples above are only Shopify's documented shape for a custom
   customer-accounts domain.

### 3. Create a `web` app in the pool

In the OpenBack portal, open the pool › **Apps** › **New app**:

| Field | Value |
|---|---|
| Kind | **`web`** (a confidential app: it gets a client secret). Not `spa` or `native`. |
| Redirect URIs | Shopify's **Callback URL**, exactly as shown (scheme, host, path; no trailing `/` added) |
| Post-logout redirect URIs | Shopify's **Logout URL(s)** |
| Allowed origins | none needed (Shopify calls the token endpoint from its servers) |

Save and copy the **client ID** (`uapp_...`) and the **client secret** (`obus_sec_...`). The secret is shown **once**;
regenerate it if you lose it (and update Shopify).

If you later change the store's customer-accounts domain, add the new Callback and Logout URLs to the app **before**
changing the domain in Shopify, and remove the old ones only after sign-in and sign-out work on the new domain.

### 4. Fill Shopify's "Application info"

| Shopify field | Value |
|---|---|
| Discovery URL (well-known configuration) | `<issuer>/.well-known/openid-configuration`, e.g. `https://api.example.com/gateway/shop/auth/main/.well-known/openid-configuration` |
| Client ID | the app's `uapp_...` |
| Client secret | the app's `obus_sec_...` |
| Token endpoint authentication | **`client_secret_post`** if the form offers a choice. Shopify's provider guides (Okta) say `client_secret_basic` "isn't supported for this flow", while the Help Center calls basic the default; the pool's `web` app accepts **both**, so either works on the OpenBack side. |
| Additional scopes | **`offline_access`** (recommended; the pool issues refresh tokens anyway, and Shopify's guides ask for it). `profile` is harmless but brings nothing Shopify imports today. Do not bother with `phone` / `address`: the pool ignores them (see [Limitations](#limitations)). Shopify always requests `openid email` itself. |
| Post-logout redirect URI parameter name (if shown) | `post_logout_redirect_uri` |
| Sync customer data | optional; with today's pool there is nothing for it to import (no `given_name` / `family_name` / `phone_number` / `address` claims), so it only matters after future pool improvements |

### 5. Save, test, activate

Click **Save**, then **Test connection** (it opens the pool's sign-in page and must come back to Shopify), then
**Activate**. Customers who were signed in to the store must sign in again through the pool. If you were signed in to
your own customer account on the storefront recently, sign out and back in before testing.

To go back to Shopify's own sign-in: **Settings › Customer accounts › Identity provider › Manage**, choose
**Activate** for the default identity provider.

## Testing the connection

1. In the pool, create a test user and verify its email (or sign up on the hosted page and confirm the code).
2. On the storefront click **Sign in**: you land on the pool's hosted page (branding of the pool), sign in, and return
   to the store signed in.
3. In the Shopify admin › **Customers**, the customer exists with the pool user's email; the pool's `sub` (`usr_...`)
   appears as the provider subject ID on the profile. A customer that already existed with the same email is linked,
   not duplicated.
4. Sign in with an **unverified** user: Shopify must show its "email not verified" error (this proves the guard works).
5. Sign out of the store: you pass through the pool's `/logout` and come back to the store (see
   [Logout behaviour](#logout-behaviour)).
6. Optional: SSO from another site (next section) — with a hosted-page session the store opens signed in, without a
   password prompt.

The pool's **Logs** (stream `users.auth`, `users.security`) show each sign-in, refused token exchange and redirect
mismatch with the client ID.

## Single sign-on from an external site

Shopify's SSO entry point signs a customer in to the store and then opens a page of the store:

```
https://{shop}/customer_authentication/login?login_hint=<email>&return_to=<relative path>
```

Shopify forwards it to the pool as an authorization request with **`prompt=none`** and the same **`login_hint`**:

- **the browser has a pool session** → the pool answers at once, Shopify signs the customer in and opens `return_to`;
- **no pool session** → the pool answers `error=login_required`; Shopify then shows the pool's sign-in page and
  continues to `return_to` afterwards.

The pool session is the hosted page's cookie (`obu_session`, per pool, HttpOnly, SameSite=Lax, valid
`sso_session_days`, default 7). So silent SSO works only if your other site signs people in **through the pool's
hosted page** (any app of the same pool: the OIDC redirect flow, `signInWithRedirect` in the JS SDK). Sign-ins made
with your own forms through the JSON API (`signInWithPassword`, email codes...) leave no browser session: the link
still works, but the customer has to sign in again on the pool's page.

```js
import { ssoLoginUrl } from "openback-app-auth-shopify";

// The email of the signed-in user, from your VERIFIED ID token / session — never from a query parameter.
const url = ssoLoginUrl({ shopDomain: "my-store.myshopify.com", email: user.email, returnTo: "/cart" });
res.redirect(url);
```

```sh
openback-app-auth-shopify sso-url --shop my-store.myshopify.com --email jane@example.com --return-to /cart
```

`shopDomain` is the store's host (`my-store.myshopify.com` or its custom domain); `returnTo` must be a relative path on
the store (`/`, `/products/<handle>`, `/cart`, `/cart/<variant id>:<quantity>`, `/checkout`): it must start with `/`,
not `//`, with no scheme, backslash, whitespace or control character — anything else throws.

Note: with a pool session, the pool signs in **the session's user** and does not compare it with `login_hint` (it only
pre-fills the email on the sign-in page). Build the link only for the user signed in on your site through the same
pool, so both are the same person.

**Runnable example**: [`examples/external-site/server.mjs`](examples/external-site/server.mjs) — sign-in on the hosted
page (authorization code + PKCE, `client_secret_post`, ES256 ID token verified with `node:crypto`), "Shop now" links
through `ssoLoginUrl()`, logout through the pool. Register a second `web` app in the same pool with redirect URI
`http://localhost:3000/callback` and post-logout URI `http://localhost:3000/`, then:

```sh
OPENBACK_ISSUER=https://api.example.com/gateway/shop/auth/main OPENBACK_CLIENT_ID=uapp_... \
OPENBACK_CLIENT_SECRET=obus_sec_... SHOP_DOMAIN=my-store.myshopify.com node examples/external-site/server.mjs
```

(In Git Bash on Windows, arguments like `--return-to /cart` are rewritten into Windows paths: prefix the command with
`MSYS_NO_PATHCONV=1`.)

## Logout behaviour

- **Sign-out in the store.** Shopify uses OpenID Connect RP-Initiated Logout: it sends the browser to the pool's
  `end_session_endpoint` (`<issuer>/logout`) with the post-logout redirect parameter (`post_logout_redirect_uri`) set to
  its Logout URL. The pool ends its **browser session** (the customer is signed out of every app of the pool that
  relies on that hosted session, and the refresh tokens issued from it stop working) and redirects back to Shopify —
  **only if** the URL is a registered post-logout URI of the app **and** the request names the app (`client_id` or an
  `id_token_hint`). Otherwise the pool shows its own "Signed out" page and the customer stays there.
- **Sign-out on your other site** through the pool (`<issuer>/logout`): ends the pool's browser session, so the next SSO
  link asks for the password. Shopify supports neither front-channel nor back-channel logout, so the **store session is
  not ended immediately**; because it came from the same pool session, its refresh token is revoked too, and the store
  should drop the customer once Shopify's access token (pool default 15 minutes) needs renewing — how quickly Shopify
  reacts to a refused refresh is not documented (see open points).
- **Session length.** Shopify keeps customer sessions up to 90 days with a refresh token, but a session can never
  outlive the pool's refresh token: default **14 days idle, 30 days absolute** (pool settings › Tokens). Raise them if
  customers should stay signed in longer.
- Disabling a user, "sign out everywhere", a password change or a reset of two-step verification revoke the pool
  sessions and refresh tokens: the store session ends at the next refresh.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| The pool shows "Redirect address not registered for this app" (no redirect back) | Shopify's Callback URL is not registered **exactly** on the app (other domain, trailing `/`, http/https) | Copy the Callback URL again from Shopify's Setup configurations into the app's Redirect URIs; register both domains during a domain change |
| `login_required` every time, nobody can sign in | Hosted sign-in is off in the pool | Turn **Hosted login** on (`check --client-id` reports it) |
| `login_required` on SSO links, then the sign-in page | Expected without a pool browser session (signed in through the JSON API, session expired, other browser) | Sign in on your site through the hosted page; raise `sso_session_days` if needed |
| Token exchange fails, `invalid_client` (401) in the pool logs | Wrong or regenerated client secret, app disabled, client ID of another pool, or an app of kind `spa`/`native` | Use a `web` app, paste its current secret into Shopify, check the app is enabled |
| `invalid_grant` "client or redirect_uri mismatch" / "invalid or expired code" | The code was redeemed by another app, after 120 s, or twice | Usually transient; check Shopify uses this app's client ID and the server clocks |
| `slow_down` (429) at the token endpoint | More than 120 token requests per minute from Shopify's addresses (sign-ins + refreshes) | See [Limitations](#limitations); spread the load or ask for a higher limit |
| Shopify error page "email not verified" | `email_verified` is false: unverified sign-up, admin-created user, provider without verified email | Keep **Require email verification** on; have the user verify (`POST /email/verify/send`) or mark the email verified in the portal; see [Requirements](#requirements) |
| Guest users cannot sign in to the store | Anonymous accounts have no email | Upgrade (`/me/upgrade`) and verify first |
| After store sign-out the customer stays on the pool's "Signed out" page | Logout URL not registered as post-logout URI, wrong parameter name, or Shopify sent neither `client_id` nor `id_token_hint` | Register Shopify's Logout URL(s) on the app; parameter name `post_logout_redirect_uri`; see open points |
| "Test connection" cannot load the provider | Issuer not public https, `GATEWAY_PUBLIC_URL` empty (issuer mismatch), discovery slower than 1 s | Run `check`; fix the gateway's public address |
| Name, phone, address, tags not imported | The pool's ID token has `name` only, none of Shopify's import claims | Not available today (see [Limitations](#limitations)) |
| A customer is asked to choose an organization or enter a 2FA code during SSO | B2B pool with several organizations, or two-step verification pending on the session | Expected: the pool shows its page even on `prompt=none`; finish it and Shopify continues |

## Limitations

- **ES256 only.** The pool signs ID tokens with ES256 (P-256) only. Shopify's Help Center lists ES256 among the
  supported algorithms (with RS256, PS256, EdDSA...; only HS256 is refused), but this setup has **not yet been tested on
  a Plus store**; `check` reports it as a warning until it is.
- **No claim import.** Shopify imports `given_name`, `family_name`, `phone_number`, `address`,
  `urn:shopify:customer:tags` and `urn:shopify:customer:addresses` (from the ID token, partly from userinfo). The pool's
  ID token and userinfo carry `name` (the display name), `picture`, `email`, `email_verified`, `org_id`, `roles` — none
  of those. So with an OpenBack pool Shopify gets the **email only**: no first/last name, phone, addresses or tags
  synced from the pool, and the `profile` / `phone` / `address` scopes add nothing (unknown scopes are ignored, not
  refused). Customers fill those fields in Shopify themselves.
- **`prompt=none` may show a page.** A B2B pool asks a user with several organizations to choose one, and a session
  without a completed second factor asks for it, instead of answering `interaction_required`. Shopify just shows the
  page; the customer finishes and continues.
- **`login_hint` is not enforced** with an existing pool session (see SSO above).
- **Token rate limit.** The pool allows 120 token-endpoint requests per minute per client address. Shopify exchanges
  codes and refreshes tokens from its servers, so a busy store may hit it (`slow_down`).
- **Logout redirect** depends on Shopify sending `client_id` or `id_token_hint` (not documented by Shopify).
- **Session length** is capped by the pool's refresh-token lifetime (default 30 days), not Shopify's 90 days.
- **Shop Pay:** if Shop Pay is enabled, Shopify asks for a "Sign in with Shop" button on the external sign-in page; the
  pool's hosted page has none.

Possible future users-service improvements (not part of this package): `given_name` / `family_name` (split name
fields) and `phone_number` / `address` profile fields with their scopes; a per-app ID token claim mapping (e.g. user
attributes → `urn:shopify:customer:tags` / `urn:shopify:customer:addresses`); `interaction_required` /
`account_selection_required` on `prompt=none` instead of showing pages, and `login_required` when `login_hint` names
another user than the session's; a per-client (instead of per-address) token-endpoint limit for server-to-server apps;
an RS256 signing option if Shopify turns out not to accept ES256.

## API reference

```js
import { ssoLoginUrl, checkPool, discoveryUrl, normalizeShopDomain, isSafeReturnTo, normalizeIssuer,
         ShopifySsoError, SHOPIFY_ID_TOKEN_ALGS, SHOPIFY_MAX_LATENCY_MS, VERSION } from "openback-app-auth-shopify";
```

| Export | |
|---|---|
| `ssoLoginUrl({ shopDomain, email, returnTo = "/" }) → string` | Shopify's SSO address; throws `ShopifySsoError` on a bad shop domain, email or return path |
| `checkPool({ issuer, clientId?, fetch?, timeoutMs? }) → Promise<report>` | `{ issuer, discoveryUrl, ok, counts: {pass, warn, fail}, checks: [{ id, status, message }], discovery }`; `ok` is false when a check fails; network errors become failed checks, never exceptions |
| `discoveryUrl(issuer) → string` | the value for Shopify's Discovery URL field |
| `normalizeShopDomain(shopDomain) → string` | lower-case host; accepts a host or an `https://` origin, refuses paths, ports, user info, `http://`, IPs |
| `isSafeReturnTo(path) → boolean` | relative same-shop path test used by `ssoLoginUrl` |
| `normalizeIssuer(issuer) → string` | the issuer without trailing `/`; `TypeError` when not an absolute http(s) URL |
| `ShopifySsoError` | `Error` with `code`: `invalid_shop_domain`, `invalid_email`, `invalid_return_to` |
| `SHOPIFY_ID_TOKEN_ALGS` | ID token algorithms Shopify lists as supported |
| `SHOPIFY_MAX_LATENCY_MS` | 1000 — Shopify's response-time limit |
| `VERSION` | `"1.0.0"` |

Check ids: `https`, `discovery`, `latency`, `issuer`, `endpoint:authorization_endpoint`, `endpoint:token_endpoint`,
`endpoint:jwks_uri`, `endpoint:userinfo_endpoint`, `response_type`, `grant:authorization_code`, `grant:refresh_token`,
`token_auth`, `prompt_none`, `claims`, `claim_import`, `scopes`, `additional_scopes`, `logout`, `pkce`, `id_token_alg`,
`jwks`, and with a client ID `hosted_login`, `email_verification`, `anonymous`, `mode`, `mfa` (or `pool-settings` when
not checked).

CLI:

```
openback-app-auth-shopify check <issuer> [--client-id <uapp_...>] [--json]     exit 0 ok, 1 a check failed, 2 usage
openback-app-auth-shopify sso-url --shop <domain> --email <email> [--return-to </path>]
openback-app-auth-shopify --help | --version
```

## Errors

- `ssoLoginUrl` throws `ShopifySsoError` (`code` as above) — validate before redirecting, show a generic error.
- `checkPool` throws `TypeError` only for an invalid issuer or a missing `fetch`; everything else is a check result.
- What Shopify and the pool answer during sign-in is in [Troubleshooting](#troubleshooting).

## Security notes

- Keep the **client secret** in Shopify only (and your secret store); it is shown once by the portal. Regenerate it if
  it leaks and update Shopify. The helper never needs it: `checkPool` reads public documents only (discovery, JWKS,
  `/api/v1/config` with the public client ID).
- **Email verification is the trust anchor**: Shopify links an existing customer by email. Keep verification on, and
  keep the pool's account-linking policy at "verified_only" so a social sign-in cannot take over an existing email.
- Build SSO links from the **verified** identity of the signed-in user, never from request parameters, and only with
  relative `returnTo` paths (the helper refuses open-redirect shapes such as `//evil.example`, `/\evil.example`,
  `/%2F%2Fevil.example`).
- The example site verifies the ID token itself (ES256 only — never `none`, HS* or RS* —, `iss`, `aud`, `exp`,
  `nonce`), uses PKCE + `state` + `nonce` from the platform CSPRNG and never logs tokens or codes.
- Refresh tokens rotate at every use and a reused one revokes the whole session; Shopify handles its own tokens.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 GexyLab and the OpenBack contributors.
