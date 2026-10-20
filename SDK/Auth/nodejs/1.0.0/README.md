# openback-app-auth-nodejs

OpenBack **App authenticator** (user pools) for Node.js: verify the pool's tokens locally, guard Express / Fastify /
`node:http` routes, sign users in to a server-rendered web app with OpenID Connect, and call the pool's JSON API.

Version **1.0.0** · License **MIT** · ES module with TypeScript types · one runtime dependency: [`jose`](https://github.com/panva/jose).

## Requirements

- Node.js **18 or later** (20+ recommended). On Node.js 18 the package installs `node:crypto`'s Web Crypto as
  `globalThis.crypto` if it is missing (jose 6 needs it).
- ES modules (`import`). From CommonJS use `await import("openback-app-auth-nodejs")` (or `require()` on Node.js
  20.19+/22.12+, which load ES modules).
- Express 4/5, Fastify 4/5 or plain `node:http` for the guards (none of them is a dependency).

## Installation

Once published on npm:

```sh
npm install openback-app-auth-nodejs
```

From this repository (until then):

```sh
npm install ./path/to/openback-plugins-community/SDK/Auth/nodejs/1.0.0
```

## Register your app in the pool

In the OpenBack portal open the user pool, tab **Apps**:

| You are building | App kind | Register |
|---|---|---|
| an API that only **verifies** tokens of other apps | none needed | use the client IDs of the apps calling it (`clientIds`) |
| a web app with its own server (`OidcWebClient`) | **`web`** | redirect URIs (exact, `http://` only for localhost), post-logout redirect URIs; keep the **client secret** on the server |
| a CLI / desktop app (`createAuth` + loopback redirect) | **`native`** | redirect URI `http://127.0.0.1:<port>/callback` |
| a server calling the JSON API (`createAuth`) | **`backend`** | nothing else (calls without `Origin`) |

Note the pool's address (the **issuer**, e.g. `https://api.example.com/gateway/shop/auth/main`) and the app's
**client ID** (`uapp_...`).

## Quick start

### Protect your API (Express)

```js
import express from "express";
import { TokenVerifier, requireAppUser } from "openback-app-auth-nodejs";

const verifier = new TokenVerifier({
  issuer: "https://api.example.com/gateway/shop/auth/main",
  clientIds: ["uapp_web", "uapp_mobile"],   // the apps whose tokens this API accepts
});

const app = express();
app.get("/api/profile", requireAppUser({ verifier }), (req, res) => res.json({ id: req.appUser.id, email: req.appUser.email }));
app.delete("/api/orders/:id", requireAppUser({ verifier, requireRoles: ["admin"], requirePermissions: ["orders.delete"] }), handler);
```

### Sign in from a script / CLI (password + two-step verification)

```js
import { createAuth } from "openback-app-auth-nodejs";

const auth = createAuth({ issuer: "https://api.example.com/gateway/shop/auth/main", clientId: "uapp_..." });
let res = await auth.signInWithPassword({ email, password });
if (res.status === "mfa_required") res = await auth.verifyMfa({ mfaToken: res.mfa_token, code });
if (res.status === "ok") {
  const r = await auth.fetch("https://api.example.com/gateway/shop/orders");   // Authorization: Bearer <access token>
}
```

### Sign in to a web app with the hosted page (OpenID Connect)

```js
import { OidcWebClient } from "openback-app-auth-nodejs";

const oidc = new OidcWebClient({
  issuer: "https://api.example.com/gateway/shop/auth/main",
  clientId: "uapp_...",
  clientSecret: process.env.OPENBACK_CLIENT_SECRET,      // client_secret_basic by default
  redirectUri: "https://shop.example.com/callback",
});

app.get("/login", async (req, res) => {
  const { url, transaction } = await oidc.authorizationUrl({ provider: req.query.provider });   // provider optional
  req.session.oidc = transaction;                       // server-side session
  res.redirect(url);
});

app.get("/callback", async (req, res) => {
  const transaction = req.session.oidc;
  delete req.session.oidc;
  const tokens = await oidc.handleCallback(req.query, transaction);   // state, iss, code exchange, ID token verified
  req.session.user = tokens.idTokenClaims;                             // sub, email, name, org_id, roles...
  req.session.tokens = { refreshToken: tokens.refreshToken, accessToken: tokens.accessToken, expiresAt: tokens.expiresAt };
  res.redirect("/");
});

app.get("/logout", async (req, res) => {
  await oidc.revoke(req.session.tokens?.refreshToken).catch(() => {});
  const url = oidc.logoutUrl({ idTokenHint: req.session.idToken, postLogoutRedirectUri: "https://shop.example.com/" });
  req.session.destroy(() => res.redirect(url));
});
```

Runnable examples in [`examples/`](examples): `express-api.mjs`, `fastify-api.mjs`, `http-api.mjs`,
`oidc-web-login.mjs` (no framework), `backend-signin.mjs`.

## Server-side verification and framework integration

`TokenVerifier` checks access tokens **locally** (no call to OpenBack per request):

- keys from `<issuer>/.well-known/jwks.json` (or `jwksUri`), cached 10 minutes (`jwksCacheTtl`, seconds); an unknown
  `kid` refetches them at most once every 30 s (`jwksRefetchInterval`); while the pool is unreachable the cached keys
  stay in use;
- **only `ES256`** — `none`, `HS*`, `RS*`... are refused before any key lookup (no algorithm confusion);
- header `typ` = `at+jwt` (case-insensitive, `application/at+jwt` accepted); ID tokens: `JWT`;
- `iss` = the issuer exactly, `aud` = one of `clientIds`, `exp` / `nbf` / `iat` with a 60 s `leeway`.

```js
const user = await verifier.verify(token);   // AppUser, or throws TokenVerificationError (code, status 401 / 503)
user.id; user.poolId; user.clientId; user.email; user.emailVerified; user.anonymous; user.orgId;
user.roles; user.permissions; user.attributes; user.sessionId; user.amr; user.claims;
user.hasRole("admin"); user.hasPermission("orders.read");   // "*" grants every permission
```

**Guards** (`requireAppUser` for Express/Connect, `requireAppUserHttp` for `node:http`, `fastifyRequireAppUser` /
the `fastifyAppUser` plugin for Fastify) read `Authorization: Bearer`, verify, and attach the user to `req.appUser`
(`property` option). Options: `verifier` (or the `TokenVerifier` options), `requireRoles` (at least one of them),
`requirePermissions` (all of them), `requireVerifiedEmail` (default `false`), `allowAnonymous` (default `false`: guest
tokens are refused). Answers:

| status | body | when |
|---|---|---|
| 401 + `WWW-Authenticate: Bearer error="invalid_token"` | `{"error":"invalid_token"}` | missing, malformed, expired or foreign token |
| 403 + `WWW-Authenticate: Bearer error="insufficient_scope"` | `{"error":"insufficient_scope"}` | guest, unverified email, role or permission missing |
| 503 | `{"error":"temporarily_unavailable"}` | the pool's keys could not be fetched yet |

```js
// Fastify
await fastify.register(fastifyAppUser, { issuer, clientIds: ["uapp_..."] });
fastify.get("/me", { preHandler: fastify.requireAppUser({ requireRoles: ["admin"] }) }, async (req) => req.appUser);

// node:http
const guard = requireAppUserHttp({ issuer, clientIds: ["uapp_..."] });
createServer(async (req, res) => { const user = await guard(req, res); if (!user) return; /* ... */ });
```

**No SDK needed behind the OpenBack gateway**: an API published through the OpenBack gateway can use the endpoint check
**"Authenticated app user"** (pool, roles, permissions, verified email, guests); the function behind it gets
`event.user`.

**Access tokens cannot be revoked** before they expire (default 15 minutes, set per pool). For instant revocation
check the session with the pool (`/userinfo`, or the JSON API's `/me`) on sensitive operations, and keep lifetimes short.

## API reference

**Verification**

| | |
|---|---|
| `new TokenVerifier({issuer, clientIds, jwksUri?, leeway?, jwksCacheTtl?, jwksRefetchInterval?, fetch?})` | |
| `verifier.verify(token)` / `verifyAccessToken(token)` | → `AppUser` |
| `verifier.verifyIdToken(token, {nonce?, clientId?, accessToken?})` | → ID token claims (nonce, azp, at_hash checked) |
| `AppUser` | `id, poolId, clientId, email, emailVerified, anonymous, orgId, roles, permissions, attributes, sessionId, amr, scope, expiresAt, claims, hasRole(), hasPermission()` |
| `TokenVerificationError` | `code` (`alg_not_allowed`, `invalid_typ`, `invalid_signature`, `invalid_issuer`, `invalid_audience`, `token_expired`, `token_not_yet_valid`, `unknown_kid`, `invalid_nonce`, `invalid_at_hash`, `invalid_token`, `jwks_unavailable`), `status` |

**Guards**: `requireAppUser(options)`, `requireAppUserHttp(options)`, `fastifyRequireAppUser(options)`,
`fastifyAppUser` (plugin: `fastify.requireAppUser(opts)`, `global: true`), `createAppUserAuthenticator(options)`
(framework-free core: `await authenticate(headers)` → `{ok, user}` or `{ok: false, status, headers, body}`).

**OidcWebClient** (`issuer, clientId, clientSecret?, redirectUri?, postLogoutRedirectUri?, scope?, tokenEndpointAuthMethod?
("client_secret_basic" | "client_secret_post" | "none"), verifier?, fetch?`)

| | |
|---|---|
| `authorizationUrl({redirectUri?, scope?, provider?, orgId?, prompt?, screenHint?, loginHint?, maxAge?, uiLocales?})` | → `{url, transaction: {state, nonce, codeVerifier, redirectUri, scope, createdAt}}` |
| `handleCallback(params, transaction)` | checks error, state (constant time), `iss`; exchanges the code; verifies the ID token → `TokenResult` |
| `refresh(refreshToken, {orgId?})` | → `TokenResult` (rotated refresh token, no ID token) |
| `revoke(refreshToken)` | RFC 7009, ends the session |
| `userinfo(accessToken)` | OIDC userinfo |
| `logoutUrl({idTokenHint?, postLogoutRedirectUri?, state?})` | the hosted logout address |

`TokenResult`: `accessToken, tokenType, expiresIn, expiresAt (epoch ms), scope, refreshToken, refreshExpiresIn, idToken,
idTokenClaims, org, raw`.

**Client** — `createAuth({issuer, clientId, clientSecret?, redirectUri?, storage?, storageKey?, transactionStorage?, fetch?})`
or `createClient(issuer, clientId, options)`; the same API as
[`openback-app-auth-javascript`](../../javascript/1.0.0#api-reference): `currentUser`, `currentOrg`,
`accessTokenClaims`, `isSignedIn`, `idToken`, `ready`, `config()`, `onAuthStateChanged(fn)`, `getAccessToken()`,
`refresh(orgId?)`, `fetch(input, init?)`, `signUp`, `signInWithPassword`, `sendEmailCode`, `signInWithEmailCode`,
`signInAnonymously`, `verifyMfa`, `enrollMfa(mfaToken?)`, `confirmMfa(code, mfaToken?)`, `disableMfa(code)`,
`sendPasswordReset`, `resetPassword`, `changeForcedPassword`, `verifyEmail`, `resendVerification`, `me`, `updateProfile`,
`changePassword`, `changeEmail`, `confirmEmailChange`, `upgradeAnonymous`, `deleteAccount`, `signOut({everywhere?})`,
`organizations`, `createOrganization`, `switchOrganization`, `members`, `addMember`, `setMemberRoles`, `removeMember`,
`buildAuthorizationRequest(opts?)`, `handleRedirectCallback(url, transaction?)`, `buildLogoutUrl(...)`. No
`signInWithRedirect` (no browser): open `buildAuthorizationRequest().url` yourself.

Storage: in memory by default. Plug any object with `getItem/setItem/removeItem` (sync or `async`) to keep the session
in a file, a database or the user's server-side session; the session is one JSON
`{accessToken, refreshToken, idToken, expiresAt, user, org}` under `openback.auth.<clientId>`:

```js
import { readFile, writeFile, rm } from "node:fs/promises";
const fileStorage = {
  getItem: (k) => readFile(`.session-${k}.json`, "utf8").catch(() => null),
  setItem: (k, v) => writeFile(`.session-${k}.json`, v, { mode: 0o600 }),
  removeItem: (k) => rm(`.session-${k}.json`, { force: true }),
};
const auth = createAuth({ issuer, clientId, storage: fileStorage });
await auth.ready;
```

Helpers: `decodeJwt(token)` (no verification), `memoryStorage()`, `AuthError`, `VERSION`. Types: [`src/index.d.ts`](src/index.d.ts).

## Outcomes and errors

Sign-up / sign-in calls return an **Outcome** (`status`); the session is kept only on `ok`:
`ok` · `mfa_required` (`mfa_token` → `verifyMfa`) · `mfa_enroll_required` (`mfa_token` → `enrollMfa`, `confirmMfa`) ·
`verification_required` · `password_change_required` (`change_token` → `changeForcedPassword`).

Errors of the pool throw `AuthError` (`status`, `code`, `message`, `detail`): `invalid_credentials` (401),
`too_many_requests` (429), `weak_password` (422, `detail.problems`), `email_in_use` (409), `invalid_code`,
`method_disabled`, `signup_disabled`, `origin_not_allowed` (403), `token_expired` / `token_invalid` / `token_missing` /
`token_revoked` / `token_other_app` (401: **the client clears its session**), `invalid_refresh_token` (401: cleared too),
`not_b2b`, `org_creation_disabled`, `not_org_admin`, `owners_only`, `not_a_member`; OAuth endpoints: `invalid_grant`,
`invalid_client`, `slow_down`, `invalid_token`; client-side: `network_error` (status 0), `not_signed_in`,
`invalid_state`, `invalid_issuer`, `invalid_nonce`, `invalid_id_token`, `missing_transaction`; anything else
`http_<status>`. ID token problems in `OidcWebClient.handleCallback` throw `TokenVerificationError`.

## Security notes

- **Refresh tokens rotate** at every use; a used one presented again revokes the whole session. The client refreshes
  one at a time (a promise queue, also for `switchOrganization`), stores the new session in one write and never
  retries a refresh after a network error. Share one client per session; if several processes share a stored session,
  serialize them with a lock around your storage. With `OidcWebClient.refresh`, store the returned `refreshToken` and
  never refresh the same session twice in parallel.
- **PKCE S256** is always used (also by confidential clients), with a random `state` (compared in constant time), the
  callback's `iss` (RFC 9207) and the ID token's `nonce`. Keep the `transaction` in a server-side session, use it once.
- **Client secrets** stay on the server (environment or secret manager), never in a browser or a mobile app.
- **Never log tokens**, authorization codes, secrets or passwords; the SDK does not log anything.
- Keep the storage of a CLI session readable only by the user (`mode: 0o600`).

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 GexyLab and the OpenBack contributors.
