# openback-app-auth-javascript

Browser client of an OpenBack **user pool** (App authenticator): sign-up, sign-in (password, email code, guest,
social providers through the hosted page), two-step verification, tokens renewed and rotated safely, organizations.

Version **1.0.0** · License **MIT** · Plain JavaScript, no dependencies, no build step needed to use it.

## Requirements

- A browser with `fetch`, Web Crypto (`crypto.subtle`) and `URLSearchParams`: every evergreen browser (Chrome/Edge 88+,
  Firefox 85+, Safari 14+). Web Locks (`navigator.locks`) is used when present to refresh once across tabs.
- Also runs in any JavaScript runtime with `fetch` and Web Crypto (Node.js 18+, Deno, Bun) — for servers prefer
  [`openback-app-auth-nodejs`](../../nodejs/1.0.0), which adds token verification and middleware.
- Node.js 18+ only to run the tests and rebuild `dist/`.

## Installation

Once published on npm:

```sh
npm install openback-app-auth-javascript
```

From this repository (until then): copy `SDK/Auth/javascript/1.0.0` into your project, or

```sh
npm install ./path/to/openback-plugins-community/SDK/Auth/javascript/1.0.0
```

Without a bundler, load the pre-built bundle with a plain `<script>` tag — it defines the global `OpenBackAppAuth`:

```html
<script src="dist/openback-app-auth.umd.min.js"></script>
<script>
  const auth = OpenBackAppAuth.createAuth({ issuer: "https://api.example.com/gateway/shop/auth/main", clientId: "uapp_..." });
</script>
```

| File | For |
|---|---|
| `src/index.js` (+ `src/index.d.ts`) | bundlers, `import` (what `"openback-app-auth-javascript"` resolves to) |
| `dist/openback-app-auth.esm.js` | `<script type="module">` / `import` from a CDN |
| `dist/openback-app-auth.umd.js` | plain `<script>` (global `OpenBackAppAuth`), AMD, CommonJS |
| `dist/openback-app-auth.umd.min.js` | the same, lighter (comments and indentation removed) |

## Register your app in the pool

In the OpenBack portal open the user pool, tab **Apps**, and add an app of kind **`spa`**:

- **Allowed origins**: every origin your site runs on (`https://shop.example.com`, `http://localhost:5173` for
  development). The JSON API answers CORS only for these; a call from another origin gets `origin_not_allowed` (403).
- **Redirect URIs** (only for the hosted page): the exact addresses `handleRedirectCallback()` runs on, e.g.
  `https://shop.example.com/callback`. They must match exactly; `http://` only for `localhost`.
- **Post-logout redirect URIs** (only for `signOutRedirect()`): where the hosted logout may send the user back.

Note the pool's address (the **issuer**, e.g. `https://api.example.com/gateway/shop/auth/main`) and the app's
**client ID** (`uapp_...`, public).

## Quick start

```js
import { createAuth } from "openback-app-auth-javascript";

const auth = createAuth({
  issuer: "https://api.example.com/gateway/shop/auth/main",
  clientId: "uapp_...",
  redirectUri: "https://shop.example.com/callback",   // only for the hosted page
});

// Called at once with the current state, then on every sign-in, sign-out, user or organization change
// (also when another tab signs in or out).
auth.onAuthStateChanged((user, org) => render(user, org));
```

### Sign in with your own form (incl. two-step verification)

```js
let res = await auth.signInWithPassword({ email, password });
if (res.status === "mfa_required") {
  res = await auth.verifyMfa({ mfaToken: res.mfa_token, code: prompt("Code from your authenticator app") });
}
switch (res.status) {
  case "ok": break;                                   // signed in: auth.currentUser, auth.isSignedIn
  case "mfa_enroll_required": {                       // the pool requires 2FA and the user has none yet
    const { otpauth_uri } = await auth.enrollMfa(res.mfa_token);   // show it as a QR code
    res = await auth.confirmMfa(codeFromApp, res.mfa_token);       // -> recovery_codes + signed in
    break;
  }
  case "verification_required": showCheckYourInbox(); break;
  case "password_change_required":
    await auth.changeForcedPassword({ changeToken: res.change_token, newPassword });
    break;
}
```

### Sign in with the hosted page (OpenID Connect, code + PKCE)

```js
// Sign-in button (provider: straight to a social provider of the pool; screenHint: "signup" opens the sign-up form)
await auth.signInWithRedirect({ provider: "uprov_..." });

// On the redirect page:
try {
  const user = await auth.handleRedirectCallback();   // null when the URL is not a callback
  history.replaceState(null, "", location.pathname);  // drop ?code=&state= from the address bar
} catch (e) { /* e.code: invalid_state, invalid_issuer, invalid_nonce, login_required, access_denied, ... */ }

// Low level: build the request yourself (e.g. to open it in a popup); the transaction is kept for the callback.
const { url, state, nonce, codeVerifier, redirectUri } = await auth.buildAuthorizationRequest({ prompt: "login" });

// Sign out of the app AND the hosted page session:
await auth.signOutRedirect({ postLogoutRedirectUri: "https://shop.example.com/" });
```

### Call your API

```js
const res = await auth.fetch("https://api.example.com/gateway/shop/orders");   // Authorization: Bearer <access token>
// or
const token = await auth.getAccessToken();   // renewed when it expires within 60 s
```

Your API checks the token: behind the OpenBack gateway with the endpoint check **"Authenticated app user"** (no code;
functions get `event.user`), or in your own server with [`openback-app-auth-nodejs`](../../nodejs/1.0.0) (or any JWT
library: ES256, `typ: at+jwt`, `iss`, `aud` = your client ID, keys at `<issuer>/.well-known/jwks.json`).

A complete page (plain `<script>` tag, password + MFA, hosted page button): [`examples/index.html`](examples/index.html).

## API reference

`createAuth(options)` / `createClient(issuer, clientId, options)` → client. Options: `issuer`, `clientId`,
`redirectUri?`, `storage?` (sync or async `getItem/setItem/removeItem`; default `localStorage`, memory when blocked),
`storageKey?` (default `openback.auth.<clientId>`), `transactionStorage?` (default `sessionStorage`), `fetch?`,
`locks?` (default `navigator.locks`; `false` disables).

| Member | |
|---|---|
| `currentUser`, `currentOrg` | the signed-in user (PoolUser) and active organization (B2B), or `null` |
| `isSignedIn` | a session is stored (refresh token, or an unexpired access token) |
| `accessTokenClaims` | the access token's claims, decoded, **not verified** |
| `idToken`, `issuer`, `clientId`, `ready` | the ID token of a hosted sign-in; options; a promise settled when an async storage is read |
| `config()` | the pool's public configuration (methods, providers, password policy, branding) |
| `onAuthStateChanged(fn)` | `fn(user, org)` now and on every change; returns the unsubscribe function |
| `getAccessToken()` | the access token, refreshed when it expires within 60 s |
| `refresh(orgId?)` | renew now (single-flight), optionally for another organization |
| `fetch(input, init?)` | `fetch` with the Bearer token |
| `signUp({email, password, displayName?, locale?, orgId?})` | → Outcome |
| `signInWithPassword({email, password, orgId?})` | → Outcome |
| `sendEmailCode(email)` / `signInWithEmailCode({email, code} \| {token}, orgId?)` | passwordless sign-in → Outcome |
| `signInAnonymously()` | guest account → Outcome |
| `verifyMfa({mfaToken, code})` | second step (TOTP or recovery code) → Outcome |
| `enrollMfa(mfaToken?)` / `confirmMfa(code, mfaToken?)` / `disableMfa(code)` | TOTP set-up (during sign-in with `mfaToken`, or signed in) |
| `buildAuthorizationRequest(opts?)` | → `{url, state, nonce, codeVerifier, redirectUri}`; opts `provider, orgId, prompt, screenHint, loginHint, maxAge, scope, uiLocales, redirectUri` |
| `signInWithRedirect(opts?)` | go to the hosted page |
| `handleRedirectCallback(url?)` | checks error, state (constant time), `iss`, exchanges the code, checks the ID token's `iss`/`aud`/`nonce` → user or `null` |
| `buildLogoutUrl(postLogoutRedirectUri?, state?)` (or `{postLogoutRedirectUri, state}`) | `<issuer>/logout?...` with `id_token_hint` |
| `signOutRedirect({postLogoutRedirectUri?, state?, everywhere?})` | `signOut()` then the hosted logout |
| `sendPasswordReset(email)` / `resetPassword({token} \| {email, code}, newPassword)` | forgotten password |
| `changeForcedPassword({changeToken, newPassword})` | after `password_change_required` |
| `verifyEmail({token} \| {email, code})` / `resendVerification()` | email verification |
| `me()` | the user with `org_id, roles, providers, has_password` |
| `updateProfile({displayName?, photoUrl?, locale?})` | → PoolUser |
| `changePassword({currentPassword?, newPassword})` | every session ends: the local one is cleared |
| `changeEmail(newEmail)` / `confirmEmailChange({code} \| {token})` | change of address |
| `upgradeAnonymous({email, password})` | a guest becomes a real account (same id) |
| `deleteAccount(password?)` | deletes the user, clears the session |
| `signOut({everywhere?})` | best-effort server call, always clears locally |
| `organizations()` / `createOrganization(name)` / `switchOrganization(orgId)` | B2B organizations |
| `members(orgId, {q, skip, limit})` / `addMember(orgId, {...})` / `setMemberRoles(orgId, userId, roles)` / `removeMember(orgId, userId)` | organization admins |
| `decodeJwt(token)`, `memoryStorage()`, `AuthError`, `VERSION` | helpers |

Types: [`src/index.d.ts`](src/index.d.ts).

## Outcomes and errors

Every sign-up / sign-in returns an **Outcome** (`res.status`); the session is kept only on `ok`:

| status | then |
|---|---|
| `ok` | signed in (`access_token`, `refresh_token`, `expires_in`, `user`, `org`) |
| `mfa_required` | `verifyMfa({ mfaToken: res.mfa_token, code })` |
| `mfa_enroll_required` | `enrollMfa(res.mfa_token)` → `confirmMfa(code, res.mfa_token)` |
| `verification_required` | the user must verify the email address first |
| `password_change_required` | `changeForcedPassword({ changeToken: res.change_token, newPassword })` |

Failures throw `AuthError` with `status` (HTTP status, `0` for network errors), `code`, `message`, `detail`:

| code | when |
|---|---|
| `invalid_credentials` (401) | wrong email/password (also unknown email, locked account) |
| `too_many_requests` (429) | rate limited |
| `weak_password` (422) | `detail.problems` lists what is missing |
| `email_in_use` (409), `invalid_code`, `method_disabled`, `signup_disabled` | |
| `origin_not_allowed` (403) | the page's origin is not an allowed origin of the app |
| `token_expired`, `token_invalid`, `token_missing`, `token_revoked`, `token_other_app` (401) | **the local session is cleared** and listeners get `null` |
| `invalid_refresh_token` (401) | the session ended (expired, revoked, reused): **cleared**, listeners notified |
| `not_signed_in` (401) | `getAccessToken()` / a signed-in call without a session |
| `network_error` (0) | the request did not complete; nothing is retried automatically |
| `invalid_state`, `invalid_issuer`, `invalid_nonce`, `invalid_id_token`, `missing_transaction` | redirect callback checks |
| `login_required`, `access_denied`, ... | the `error` of the hosted page's redirect (e.g. `prompt: "none"` without a session) |
| `invalid_grant`, `invalid_client`, `slow_down` | the token endpoint |
| `http_<status>` | anything without a code |

## Security notes

- **Storage**: the session (`{accessToken, refreshToken, idToken, expiresAt, user, org}`) is kept in `localStorage`
  under `openback.auth.<clientId>`, readable by any script of your origin: protect the site against XSS (CSP, no
  untrusted HTML). Pass `storage: memoryStorage()` to keep it only for the page's life, or your own storage.
- **Refresh token rotation**: every refresh returns a new refresh token and invalidates the old one; presenting a used
  one revokes the whole session. The SDK refreshes **one at a time** (a queue in the tab, Web Locks across tabs),
  re-reads the stored session before refreshing (another tab may have done it), writes the new session in one storage
  write, and never retries a refresh after a network error (the server may have rotated already: the error is
  surfaced; the next call tries again with the stored token). Browsers without Web Locks may, rarely, refresh in two
  tabs at once and lose the session.
- **PKCE and state**: the hosted flow always uses PKCE S256 (64-character verifier from 48 random bytes), a random
  `state` checked in constant time, the `iss` of the redirect (RFC 9207) and the ID token's `nonce`. The pending
  transaction lives in `sessionStorage` and is used once. The ID token's signature is not checked in the browser (it
  comes straight from the token endpoint over TLS); servers must verify tokens with the pool's keys.
- **Access tokens cannot be revoked** before they expire (default 15 minutes); `signOut()` revokes the refresh token.
- **Never log tokens**, codes or passwords; the SDK does not log anything.
- `auth.fetch()` sends the token to whatever URL you give it: use it only for your own APIs.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 GexyLab and the OpenBack contributors.
