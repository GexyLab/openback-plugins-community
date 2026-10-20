# openback-app-auth-php

PHP SDK for OpenBack's **App authenticator** (user pools): verify the pool's tokens in your API, sign users in to your
PHP web app through the pool's hosted page, or call the pool's JSON API from PHP code.

Version **1.0.0** · License **MIT** · Composer package `openback/openback-app-auth-php` · namespace `OpenBack\AppAuth`

## Requirements

- PHP **8.1** or later, with `ext-openssl` and `ext-json`.
- `ext-curl` for the built-in HTTP transport, **or** any PSR-18 HTTP client (Guzzle, Symfony HttpClient...) with PSR-17
  factories.
- Optional: a PSR-16 cache (`psr/simple-cache`) or APCu for the JWKS cache; `psr/http-server-middleware` and a PSR-7
  implementation (e.g. `nyholm/psr7`) for the PSR-15 middleware.

No JWT or crypto library is needed: ES256 verification is done with ext-openssl directly.

## Installation

Once published on Packagist:

```bash
composer require openback/openback-app-auth-php
```

Until then, from this repository (path `SDK/Auth/php/1.0.0` of
[openback-plugins-community](https://github.com/GexyLab/openback-plugins-community)):

```json
{
    "repositories": [{"type": "path", "url": "../openback-plugins-community/SDK/Auth/php/1.0.0"}],
    "require": {"openback/openback-app-auth-php": "1.0.0"}
}
```

## Register your app in the pool

In the OpenBack portal open the user pool, tab **Apps**, and add the app of the kind that matches your PHP code:

| You are writing | Kind | Register |
|---|---|---|
| an API that only **verifies** tokens of other apps | none needed | use the client IDs of the apps that call it (`aud`) |
| a server-rendered site signing users in with the hosted page | `web` | redirect URI(s), e.g. `https://shop.example.com/auth/callback` (exact match), post-logout redirect URI(s); copy the **client secret** |
| a server calling the JSON API for users (your own forms) | `backend` | client secret (kept on the server) |
| a CLI / desktop tool | `native` | a redirect URI if it uses the hosted page |

You need the pool's address (the **issuer**, e.g. `https://api.example.com/gateway/shop/auth/main`) and the app's
**client ID** (`uapp_...`). Redirect URIs must match a registered one exactly; `http://` is allowed only for
`localhost`.

## Quick start

### Sign in with email and password (own forms, JSON API)

```php
use OpenBack\AppAuth\Client;
use OpenBack\AppAuth\OutcomeStatus;
use OpenBack\AppAuth\Storage\SessionStorage;

$auth = new Client('https://api.example.com/gateway/shop/auth/main', 'uapp_...', [
    'storage' => new SessionStorage(),          // the session follows the browser's PHP session
]);

$res = $auth->signInWithPassword($email, $password);
switch ($res->status) {
    case OutcomeStatus::Ok:                     // signed in: tokens kept in the storage
        break;
    case OutcomeStatus::MfaRequired:            // ask for the authenticator code
        $res = $auth->verifyMfa($res->mfaToken, $code);
        break;
    case OutcomeStatus::MfaEnrollRequired:      // the pool requires two factors: enroll now
        $enroll = $auth->enrollMfa($res->mfaToken);          // {secret, otpauth_uri}: show a QR code
        $done = $auth->confirmMfa($code, $res->mfaToken);    // {recovery_codes, ...}: show them once
        break;
    case OutcomeStatus::PasswordChangeRequired:
        $auth->changeForcedPassword($res->changeToken, $newPassword);
        break;
    case OutcomeStatus::VerificationRequired:   // the email must be verified first
        break;
}
```

### Hosted sign-in page (`web` app)

```php
use OpenBack\AppAuth\OidcWebClient;

$oidc = new OidcWebClient($issuer, 'uapp_...', getenv('OPENBACK_CLIENT_SECRET'), 'https://shop.example.com/auth/callback');

// /auth/login
$req = $oidc->authorizationUrl(['provider' => 'uprov_...']);       // optional: straight to Google etc.
$_SESSION['ob_tx'] = $req->transaction->toArray();                  // server-side, never in a plain cookie
header('Location: ' . $req->url);

// /auth/callback
$tx = $_SESSION['ob_tx'] ?? [];
unset($_SESSION['ob_tx']);
$tokens = $oidc->handleCallback($_GET, $tx);      // checks error, state, iss; PKCE; verifies the ID token + nonce
$sub = $tokens->idTokenClaims['sub'];             // the user id (usr_...): link your local account to it

// /auth/logout (single logout; the post-logout URI must be registered on the app)
header('Location: ' . $oidc->logoutUrl($idToken, 'https://shop.example.com/'));
```

A complete page is in [examples/web-login.php](examples/web-login.php).

### Calling your API

```php
$response = $auth->fetch('GET', 'https://api.example.com/gateway/shop/orders');   // adds Authorization: Bearer
$request = $auth->authorizeRequest($psr7Request);                                  // or with your PSR-18 client
$token = $auth->getAccessToken();                                                  // renewed 60 s before expiry
```

## Server-side verification

```php
use OpenBack\AppAuth\TokenVerifier;

$verifier = new TokenVerifier('https://api.example.com/gateway/shop/auth/main', ['uapp_web', 'uapp_mobile'], [
    'cache' => $psr16Cache,      // optional: PSR-16; else APCu when enabled, else in-process memory
    'leeway' => 60,              // seconds of clock skew for exp/nbf/iat
    'cacheTtl' => 600,           // JWKS cache lifetime
]);
$user = $verifier->verify($bearerToken);          // AppUser or AppAuthException (401 token_*, 503 jwks_unavailable)
$user->id; $user->orgId; $user->roles; $user->hasRole('admin'); $user->hasPermission('orders.read');
```

What is checked: algorithm **ES256 only** (`none`, HS*, RS* are refused), header `typ` `at+jwt` (or
`application/at+jwt`), the signature with the pool's key `kid` from `<issuer>/.well-known/jwks.json` (cached; an
unknown `kid` refetches at most once per 30 s), `iss` exact, `aud` among your client IDs, `exp` / `nbf` / `iat` with
the leeway. No call to OpenBack per token. **Access tokens cannot be revoked before they expire** (the pool's default
lifetime is 15 minutes): for an immediate check of the session, call the pool's `/api/v1/me` instead.

### PSR-15 middleware

```php
use OpenBack\AppAuth\AppUser;
use OpenBack\AppAuth\Middleware\RequireAppUser;

$app->add(new RequireAppUser($verifier, $responseFactory, $streamFactory, [
    'requireRoles' => ['admin', 'editor'],     // any of them
    'requirePermissions' => ['orders.read'],   // all of them ("*" grants all)
    'requireVerifiedEmail' => false,
    'allowAnonymous' => false,                 // guest tokens (anon: true) are refused by default
]));
$user = $request->getAttribute(AppUser::class);
```

Missing or invalid token: **401** `WWW-Authenticate: Bearer error="invalid_token"`, body `{"error":"invalid_token"}`;
options not met: **403** `{"error":"insufficient_scope"}`; the pool's keys unreachable: **503**
`{"error":"temporarily_unavailable"}`. Example: [examples/psr15-middleware.php](examples/psr15-middleware.php).
Without a PSR-15 stack see [examples/verify-token.php](examples/verify-token.php).

### No SDK needed behind the OpenBack gateway

An API published through the OpenBack gateway can use the endpoint check **"Authenticated app user"** instead: the
gateway verifies the token (roles, permissions, verified email, guests) and a function behind the endpoint receives
`event.user`.

## API reference

### `TokenVerifier`

| Method | |
|---|---|
| `__construct(string $issuer, string\|array $clientIds, array $options = [])` | options: `transport`, `httpClient` + `requestFactory` + `streamFactory`, `jwksUri`, `cache`, `cacheTtl` (600), `leeway` (60), `refetchInterval` (30), `clock` |
| `verify(?string $token): AppUser` | verifies an access token |
| `verifyIdToken(?string $idToken, ?string $nonce = null): array` | verifies an ID token (`typ: JWT`) and its nonce, returns its claims |
| `issuer()`, `clientIds()` | configuration |

### `AppUser`

Readonly properties `id`, `poolId`, `clientId`, `email`, `emailVerified`, `anonymous`, `orgId`, `roles`,
`permissions`, `attributes`, `sessionId`, `amr`, `claims` (raw); `hasRole(string)`, `hasPermission(string)`.

### `Middleware\RequireAppUser`

`__construct(TokenVerifier, ResponseFactoryInterface, StreamFactoryInterface, array $options)`, `process()` (PSR-15),
`allowed(AppUser): bool`, static `bearer(string $authorizationHeader): ?string`.

### `OidcWebClient`

| Method | |
|---|---|
| `__construct($issuer, $clientId, $clientSecret, $redirectUri, $options)` | options: `authMethod` (`client_secret_basic` default, `client_secret_post`), `scope`, `verifier`, transport/cache options |
| `authorizationUrl(array $options = []): AuthorizationRequest` | `provider`, `orgId`, `prompt`, `screenHint`, `loginHint`, `maxAge`, `scope`, `uiLocales`, `redirectUri` → `url` + `transaction` |
| `handleCallback(array $params, AuthTransaction\|array $tx): TokenSet` | checks and exchanges the code; `idTokenClaims` verified |
| `refresh(string $refreshToken, ?string $orgId = null): TokenSet` | the refresh token rotates: store the new one |
| `revoke(string $refreshToken): void` | RFC 7009 |
| `userinfo(string $accessToken): array` | OIDC userinfo |
| `logoutUrl(?string $idTokenHint, ?string $postLogoutRedirectUri, ?string $state): string` | end session |
| `verifier()`, `issuer()`, `clientId()` | |

`AuthTransaction` (`state`, `nonce`, `codeVerifier`, `redirectUri`, `createdAt`; `toArray()`, `fromArray()`,
`codeChallenge()`), `AuthorizationRequest` (`url`, `transaction`), `TokenSet` (`accessToken`, `tokenType`,
`expiresIn`, `expiresAt`, `scope`, `refreshToken`, `refreshExpiresIn`, `idToken`, `idTokenClaims`, `org`, `raw`).

### `Client`

| Method | |
|---|---|
| `__construct(string $issuer, string $clientId, array $options = [])` | options: `redirectUri`, `storage`, `storageKey`, `clientSecret` (web/backend only), `authMethod`, `lock`, `verifier`, transport/cache options, `clock` |
| `config()` | the pool's public configuration |
| `currentUser()`, `currentOrg()`, `accessTokenClaims()` (unverified), `isSignedIn()`, `idToken()` | state |
| `onAuthStateChanged(callable $listener): Closure` | called now and at each change with `(?array $user, ?array $org)`; returns the unsubscribe closure |
| `getAccessToken(): string`, `refresh(?string $orgId = null): string` | single-flight renewal |
| `fetch($method, $url, $headers, $body): HttpResponse`, `authorizeRequest(RequestInterface)` | your API with the bearer |
| `signUp($email, $password, $displayName, $locale, $orgId): Outcome` | |
| `signInWithPassword($email, $password, $orgId): Outcome` | |
| `sendEmailCode($email)`, `signInWithEmailCode($email, $code, $token, $orgId): Outcome` | |
| `signInAnonymously(): Outcome` | guest account |
| `verifyMfa($mfaToken, $code): Outcome`, `enrollMfa(?$mfaToken)`, `confirmMfa($code, ?$mfaToken)`, `disableMfa($code)` | two-step |
| `sendPasswordReset($email)`, `resetPassword($newPassword, $token, $email, $code)`, `changeForcedPassword($changeToken, $newPassword)` | passwords |
| `verifyEmail($token, $email, $code)`, `resendVerification()` | email verification |
| `me()`, `updateProfile($displayName, $photoUrl, $locale)`, `changePassword($new, $current)` (clears the session), `changeEmail($new)`, `confirmEmailChange($code, $token)`, `upgradeAnonymous($email, $password)`, `deleteAccount($password)` (clears) | the user |
| `signOut(bool $everywhere = false)` | server (best effort) + local |
| `organizations()`, `createOrganization($name)`, `switchOrganization($orgId)`, `members($orgId, $q, $skip, $limit)`, `addMember($orgId, $email, $displayName, $password, $roles)`, `setMemberRoles($orgId, $userId, $roles)`, `removeMember($orgId, $userId)` | B2B |
| `buildAuthorizationRequest(array $options): AuthorizationRequest` | hosted page; the transaction is kept in the storage |
| `handleRedirectCallback(string\|array $urlOrParams): ?array` | completes it, returns the user |
| `buildLogoutUrl($postLogoutRedirectUri, $state)`, `signOutRedirect($postLogoutRedirectUri, $state): string` | end session (the second also clears locally) |

Storage: `Storage\Storage` (`get`, `set`, `remove`), `Storage\MemoryStorage` (default), `Storage\SessionStorage`
(PHP session). The session is JSON `{accessToken, refreshToken, idToken, expiresAt (epoch ms), user, org}` under
`openback.auth.<clientId>`. To keep it in a file, a database or Redis, implement the three methods.

Locks: `Lock\RefreshLock` (`synchronized($name, $callable)`), `Lock\InProcessLock` (default), `Lock\FileLock`.

HTTP: `Http\HttpTransport` (`send($method, $url, $headers, $body): HttpResponse`), `Http\CurlTransport`,
`Http\Psr18Transport`. JWKS cache: `Cache\JwksCache`, `Cache\Psr16JwksCache`, `Cache\ApcuJwksCache`,
`Cache\MemoryJwksCache`.

## Outcomes and errors

Sign-up and sign-in methods return an `Outcome`: `status` (`OutcomeStatus::Ok`, `VerificationRequired`, `MfaRequired`,
`MfaEnrollRequired`, `PasswordChangeRequired`, `Unknown`), `rawStatus`, `user`, `org`, `mfaToken`, `changeToken`,
`raw`. The session is kept only on `Ok`.

Every error is an `AppAuthException` with `status` (HTTP status; 0 for a network error), `errorCode` and `detail`;
`getMessage()` is the pool's message and `getCode()` the status. (`errorCode` is the spec's `code`: PHP's
`Exception::$code` is an integer.) Codes of the pool: `invalid_credentials` (401), `too_many_requests` (429),
`weak_password` (422, `detail['problems']`), `email_in_use` (409), `invalid_code`, `method_disabled`,
`signup_disabled`, `origin_not_allowed` (403), `token_expired` / `token_invalid` / `token_missing` / `token_revoked` /
`token_other_app` (401), `invalid_refresh_token` (401), `not_b2b` (404), `org_creation_disabled`, `not_org_admin`,
`owners_only`, `not_a_member` (403); OAuth codes at the token endpoint (`invalid_grant`, `invalid_client`,
`slow_down`); `http_<status>` otherwise. SDK codes: `network_error`, `not_signed_in`, `invalid_state`,
`invalid_issuer`, `invalid_nonce`, `invalid_at_hash`, `missing_id_token`, `jwks_unavailable` (503).
`endsSession()` tells whether the local session was cleared (a refused token or refresh token).

## Security notes

- **Never log** tokens, authorization codes, client secrets or passwords (the SDK does not).
- Keep the **client secret** on the server only (environment variable, secret store) — never in a browser or a
  mobile app (those use `spa` / `native` apps without secret).
- Keep the hosted sign-in **transaction server-side** (PHP session, cache keyed by an HttpOnly cookie). State, nonce
  and the PKCE verifier come from `random_bytes()`; state is compared in constant time; `iss` is checked (RFC 9207);
  the ID token's signature, audience, nonce and `at_hash` are verified. PKCE S256 is always sent, also by
  confidential clients.
- **Refresh tokens rotate** and a reused one revokes the whole session: the Client refreshes one at a time, stores the
  new refresh token at once, and never retries a refresh after a network error. When several processes share one
  stored session, pass a `RefreshLock` (`FileLock`, or your own on Redis / the database).
- Access tokens are short-lived and **cannot be revoked** before expiry.
- `SessionStorage` keeps tokens in the server-side PHP session: use secure, HttpOnly session cookies.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 GexyLab and the OpenBack contributors.
