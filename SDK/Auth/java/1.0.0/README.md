# openback-app-auth-java

Java SDK for the OpenBack **App authenticator** (users-service user pools): sign users in from desktop/CLI apps and
servers, and verify the pool's access tokens in your Java backend (plain Servlet or Spring Boot 3).

Version **1.0.0** · License **MIT** · groupId `io.openback`

| Artifact | What |
|---|---|
| `io.openback:openback-app-auth-java` | Client (`AppAuthClient`), hosted sign-in helpers (`LoopbackSignIn`), `TokenVerifier` + `AppUser`, `OidcWebClient`, Jakarta Servlet `RequireAppUserFilter`. Java package `io.openback.appauth`. |
| `io.openback:openback-app-auth-java-spring-boot-starter` | Spring Boot 3 auto-configuration (`openback.app-auth.*`), Spring Security filter + `AuthenticationProvider`, authorities `ROLE_<role>` / `PERM_<permission>`. Java package `io.openback.appauth.spring`. |

Maven/Gradle artifact IDs use the base name `openback-app-auth-java`; Java packages cannot contain hyphens, so the code
lives in `io.openback.appauth`.

## 1. Requirements

- `openback-app-auth-java`: Java **11+** (uses `java.net.http.HttpClient`). One dependency: `jackson-databind` 2.17.
  ES256 is implemented with `java.security` (no JOSE library). `RequireAppUserFilter` needs a Jakarta Servlet 5+
  container (`jakarta.servlet-api` is `compileOnly`). `LoopbackSignIn` uses `jdk.httpserver` and `java.desktop`
  (standard JDK modules).
- Spring Boot starter: Java **17+**, Spring Boot **3.x** (built against 3.3.5), Spring Security 6.
- An OpenBack user pool and an app registered in it.

## 2. Installation

Once published to Maven Central:

```kotlin
// Gradle (Kotlin DSL)
dependencies {
    implementation("io.openback:openback-app-auth-java:1.0.0")
    // Spring Boot 3 API:
    implementation("io.openback:openback-app-auth-java-spring-boot-starter:1.0.0")
}
```

```xml
<dependency>
  <groupId>io.openback</groupId>
  <artifactId>openback-app-auth-java</artifactId>
  <version>1.0.0</version>
</dependency>
```

From this repository (`SDK/Auth/java/1.0.0` of https://github.com/GexyLab/openback-plugins-community):

```bash
cd SDK/Auth/java/1.0.0
./gradlew build                 # compile + tests + jars (build/libs of each module)
./gradlew publishToMavenLocal   # install 1.0.0 into ~/.m2, then use the coordinates above with mavenLocal()
```

## 3. Register your app in the pool

In the portal: the pool's **Apps** tab. The client ID (`uapp_...`) is public.

| Your app | Kind | Register |
|---|---|---|
| Desktop / CLI (`AppAuthClient`, `LoopbackSignIn`) | `native` | redirect URI `http://127.0.0.1:<port>/callback` exactly (pick a fixed port: redirect URIs must match exactly; `http://` is accepted only for localhost/127.0.0.1) |
| Server-side web app with sessions (`OidcWebClient`) | `web` | redirect URI(s) such as `https://app.example.com/callback`, post-logout redirect URIs; keep the client secret in a secret store |
| Backend calling the JSON API (`AppAuthClient`) | `backend` | no Origin is sent; a client secret only for the OIDC code exchange |
| An API that only **verifies** tokens (`TokenVerifier`, filter, starter) | — | nothing: accept the client IDs of the apps that call it |

## 4. Quick start

### Sign in with a password (incl. two-step verification)

```java
AppAuthClient auth = AppAuthClient.builder("https://api.example.com/gateway/shop/auth/main", "uapp_...")
        .storage(myStorage)                                    // default: in memory
        .build();
auth.onAuthStateChanged((user, org) -> render(user, org));     // called now and at every change

AuthOutcome res = auth.signInWithPassword(email, password);
switch (res.getStatus()) {
    case OK: break;
    case MFA_REQUIRED: res = auth.verifyMfa(res.getMfaToken(), askCode()); break;
    case MFA_ENROLL_REQUIRED: {
        MfaEnrollment e = auth.enrollMfa(res.getMfaToken());   // show e.getOtpauthUri() as a QR code
        res = auth.confirmMfa(askCode(), res.getMfaToken()).getOutcome();
        break;
    }
    case PASSWORD_CHANGE_REQUIRED: auth.changeForcedPassword(res.getChangeToken(), newPassword); break;
    case VERIFICATION_REQUIRED: tellUserToCheckInbox(); break;
    default: break;
}
```

### Hosted sign-in page (desktop: system browser + loopback)

```java
try (LoopbackSignIn loopback = LoopbackSignIn.start(53682, "/callback")) {
    PoolUser user = loopback.signIn(auth, new AuthorizationOptions().provider("uprov_google"), Duration.ofMinutes(5));
}
```

Low level (any redirect handling): `AuthorizationRequest req = auth.buildAuthorizationRequest(options)` → open
`req.getUrl()` → `auth.handleRedirectCallback(callbackUrl)`. The state, nonce and PKCE verifier are kept in the storage
under `openback.auth.<clientId>.pkce`, so the callback can be completed by a new process.

### Call your API

```java
HttpResponse<String> res = auth.send(HttpRequest.newBuilder(URI.create("https://api.example.com/gateway/shop/orders")),
        HttpResponse.BodyHandlers.ofString());                 // adds Authorization: Bearer <access token>
String token = auth.getAccessToken();                          // or take the token yourself
```

Async: `auth.getAccessTokenAsync()`, `auth.sendAsync(...)`, and `auth.async(() -> auth.me())` for any call (the
client's executor: a pool of daemon threads, or `Builder.executor(...)`).

## 5. Server-side verification and framework integration

### TokenVerifier (any Java backend)

```java
TokenVerifier verifier = TokenVerifier.builder("https://api.example.com/gateway/shop/auth/main")
        .clientIds("uapp_web", "uapp_android")                 // accepted audiences
        .build();                                              // leeway 60 s, JWKS cache 10 min
AppUser user = verifier.verify(bearerToken);                   // TokenVerificationException (401, or 503 jwks_unavailable)
user.getId(); user.getOrgId(); user.hasRole("admin"); user.hasPermission("invoices.read");   // "*" grants all
```

Checks: signature **ES256 only** (`none`, HS*, RS* refused), header `typ` `at+jwt` (or `application/at+jwt`), `iss`
exact, `aud` one of the client IDs, `exp` / `nbf` / `iat` with leeway. JWKS from `<issuer>/.well-known/jwks.json`,
cached 10 minutes, refetched on an unknown `kid` at most once every 30 seconds. Verification is local: no call to
OpenBack. **Access tokens cannot be revoked before they expire** (the pool's default lifetime is 15 minutes).

### Jakarta Servlet

```java
FilterRegistration.Dynamic f = servletContext.addFilter("appAuth",
        new RequireAppUserFilter(verifier, AppUserRequirements.defaults().requireRoles("admin").requirePermissions("invoices.read")));
f.addMappingForUrlPatterns(null, false, "/api/*");
// in a servlet: AppUser user = RequireAppUserFilter.currentUser(request);   (attribute AppUser.REQUEST_ATTRIBUTE)
```

Missing/invalid token → **401** `WWW-Authenticate: Bearer error="invalid_token"`, `{"error":"invalid_token"}`;
requirements not met → **403** `{"error":"insufficient_scope"}`. Requirements: `requireRoles` (any of),
`requirePermissions` (all of), `requireVerifiedEmail` (default false), `allowAnonymous` (default false: guest tokens
refused).

### Spring Boot 3

```properties
openback.app-auth.issuer=https://api.example.com/gateway/shop/auth/main
openback.app-auth.client-ids=uapp_web,uapp_android
openback.app-auth.require-verified-email=false
openback.app-auth.allow-anonymous=false
# openback.app-auth.leeway=60s  jwks-cache-ttl=10m  jwks-uri=...  default-security-filter-chain=true
```

Beans: `TokenVerifier`, `AppUserAuthenticationProvider`, `OpenBackAppAuthFilter`. Without a `SecurityFilterChain` of
yours the starter registers one (stateless, CSRF off, every request authenticated). With your own chain:

```java
@Bean
SecurityFilterChain api(HttpSecurity http, OpenBackAppAuthFilter appAuth) throws Exception {
    return http.csrf(AbstractHttpConfigurer::disable)
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(a -> a.requestMatchers("/admin/**").hasRole("admin")
                                     .requestMatchers("/invoices/**").hasAuthority("PERM_invoices.read")
                                     .anyRequest().authenticated())
        .addFilterBefore(appAuth, UsernamePasswordAuthenticationFilter.class)
        .exceptionHandling(e -> e.authenticationEntryPoint(OpenBackAppAuthFilter.ENTRY_POINT)
                                 .accessDeniedHandler(OpenBackAppAuthFilter.ACCESS_DENIED))
        .build();
}
```

The `Authentication` is an `AppUserAuthentication`: principal `AppUser` (`@AuthenticationPrincipal AppUser user`),
authorities `ROLE_<role>` and `PERM_<permission>`. A `"*"` permission becomes `PERM_*`; for wildcard-aware checks use
`@PreAuthorize("principal.hasPermission('reports.read')")`.

**Alternative: Spring Security's resource server.** Without this starter, `spring-boot-starter-oauth2-resource-server`
works too:

```properties
spring.security.oauth2.resourceserver.jwt.jwk-set-uri=https://api.example.com/gateway/shop/auth/main/.well-known/jwks.json
spring.security.oauth2.resourceserver.jwt.issuer-uri=https://api.example.com/gateway/shop/auth/main
spring.security.oauth2.resourceserver.jwt.audiences=uapp_web
spring.security.oauth2.resourceserver.jwt.jws-algorithms=ES256
```

Then map `roles`/`permissions` with a `JwtAuthenticationConverter` (Spring's default reads `scope`), and note that
Nimbus checks the `typ` header only if you configure `JwtTypeValidator`/a `JOSEObjectTypeVerifier` for `at+jwt`.

### Web apps with a server (OIDC, confidential)

```java
OidcWebClient oidc = OidcWebClient.builder(issuer, "uapp_web", secretFromVault, "https://app.example.com/callback").build();
AuthorizationRequest tx = oidc.authorizationUrl(new AuthorizationOptions());    // store tx.toJson() in the server session
OidcWebClient.Result r = oidc.handleCallback(callbackParams, tx);               // tokens + verified ID token claims
oidc.refresh(refreshToken); oidc.revoke(refreshToken); oidc.userinfo(accessToken); oidc.logoutUrl(idToken, postLogout, state);
```

`client_secret_basic` by default, `.clientAuthMethod(ClientAuthMethod.CLIENT_SECRET_POST)` as an option.

### No SDK: the gateway's check

An API behind the OpenBack gateway can use the endpoint check **"Authenticated app user"** (pool, required roles /
permissions, verified email, guests): the gateway verifies the token and a function behind the endpoint receives
`event.user`. No SDK is needed in that case.

## 6. API reference

### `AppAuthClient` (`AppAuthClient.builder(issuer, clientId)`)

Builder: `redirectUri`, `storage`, `storageKey` (default `openback.auth.<clientId>`), `httpClient`, `clientSecret`
(web/backend only), `timeout` (30 s), `executor`, `clock`.

| Method | |
|---|---|
| `config()` | `GET /config`: methods, providers, password policy, mode, branding |
| `getCurrentUser()`, `getCurrentOrg()`, `getAccessTokenClaims()`, `isSignedIn()` | current state (claims decoded, not verified) |
| `onAuthStateChanged(listener)` | listener `(user, org)`, called immediately; returns a `Subscription` (`close()`) |
| `getAccessToken()`, `getAccessTokenAsync()` | a valid access token (refreshed if it expires within 60 s) |
| `refresh()`, `refresh(orgId)`, `refreshAsync(orgId)` | renew now (single-flight) |
| `authorize(builder)`, `send(builder, handler)`, `sendAsync(builder, handler)` | your requests with `Authorization: Bearer` |
| `async(supplier)` | run any call on the client's executor |
| `signUp(email, password[, displayName, locale, orgId])` | outcome |
| `signInWithPassword(email, password[, orgId])` | outcome |
| `sendEmailCode(email)` / `signInWithEmailCode(email, code[, orgId])` / `signInWithEmailLinkToken(token, orgId)` | one-time code sign-in |
| `signInAnonymously()` | guest account |
| `verifyMfa(mfaToken, code)` | second step (TOTP or recovery code) |
| `enrollMfa()` / `enrollMfa(mfaToken)` | `MfaEnrollment` (secret, otpauth URI) |
| `confirmMfa(code)` / `confirmMfa(code, mfaToken)` | `MfaConfirmation` (recovery codes, outcome) |
| `disableMfa(code)` | turn TOTP off |
| `sendPasswordReset(email)` | always `{status: "sent"}` |
| `resetPasswordWithToken(token, newPassword)` / `resetPasswordWithCode(email, code, newPassword)` | reset |
| `changeForcedPassword(changeToken, newPassword)` | continue `PASSWORD_CHANGE_REQUIRED` |
| `verifyEmailWithToken(token)` / `verifyEmailWithCode(email, code)` / `resendVerification()` | email verification |
| `me()` / `updateProfile(new ProfileUpdate().displayName(..).photoUrl(..).locale(..))` | the user |
| `changePassword(current, next)` | ends every session (clears the local one) |
| `changeEmail(newEmail)` / `confirmEmailChangeWithCode(code)` / `confirmEmailChangeWithToken(token)` | change of address |
| `upgradeAnonymous(email, password)` | guest → real account (same id) |
| `deleteAccount(password)` | deletes, clears the session |
| `signOut()` / `signOut(everywhere)` | best-effort server call, always clears locally |
| `organizations()`, `createOrganization(name)`, `switchOrganization(orgId)` | B2B |
| `members(orgId[, q, skip, limit])`, `addMember(orgId, email, displayName, password, roles)`, `setMemberRoles(orgId, userId, roles)`, `removeMember(orgId, userId)` | organization admins |
| `buildAuthorizationRequest(options)` | hosted sign-in URL + transaction (persisted) |
| `handleRedirectCallback(url)` | checks error/state/iss, exchanges the code, checks the nonce, returns the user |
| `buildLogoutUrl(postLogoutRedirectUri, state)` / `signOutRedirect(postLogoutRedirectUri, state)` | end-session URL (the latter also signs out) |

`AuthorizationOptions`: `redirectUri`, `scope` (default `openid profile email`), `provider`, `orgId`, `prompt`
(`none`/`login`), `screenHint` (`signup`), `loginHint`, `maxAge`, `uiLocales`.

`LoopbackSignIn`: `start(port, path)`, `getRedirectUri()`, `signIn(client, options, timeout[, browserOpener])`,
`awaitCallback(timeout)`, `openWithDesktop(url)`, `close()`.

`TokenStorage`: `get(key)`, `set(key, value)`, `remove(key)`; `InMemoryTokenStorage` is the default. Stored JSON:
`{accessToken, refreshToken, idToken, expiresAt (epoch ms), user, org}` under `openback.auth.<clientId>`. For a desktop
app plug a file/keychain store (see `examples/desktop/FileTokenStorage.java`); on a server, the visitor's session or a
database row.

### Server side

| Class | |
|---|---|
| `TokenVerifier.builder(issuer)` | `.clientIds(...)`, `.leeway(Duration)`, `.jwksCacheTtl(Duration)`, `.jwksUri(url)`, `.httpClient(..)`, `.timeout(..)`, `.clock(..)`; `verify(token)` → `AppUser`; `verifyIdToken(idToken, nonce)` → claims; `clearCache()` |
| `AppUser` | `getId`, `getPoolId`, `getClientId`, `getEmail`, `isEmailVerified`, `isAnonymous`, `getOrgId`, `getRoles`, `getPermissions`, `getAttributes`, `getSessionId`, `getAmr`, `getClaims`, `hasRole`, `hasPermission` |
| `AppUserRequirements` | `defaults()`, `requireRoles(..)`, `requirePermissions(..)`, `requireVerifiedEmail(b)`, `allowAnonymous(b)`, `isSatisfiedBy(user)` |
| `RequireAppUserFilter` | `new RequireAppUserFilter(verifier[, requirements])`, `currentUser(request)`, `bearerToken(header)` |
| `OidcWebClient.builder(issuer, clientId, secret, redirectUri)` | `authorizationUrl(options)`, `handleCallback(params \| url, tx)`, `refresh(rt[, orgId])`, `revoke(rt)`, `userinfo(at)`, `logoutUrl(idTokenHint, postLogoutRedirectUri, state)` |
| Spring: `OpenBackAppAuthFilter`, `AppUserAuthenticationProvider`, `AppUserAuthentication`, `OpenBackAppAuthProperties` | see section 5 |

## 7. Outcomes and errors

`AuthOutcome.getStatus()`: `OK` (session kept), `VERIFICATION_REQUIRED`, `MFA_REQUIRED` (`getMfaToken()`),
`MFA_ENROLL_REQUIRED` (`getMfaToken()`), `PASSWORD_CHANGE_REQUIRED` (`getChangeToken()`), `UNKNOWN` (see
`getRawStatus()`). The tokens are never exposed on outcomes.

Errors are `AppAuthException` (unchecked): `getStatus()` (HTTP status, 0 for local/network failures), `getCode()`
(`invalid_credentials`, `too_many_requests`, `weak_password` — `getDetail().get("problems")` —, `email_in_use`,
`invalid_code`, `method_disabled`, `signup_disabled`, `origin_not_allowed`, `token_expired`, `token_revoked`,
`invalid_refresh_token`, `not_b2b`, `not_org_admin`, `owners_only`, `not_a_member`...; OAuth errors at `/token`:
`invalid_grant`, `invalid_client`, `slow_down`; `http_<status>` when the answer has no code; local: `network_error`,
`interrupted`, `not_signed_in`, `invalid_state`, `invalid_issuer`, `invalid_nonce`, `no_pending_request`, `timeout`),
`getMessage()`, `getDetail()`. A 401 `token_*` on a signed-in call or `invalid_refresh_token` clears the local session
and notifies the listeners (`isSessionEnded()`). `TokenVerificationException` (a subclass) reports why a token was
refused (`token_expired`, `token_invalid_signature`, `token_invalid_audience`, ...).

## 8. Security notes

- **Storage**: the default storage is in memory. A persistent store holds secrets (refresh token): encrypt it or use the
  OS keychain, restrict file permissions, write atomically. Never log tokens, codes, secrets or passwords; the SDK's
  `toString()` methods redact them.
- **Refresh rotation**: refresh tokens rotate at every use and a reused one revokes the whole session. The client runs
  one refresh at a time (a lock; threads waiting get the result of the refresh in progress), stores the new token
  before returning, and never retries a refresh after a network error (the error is surfaced; the next call tries again
  with the stored token). Several processes sharing one storage must not refresh concurrently.
- **PKCE, state, nonce**: always sent (S256, 64-character verifier from `SecureRandom`); `state` compared in constant
  time; `iss` checked when present (RFC 9207); the ID token's `nonce` checked.
- **Client secrets** only in server-side apps (`web`, `backend`), never in desktop or mobile apps.
- **Verification**: only ES256; JWKS fetched from the configured issuer only; access tokens are valid until they expire
  (keep lifetimes short).
- **Loopback redirect**: the listener binds 127.0.0.1 only, answers one callback, and should be closed right after.

## 9. Examples

`examples/` (not part of the build): `desktop/DesktopSignIn.java` (password + MFA, hosted page via loopback, API call),
`desktop/FileTokenStorage.java`, `spring-boot-api/` (starter with roles and permissions), `servlet/` (filter and a
confidential web app with `OidcWebClient`).

## 10. License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 GexyLab and the OpenBack contributors.
