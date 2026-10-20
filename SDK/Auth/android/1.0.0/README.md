# openback-app-auth-android

Native Android SDK (Kotlin) for the OpenBack **App authenticator** (users-service user pools): sign users in with your
own screens or with the pool's hosted page in a Custom Tab, keep the session encrypted with the Android Keystore, and
call your API with the access token.

Version **1.0.0** · License **MIT** · `io.openback:openback-app-auth-android` · namespace/package
`io.openback.appauth.android` (Java/Kotlin packages cannot contain hyphens).

## 1. Requirements

- Android **minSdk 23** (Android 6.0), compileSdk **34+** (built with 35), Kotlin 2.0+ / Java 11 bytecode.
- Dependencies (transitive): OkHttp 4.12, kotlinx-coroutines 1.9, kotlinx-serialization-json 1.7, androidx.activity
  1.9 (`ActivityResultContract`), androidx.browser 1.8 (Custom Tabs).
- A browser on the device for the hosted page (Chrome or any Custom Tabs provider; any browser as a fallback).

## 2. Installation

Once published to Maven Central:

```kotlin
dependencies {
    implementation("io.openback:openback-app-auth-android:1.0.0")
}
```

From this repository (`SDK/Auth/android/1.0.0` of https://github.com/GexyLab/openback-plugins-community): with the
Android SDK installed (`ANDROID_HOME` or `local.properties` `sdk.dir`),

```bash
cd SDK/Auth/android/1.0.0
./gradlew :openback-app-auth-android:assembleRelease          # AAR in openback-app-auth-android/build/outputs/aar
./gradlew :openback-app-auth-android:publishToMavenLocal      # then mavenLocal() + the coordinates above
```

or include the module in your build (`include(":openback-app-auth-android")` with `projectDir` pointing here).

## 3. Register your app in the pool

In the portal, the pool's **Apps** tab: add an app of kind **`native`** (public client, PKCE, no secret) and register
the redirect URI **`com.example.app:/oauth2redirect`** (a custom scheme you own — use your application id) exactly; add
`com.example.app:/signed-out` (for example) as a **post-logout redirect URI** if you use the hosted sign-out. Redirect
URIs must match exactly. Then set the scheme in the app module:

```kotlin
android {
    defaultConfig {
        manifestPlaceholders["openbackAppAuthRedirectScheme"] = "com.example.app"
    }
}
```

The library's manifest declares `RedirectReceiverActivity` with an intent filter on that scheme (like AppAuth's
`appAuthRedirectScheme`): nothing else to add to your manifest. An `https` App Link redirect is also possible: declare
your own `<intent-filter android:autoVerify="true">` for `io.openback.appauth.android.RedirectReceiverActivity` in your
manifest. The library adds the `INTERNET` permission and the `<queries>` needed to find a browser on Android 11+.

**Backups**: the session is encrypted with a key that never leaves the device; exclude the preferences file
`openback_app_auth.xml` from Auto Backup (`examples/backup_rules.xml`).

## 4. Quick start

```kotlin
class App : Application() {
    val auth by lazy {
        OpenBackAuth.create(this, "https://api.example.com/gateway/shop/auth/main", "uapp_...",
            redirectUri = "com.example.app:/oauth2redirect")
    }
}

// UI: who is signed in
lifecycleScope.launch {
    auth.authState.collect { state ->
        when (state) {
            is AuthState.SignedIn -> showHome(state.user)
            AuthState.SignedOut -> showSignIn()
        }
    }
}
```

### Your own screens: password + two-step verification

```kotlin
when (val res = auth.signInWithPassword(email, password)) {
    is AuthOutcome.SignedIn -> Unit                                   // session kept, authState updated
    is AuthOutcome.MfaRequired -> auth.verifyMfa(res.mfaToken, code)
    is AuthOutcome.MfaEnrollRequired -> {
        val e = auth.enrollMfa(res.mfaToken)                          // QR code of e.otpauthUri
        auth.confirmMfa(code, res.mfaToken)                           // .recoveryCodes: show once
    }
    is AuthOutcome.PasswordChangeRequired -> auth.changeForcedPassword(res.changeToken, newPassword)
    is AuthOutcome.VerificationRequired -> showCheckYourInbox()
    is AuthOutcome.Unknown -> Unit
}
```

### Hosted page (Custom Tabs, PKCE)

```kotlin
private val signIn = registerForActivityResult(OpenBackSignInContract()) { result ->
    when (result) {
        is BrowserResult.Redirected -> lifecycleScope.launch { auth.handleRedirectCallback(result.uri) }
        BrowserResult.Cancelled -> Unit
        BrowserResult.NoBrowser -> showInstallABrowser()
    }
}

lifecycleScope.launch {
    signIn.launch(auth.buildAuthorizationRequest(AuthorizationOptions(provider = "uprov_google")))
}

// sign-out, also ending the hosted page's browser session
private val signOut = registerForActivityResult(OpenBackSignOutContract()) { }
lifecycleScope.launch { signOut.launch(auth.signOutRedirect(postLogoutRedirectUri = "com.example.app:/signed-out")) }
```

`buildAuthorizationRequest` keeps state, nonce and PKCE verifier in the storage (`openback.auth.<clientId>.pkce`), so
`handleRedirectCallback` works even if the process was restarted while the tab was open.

### Calling your API

```kotlin
val api = OkHttpClient.Builder()
    .addInterceptor(OpenBackAuthInterceptor(auth) { it.url.host == "api.example.com" })   // Bearer token, your host only
    .authenticator(OpenBackAuthAuthenticator(auth))                                         // one renewal + retry on 401
    .build()
// or: val token = auth.getAccessToken()   (suspend)
```

Do not add the interceptor to the `OkHttpClient` passed to `OpenBackAuth` itself. Your API verifies the token with a
server SDK (`TokenVerifier`), or sits behind the OpenBack gateway with the endpoint check **"Authenticated app user"**
(no SDK needed there; functions receive `event.user`).

## 5. Server-side verification

This is a client SDK. Verify the tokens in your backend with a server SDK of this repository (Java, Node, Python,
PHP, C#...) or the gateway check above. Register the backend's accepted client IDs (`aud`) = this app's client ID.

## 6. API reference

`OpenBackAuth(issuer, clientId, Options(redirectUri, storage, storageKey, httpClient, clientSecret, ioDispatcher, clock))`
or `OpenBackAuth.create(context, issuer, clientId, redirectUri, httpClient)` (Keystore storage). All network methods are
`suspend` and main-safe (they switch to the IO dispatcher).

| Member | |
|---|---|
| `issuer`, `clientId` | the pool address (no trailing slash) and the app |
| `authState: StateFlow<AuthState>` | `SignedOut` / `SignedIn(user, org)` |
| `currentUser`, `currentOrg`, `accessTokenClaims`, `isSignedIn` | current state (claims decoded, not verified) |
| `onAuthStateChanged(listener)` | `(PoolUser?, ActiveOrg?) -> Unit`, called immediately; returns the unsubscribe function |
| `getAccessToken()` | a valid token (refreshed if it expires within 60 s) |
| `refresh(orgId = null)` | renew now (single-flight, never cancelled half-way) |
| `config()` | methods, providers, password policy, mode, branding |
| `signUp(email, password, displayName?, locale?, orgId?)` | `AuthOutcome` |
| `signInWithPassword(email, password, orgId?)` | `AuthOutcome` |
| `sendEmailCode(email)` / `signInWithEmailCode(email, code, orgId?)` / `signInWithEmailLinkToken(token, orgId?)` | one-time codes |
| `signInAnonymously()` | guest account |
| `verifyMfa(mfaToken, code)` | second step |
| `enrollMfa(mfaToken?)` / `confirmMfa(code, mfaToken?)` / `disableMfa(code)` | TOTP |
| `sendPasswordReset(email)` / `resetPassword(newPassword, token?, email?, code?)` | reset |
| `changeForcedPassword(changeToken, newPassword)` | continue `PasswordChangeRequired` |
| `verifyEmail(token?, email?, code?)` / `resendVerification()` | email verification |
| `me()` / `updateProfile(displayName?, photoUrl?, locale?)` | the user |
| `changePassword(currentPassword, newPassword)` | ends every session (clears the local one) |
| `changeEmail(newEmail)` / `confirmEmailChange(code?, token?)` | change of address |
| `upgradeAnonymous(email, password)` | guest → real account |
| `deleteAccount(password?)` | deletes, clears the session |
| `signOut(everywhere = false)` | best-effort server call, always clears locally |
| `organizations()`, `createOrganization(name)`, `switchOrganization(orgId)` | B2B |
| `members(orgId, q, skip, limit)`, `addMember(orgId, email, displayName?, password?, roles)`, `setMemberRoles(orgId, userId, roles)`, `removeMember(orgId, userId)` | organization admins |
| `buildAuthorizationRequest(AuthorizationOptions)` | `AuthorizationRequest(url, state, nonce, codeVerifier, redirectUri)`, persisted |
| `handleRedirectCallback(uri)` | checks error/state/iss, exchanges the code, checks the nonce → `PoolUser?` |
| `buildLogoutUrl(postLogoutRedirectUri?, state?)` / `signOutRedirect(postLogoutRedirectUri?, state?, everywhere)` | end-session URL (the latter also signs out) |

`AuthorizationOptions(redirectUri, scope = "openid profile email", provider, orgId, prompt, screenHint, loginHint,
maxAge, uiLocales)`.

Browser: `OpenBackSignInContract` (`AuthorizationRequest` → `BrowserResult`), `OpenBackSignOutContract` (URL →
`BrowserResult`), `BrowserResult.Redirected(uri) | Cancelled | NoBrowser`, `RedirectReceiverActivity`.

Storage: `TokenStorage` (`get`, `set`, `remove`), `KeystoreTokenStorage(context, prefsName = "openback_app_auth",
keyAlias = "io.openback.appauth.v1")`, `InMemoryTokenStorage`. Stored JSON: `{accessToken, refreshToken, idToken,
expiresAt (epoch ms), user, org}` under `openback.auth.<clientId>`.

OkHttp: `OpenBackAuthInterceptor(auth, shouldAuthorize)`, `OpenBackAuthAuthenticator(auth)`.

Models: `PoolUser`, `ActiveOrg`, `Organization`, `OrganizationList`, `Member`, `MemberPage`, `OrgRole`,
`MfaEnrollment`, `MfaConfirmation`, `LinkedProvider`.

## 7. Outcomes and errors

`AuthOutcome` is sealed: `SignedIn(user, org, recoveryCodes)`, `VerificationRequired`, `MfaRequired(mfaToken)`,
`MfaEnrollRequired(mfaToken)`, `PasswordChangeRequired(changeToken)`, `Unknown(status)`; each has `details` (the answer
without tokens). Only `SignedIn` keeps a session.

Errors are `AuthException(status, code, message, detail)`: the service's codes (`invalid_credentials`,
`too_many_requests`, `weak_password` with `detail.problems`, `email_in_use`, `invalid_code`, `method_disabled`,
`signup_disabled`, `token_expired`, `token_revoked`, `invalid_refresh_token`, `not_b2b`, `not_org_admin`, `owners_only`,
`not_a_member`...), OAuth errors of `/token` (`invalid_grant`, `invalid_client`, `slow_down`), `http_<status>` when the
answer has no code, and local codes (`network_error`, `not_signed_in`, `invalid_state`, `invalid_issuer`,
`invalid_nonce`, `invalid_id_token`, `no_pending_request`, `invalid_request`). A 401 `token_*` on a signed-in call or
`invalid_refresh_token` clears the session (`isSessionEnded`), and `authState` becomes `SignedOut`.

## 8. Security notes

- **Storage**: `KeystoreTokenStorage` encrypts every value with AES-256-GCM under a non-exportable Android Keystore key
  (hardware-backed where available), the entry name as associated data, written with `commit()` so a rotated refresh
  token is on disk before use. Undecryptable values (key lost) are dropped. `androidx.security:security-crypto`
  (EncryptedSharedPreferences) is deprecated and not used. Exclude the file from backups.
- **Refresh rotation**: refresh tokens rotate at every use and a reused one revokes the whole session. The SDK runs one
  refresh at a time (a `Mutex`; waiting callers get its result), makes it non-cancellable, stores the new token
  atomically, disables OkHttp's silent retries for its own calls, and never retries a refresh after a network error.
- **PKCE, state, nonce**: always sent (S256, 64-character verifier from `SecureRandom`); state compared in constant time;
  `iss` checked (RFC 9207); ID token nonce, issuer and audience checked. The redirect receiver only forwards the URI;
  the callback is accepted only if it matches the pending request.
- **No client secret** in a mobile app: register a `native` app.
- **Never log** tokens, codes, the PKCE verifier or passwords (`toString()` of the SDK's types redacts them). Restrict
  the interceptor to your API's hosts.
- Custom Tabs (not WebViews) are used for the hosted page, as RFC 8252 requires.

## 9. Examples

`examples/` (not part of the build): `SignInActivity.kt` (password, MFA, hosted sign-in and sign-out, `authState`),
`ApiClient.kt` (OkHttp), `app-build.gradle.kts` (manifest placeholder), `backup_rules.xml`.

## 10. License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 GexyLab and the OpenBack contributors.
