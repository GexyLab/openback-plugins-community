# openback-app-auth-flutter

The Flutter client of OpenBack's **App authenticator** (users-service user pools): sign-up, password, email code,
guest and two-step sign-in with your own screens, the pool's hosted sign-in page (OpenID Connect + PKCE) for social
providers, secure token storage, single-flight token renewal and an authorized `http.Client` for your API.

- Version: **1.0.0**
- License: **MIT** (see `LICENSE`)
- Platforms: iOS, Android, web, macOS, Windows, Linux

> **Package name.** The base name of every OpenBack App Auth package is `openback-app-auth-<platform>`. pub.dev
> forbids hyphens in package names, so this package is **`openback_app_auth_flutter`** (base name
> `openback-app-auth-flutter`).

## 1. Requirements

- Dart **3.3+**, Flutter **3.19+**
- Dependencies: `http`, `crypto`, `flutter_secure_storage` (9.x), `flutter_web_auth_2` (3.1–4.x)
- Android minSdk **23** (EncryptedSharedPreferences), iOS **12+**, macOS **10.15+**
- An OpenBack user pool and an app registered in it (section 3)

## 2. Installation

Once published on pub.dev:

```yaml
dependencies:
  openback_app_auth_flutter: ^1.0.0
```

Until then, from this repository (path or git):

```yaml
dependencies:
  openback_app_auth_flutter:
    git:
      url: https://github.com/GexyLab/openback-plugins-community
      path: SDK/Auth/flutter/1.0.0
      ref: production
  # or, with a local checkout:
  # openback_app_auth_flutter:
  #   path: ../openback-plugins-community/SDK/Auth/flutter/1.0.0
```

```dart
import 'package:openback_app_auth_flutter/openback_app_auth_flutter.dart';
```

## 3. Register your app in the pool

In the OpenBack portal open the user pool, tab **Apps**, and add the app. Note the pool's address (the **issuer**,
e.g. `https://api.example.com/gateway/shop/auth/main`) and the app's **client ID** (`uapp_...`).

| Your Flutter target | App kind | Redirect address to register |
|---|---|---|
| iOS, macOS, Android | `native` | a custom scheme, e.g. `com.example.app:/oauth2redirect` |
| Windows, Linux | `native` | a loopback address, e.g. `http://localhost:43823/callback` (`http://` is accepted only for localhost) |
| Web | `spa` | the callback page, e.g. `https://app.example.com/auth.html`; add the site's origin (`https://app.example.com`) to **allowed origins** |

- Redirect addresses must match **exactly**. For `signOutWithHostedPage()` also add the address to the app's
  **post-logout redirect** list (by default the SDK uses the redirect address).
- A native app needs a redirect address only for the hosted page; the JSON API (your own screens) works without one.
- `native` and `spa` apps are public clients: no client secret, PKCE always (the SDK does it).

### Platform setup (hosted page)

The hosted page opens through [`flutter_web_auth_2`](https://pub.dev/packages/flutter_web_auth_2). The callback URL
scheme is taken from the redirect address (`com.example.app` above; `http://localhost:<port>` on Windows/Linux);
override it with `callbackUrlScheme:`.

**iOS** — nothing to add: `ASWebAuthenticationSession` catches the callback scheme itself (no `CFBundleURLTypes`
needed). iOS shows a "*App* wants to use *example.com* to sign in" prompt; `preferEphemeral: true` avoids it (and
shares no cookies with Safari).

**macOS** — as iOS. Enable the outgoing network entitlement (`com.apple.security.network.client`) and, for
`flutter_secure_storage`, the Keychain Sharing capability.

**Android** — declare the callback activity of `flutter_web_auth_2` with your scheme in
`android/app/src/main/AndroidManifest.xml` (inside `<application>`):

```xml
<activity
    android:name="com.linusu.flutter_web_auth_2.CallbackActivity"
    android:exported="true">
    <intent-filter android:label="flutter_web_auth_2">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="com.example.app" />
    </intent-filter>
</activity>
```

Also set `minSdkVersion 23` and exclude the secure storage from Android Auto Backup (`android:allowBackup="false"`,
or a `fullBackupContent` rule excluding `FlutterSecureStorage`), so a restored backup does not hold undecryptable data.

**Web** — host a callback page at the redirect address (same origin as the app). It hands the result back to the
app window; a ready one is in [`example/web/auth.html`](example/web/auth.html):

```html
<!DOCTYPE html>
<title>Signing in…</title>
<script>
  var message = { "flutter-web-auth-2": window.location.href };
  if (window.opener) { window.opener.postMessage(message, window.location.origin); window.close(); }
  else if (window.parent && window.parent !== window) { window.parent.postMessage(message, window.location.origin); }
  else { localStorage.setItem("flutter-web-auth-2", window.location.href); window.close(); }
</script>
```

On the web `SecureTokenStorage` keeps the session in WebCrypto-encrypted `localStorage` (flutter_secure_storage's
web implementation): it is readable by any script on your origin, as any browser storage is. Keep a strict CSP.

**Windows / Linux** — register `http://localhost:<port>/callback`; `flutter_web_auth_2` waits for the callback on that
loopback port. See its documentation for the desktop prerequisites (Linux: a webview/browser and `libsecret` for
`flutter_secure_storage`).

## 4. Quick start

```dart
final auth = OpenBackAppAuth(
  issuer: 'https://api.example.com/gateway/shop/auth/main',
  clientId: 'uapp_...',
  redirectUri: 'com.example.app:/oauth2redirect', // only for the hosted page
);
await auth.initialize(); // loads the stored session

auth.authStateChanges.listen((state) {
  // state.user == null: signed out
});
```

### Sign in with email and password (and the two-step branch)

```dart
var outcome = await auth.signInWithPassword(email: email, password: password);
if (outcome is MfaRequired) {
  outcome = await auth.verifyMfa(mfaToken: outcome.mfaToken, code: codeFromAuthenticatorApp);
}
switch (outcome) {
  case SignInOk(:final user):
    print('Hello ${user?.displayName}');
  case MfaRequired():
    // wrong code: ask again
  case MfaEnrollRequired(:final mfaToken):
    final enrollment = await auth.enrollMfa(mfaToken: mfaToken); // show enrollment.otpauthUri as a QR code
    final done = await auth.confirmMfa(firstCode, mfaToken: mfaToken); // done.recoveryCodes: show them once
  case PasswordChangeRequired(:final changeToken):
    await auth.changeForcedPassword(changeToken: changeToken, newPassword: newPassword); // then sign in again
  case VerificationRequired():
    // the pool emailed a code and a link: auth.verifyEmail(email: email, code: code), then sign in
}
```

### Sign in with the hosted page (social providers, the pool's forms)

```dart
try {
  final user = await auth.signInWithHostedPage();                       // the pool's page
  // await auth.signInWithHostedPage(provider: 'uprov_...');            // straight to Google, Microsoft...
  // await auth.signInWithHostedPage(screenHint: 'signup', uiLocales: 'it');
} on AppAuthException catch (e) {
  if (e.code != 'canceled') rethrow;                                    // the user closed the browser
}
```

The provider ids are in `(await auth.config()).providers`.

### Call your API

```dart
final api = auth.authorizedClient(hosts: {'api.example.com'}); // adds Authorization: Bearer <access token>
final res = await api.get(Uri.parse('https://api.example.com/gateway/shop/orders'));

// or by hand:
final token = await auth.getAccessToken(); // renewed when it expires in less than 60 s
```

Your API verifies the token: behind the OpenBack gateway with the endpoint check **"Authenticated app user"** (no
code; functions get `event.user`), or in your own server with an OpenBack server SDK (Node.js, Python, PHP, .NET,
Java, C++) or any JWT library (ES256, JWKS at `<issuer>/.well-known/jwks.json`, `iss`, `aud` = client ID, `exp`).

### Sign out

```dart
await auth.signOut();                    // revokes the refresh token, ends this session, clears locally
await auth.signOut(everywhere: true);    // ends every session of the user
await auth.signOutWithHostedPage();      // also ends the hosted page's browser session (cookie)
```

## 5. Server-side verification

This is a client SDK: it decodes the access token for display (`accessTokenClaims`) but never trusts it for
security decisions. Verify tokens on your server (see "Call your API" above).

## 6. API reference

Constructor: `OpenBackAppAuth({required issuer, required clientId, redirectUri, storage, storageKey, httpClient,
callbackUrlScheme, webAuthenticator, clock})`.

| Member | What it does |
|---|---|
| `initialize()` | Loads the stored session (every method also waits for it) |
| `currentUser`, `currentOrg`, `authState`, `isSignedIn` | The signed-in user, active organization (B2B), both, whether a session exists |
| `accessTokenClaims` | The access token's claims, decoded, not verified |
| `authStateChanges` | `Stream<AuthState>`: the current state, then every change |
| `onAuthStateChanged(listener)` | Same as a callback `(user, org)`; returns an unsubscribe function |
| `config()` | The pool's public settings (`PoolConfig`: methods, providers, password policy, mode, branding) |
| `getAccessToken()` | A valid access token (renewed if it expires within 60 s) |
| `refresh({orgId})` | Renews the tokens now (single-flight), optionally for another organization |
| `authorizedClient({inner, hosts})` | `http.Client` adding the Bearer token |
| `signUp({email, password, displayName, locale, orgId})` | Creates an account → `SignInOutcome` |
| `signInWithPassword({email, password, orgId})` | → `SignInOutcome` |
| `sendEmailCode(email)` | Emails a sign-in code |
| `signInWithEmailCode({email, code, token, orgId})` | → `SignInOutcome` |
| `signInAnonymously()` | Guest account → `SignInOutcome` |
| `verifyMfa({mfaToken, code})` | Second factor (TOTP or recovery code) → `SignInOutcome` |
| `enrollMfa({mfaToken})` | Starts a TOTP enrollment → `MfaEnrollment` (`secret`, `otpauthUri`) |
| `confirmMfa(code, {mfaToken})` | Confirms it → `MfaConfirmation` (`recoveryCodes`, `outcome`) |
| `disableMfa(code)` | Turns two-step verification off |
| `sendPasswordReset(email)` | Emails a reset code and link |
| `resetPassword({token \| email+code, newPassword})` | Sets a new password |
| `changeForcedPassword({changeToken, newPassword})` | Answers `PasswordChangeRequired` |
| `verifyEmail({token \| email+code})` | Verifies the address → `PoolUser?` |
| `resendVerification()` | Sends the verification email again |
| `me()` | The user, fresh (also updates `currentUser`) |
| `updateProfile({displayName, photoUrl, locale})` | → `PoolUser` |
| `changePassword({currentPassword, newPassword})` | Ends every session, clears the local one |
| `changeEmail(newEmail)` / `confirmEmailChange({code, token})` | Email change with a code sent to the new address |
| `upgradeAnonymous({email, password})` | Guest → real account (same id), tokens renewed |
| `deleteAccount({password})` | Deletes the account, clears the session |
| `signOut({everywhere})` | Best-effort server sign-out, always clears locally |
| `organizations()` | `OrganizationList` (`orgs`, `active`; B2C: empty) |
| `createOrganization(name)` | → `Organization` (the user is its owner) |
| `switchOrganization(orgId)` | New tokens for that organization → `ActiveOrg?` |
| `members(orgId, {q, skip, limit})` | → `MemberPage` (owners/admins) |
| `addMember(orgId, {email, displayName, password, roles})` | → `AddedMember` (may carry `temporaryPassword`) |
| `setMemberRoles(orgId, userId, roles)` / `removeMember(orgId, userId)` | Member management |
| `buildAuthorizationRequest({redirectUri, provider, orgId, prompt, screenHint, loginHint, maxAge, scope, uiLocales})` | Low level: `AuthorizationRequest` (`url`, `state`, `nonce`, `codeVerifier`, `redirectUri`), stored for the callback |
| `handleRedirectCallback(url)` | Low level: checks `error`, `state`, `iss`, exchanges the code, checks the ID token's `nonce` → `PoolUser?` |
| `signInWithHostedPage({provider, orgId, prompt, screenHint, loginHint, maxAge, scope, uiLocales, preferEphemeral})` | The whole hosted flow with `flutter_web_auth_2` |
| `buildLogoutUrl({postLogoutRedirectUri, state})` | The pool's end-session address |
| `signOutWithHostedPage({postLogoutRedirectUri, everywhere, preferEphemeral})` | `signOut()` + the hosted page's logout |
| `dispose()` | Closes the stream and the HTTP client the SDK created |

Storage: `TokenStorage` (`read`, `write`, `delete`), `SecureTokenStorage` (default), `MemoryTokenStorage`. The session is
stored as JSON `{accessToken, refreshToken, idToken, expiresAt, user, org}` under `openback.auth.<clientId>`; a hosted
sign-in in progress under `openback.auth.<clientId>.pkce`.

## 7. Outcomes and errors

Sign-up and sign-in return a `SignInOutcome` (sealed): `SignInOk` (`user`, `org`), `VerificationRequired`,
`MfaRequired` (`mfaToken`), `MfaEnrollRequired` (`mfaToken`), `PasswordChangeRequired` (`changeToken`). Only
`SignInOk` stores a session.

Failures throw `AppAuthException` with `status` (HTTP status, 0 without an answer), `code`, `message`, `detail`:

| Code | Status | Meaning |
|---|---|---|
| `invalid_credentials` | 401 | Wrong email/password (also unknown or locked accounts) |
| `too_many_requests` | 429 | Rate limited |
| `weak_password` | 422 | `e.problems` lists the policy problems |
| `email_in_use` | 409 | |
| `invalid_code`, `method_disabled`, `signup_disabled` | 400/403 | |
| `origin_not_allowed` | 403 | Web: the site's origin is not an allowed origin of the `spa` app |
| `token_expired`, `token_invalid`, `token_missing`, `token_revoked`, `token_other_app` | 401 | The session is dead: the SDK cleared it (`e.isSessionEnded`) |
| `invalid_refresh_token` | 401 | The refresh token was refused: the SDK cleared the session |
| `not_b2b`, `org_creation_disabled`, `not_org_admin`, `owners_only`, `not_a_member` | 403/404 | Organizations |
| `not_signed_in` | 401 | Raised by the SDK: no session |
| `network_error` | 0 | The pool could not be reached (`e.cause`) |
| `canceled`, `browser_error` | 0 | Hosted page closed by the user / browser failure |
| `invalid_state`, `invalid_issuer`, `invalid_nonce`, `invalid_id_token`, `invalid_callback` | 400 | Hosted sign-in callback refused |
| `invalid_grant`, `invalid_client`, `slow_down` | 400/401/429 | Token endpoint (hosted sign-in) |
| `http_<status>` | | Any other answer without a code |

When the session ends (sign-out, refused refresh token, `token_*` answer, password change, account deletion),
`authStateChanges` emits a signed-out state.

## 8. Security notes

- **Storage**: tokens live in `flutter_secure_storage` (Keychain "after first unlock, this device only" on Apple
  platforms, EncryptedSharedPreferences/Keystore on Android). Pass your own `TokenStorage` to keep them elsewhere;
  `MemoryTokenStorage` keeps nothing across restarts.
- **Refresh token rotation**: every renewal returns a new refresh token and the old one dies; presenting a used one
  revokes the whole session. The SDK runs one renewal at a time (concurrent callers share it), stores the new token
  in a single write and never retries a renewal automatically after a network error (it surfaces `network_error`;
  the next call tries again).
- **PKCE, state, nonce**: generated from the platform CSPRNG (`Random.secure`), PKCE S256 always; the callback's
  `state` is compared in constant time, `iss` must equal the issuer (RFC 9207), the ID token's `nonce`, `aud` and
  `iss` are checked. The ID token is decoded, not signature-checked: it comes straight from the token endpoint over
  TLS (OpenID Connect Core 3.1.3.7).
- **Never log tokens**, codes, secrets or passwords; the SDK never does. `AppAuthException` messages carry no tokens.
- **Access tokens cannot be revoked** before they expire (default 15 minutes): your server should keep them short-lived
  and rely on the refresh token's rejection.
- `authorizedClient(hosts: ...)` sends the token only to your hosts.
- No client secret in apps: register mobile/desktop apps as `native` and web apps as `spa`.

## 9. Tests

```sh
flutter pub get
flutter test
```

The tests mock HTTP with `package:http/testing.dart` (`MockClient`) and use `MemoryTokenStorage` and a fake browser
(`webAuthenticator`); they never touch the network.

## 10. License

MIT — Copyright (c) 2026 GexyLab and the OpenBack contributors. See [LICENSE](LICENSE).
