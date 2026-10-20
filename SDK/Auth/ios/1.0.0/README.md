# openback-app-auth-ios

The Swift client of OpenBack's **App authenticator** (users-service user pools) for iOS, iPadOS, macOS (and tvOS /
watchOS for the JSON API): sign-up, password, email code, guest and two-step sign-in with your own screens, the pool's
hosted sign-in page (OpenID Connect + PKCE) in `ASWebAuthenticationSession`, Keychain token storage, single-flight token
renewal and a SwiftUI model.

- Version: **1.0.0**
- License: **MIT** (see `LICENSE`)
- No third-party dependencies (Foundation, Security, CryptoKit, AuthenticationServices)

> **Names.** The package is `openback-app-auth-ios` (SwiftPM package and CocoaPods pod). Swift module names cannot
> contain hyphens, so the library product and the module are **`OpenBackAppAuth`** (`import OpenBackAppAuth`).

## 1. Requirements

- Swift **5.9+** (Xcode 15+); Xcode 15.3+ (Swift 5.10) for https (universal link) callbacks
- iOS / iPadOS **15+**, macOS **12+**, tvOS **15+**, watchOS **8+**
- Hosted sign-in (`ASWebAuthenticationSession`): iOS and macOS only (incl. Mac Catalyst). On tvOS and watchOS use your own
  screens (JSON API) or pass your own `WebAuthenticator`.

## 2. Installation

### Swift Package Manager

SwiftPM reads `Package.swift` only at the root of a repository, and this package lives in
`SDK/Auth/ios/1.0.0/` of `openback-plugins-community`. Until it is published from a repository of its own (then: `.package(url: <that repository>, from: "1.0.0")`), add
it as a **local package**:

- Xcode › File › Add Package Dependencies… › Add Local… › `openback-plugins-community/SDK/Auth/ios/1.0.0`;
- or in a `Package.swift`:

```swift
dependencies: [
    .package(path: "../openback-plugins-community/SDK/Auth/ios/1.0.0"),
],
targets: [
    .target(name: "MyApp", dependencies: [.product(name: "OpenBackAppAuth", package: "openback-app-auth-ios")]),
]
```

### CocoaPods

Once published to trunk: `pod 'openback-app-auth-ios', '~> 1.0'`. Until then, from a local checkout of this
repository:

```ruby
pod 'openback-app-auth-ios', :path => '../openback-plugins-community/SDK/Auth/ios/1.0.0'
```

The podspec's paths are relative to its own directory; a `:git` install needs the podspec at the root of a repository,
so it becomes possible once the package is published from a repository of its own (as for SwiftPM).

## 3. Register your app in the pool

In the OpenBack portal open the user pool, tab **Apps**, and add the app as **`native`** (public client: no secret,
PKCE). Note the pool's address (the **issuer**, e.g. `https://api.example.com/gateway/shop/auth/main`) and the app's
**client ID** (`uapp_...`).

Redirect address (needed for the hosted page only), matched **exactly**:

- a custom scheme: `com.example.app:/oauth2redirect` (use your bundle id, reversed-domain style); or
- a universal link: `https://app.example.com/oauth2redirect` (iOS 17.4+ / macOS 14.4+, see below).

For `signOutWithHostedPage()` add the same address (or another one) to the app's **post-logout redirect** list.

### Info.plist and URL schemes

`ASWebAuthenticationSession` catches the callback itself: you do **not** need to declare the scheme in `Info.plist`
for the hosted sign-in. Declare it (`CFBundleURLTypes`) only if your app must also open other `com.example.app:` links
(for example your own deep links from emails):

```xml
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleURLName</key>
    <string>com.example.app</string>
    <key>CFBundleURLSchemes</key>
    <array><string>com.example.app</string></array>
  </dict>
</array>
```

For an **https callback** (universal link) add the Associated Domains capability with `webcredentials:app.example.com` and the matching
`apple-app-site-association` file on your domain; the SDK then uses
`ASWebAuthenticationSession.Callback.https(host:path:)` (iOS 17.4+ / macOS 14.4+; older systems need a custom scheme).

**macOS**: enable App Sandbox › Outgoing Connections (Client); the default `KeychainTokenStorage` uses the data
protection keychain, which needs a signed app (a development team) — or pass
`KeychainTokenStorage(useDataProtectionKeychain: false)`.

**App extensions**: the default presentation anchor uses `UIApplication.shared`; in extensions use the JSON API or pass
`SystemWebAuthenticator(presentationAnchor:)` from the app target.

## 4. Quick start

```swift
import OpenBackAppAuth

let auth = AppAuthClient(issuer: "https://api.example.com/gateway/shop/auth/main",
                         clientId: "uapp_...",
                         redirectURI: "com.example.app:/oauth2redirect") // only for the hosted page
```

### Sign in with email and password (and the two-step branch)

```swift
var outcome = try await auth.signInWithPassword(email: email, password: password)
if case .mfaRequired(let mfaToken) = outcome {
    outcome = try await auth.verifyMfa(mfaToken: mfaToken, code: codeFromAuthenticatorApp)
}
switch outcome {
case .ok(let user, _):
    print("Hello \(user?.displayName ?? "")")
case .mfaRequired:
    break // wrong code: ask again
case .mfaEnrollRequired(let mfaToken):
    let enrollment = try await auth.enrollMfa(mfaToken: mfaToken)     // show enrollment.otpauthURI as a QR code
    let done = try await auth.confirmMfa(code: firstCode, mfaToken: mfaToken) // done.recoveryCodes: show once
case .passwordChangeRequired(let changeToken):
    try await auth.changeForcedPassword(changeToken: changeToken, newPassword: newPassword) // then sign in again
case .verificationRequired:
    break // the pool emailed a code and a link: auth.verifyEmail(email:code:), then sign in
}
```

### Sign in with the hosted page

```swift
do {
    let user = try await auth.signInWithHostedPage()                                   // the pool's page
    // try await auth.signInWithHostedPage(AuthorizationOptions(provider: "uprov_...")) // straight to Google...
    // try await auth.signInWithHostedPage(prefersEphemeralSession: true)              // private session
} catch let error as AppAuthError where error.code == "canceled" {
    // the user closed the sheet
}
```

`prefersEphemeralSession: true` shares no cookies with Safari and skips the "*App* wants to use *example.com* to sign
in" alert, but the user signs in every time. The provider ids are in `try await auth.config().providers`.

### SwiftUI

```swift
@main
struct MyApp: App {
    @StateObject private var auth = AppAuthModel(client: AppAuthClient(issuer: issuer, clientId: clientId,
                                                                      redirectURI: "com.example.app:/oauth2redirect"))
    var body: some Scene {
        WindowGroup {
            if let user = auth.user { HomeView(user: user) } else { SignInView() }
        }
    }
}
```

`AppAuthModel` (`@MainActor ObservableObject`) publishes `user`, `org`, `isLoaded`; call `auth.client` for everything
else. A complete sample is in [`Examples/SwiftUIExample`](Examples/SwiftUIExample/OpenBackAuthExampleApp.swift).

### Call your API

```swift
let (data, response) = try await URLSession.shared.data(for: URLRequest(url: ordersURL), authorizedBy: auth)
// or:
let request = try await auth.authorize(URLRequest(url: ordersURL)) // adds Authorization: Bearer <access token>
let token = try await auth.accessToken()                           // renewed when it expires in less than 60 s
```

Send the token only to your own API. Your API verifies it: behind the OpenBack gateway with the endpoint check
**"Authenticated app user"** (no code; functions get `event.user`), or in your own server with an OpenBack server SDK
or any JWT library (ES256, JWKS at `<issuer>/.well-known/jwks.json`, `iss`, `aud` = client ID, `exp`).

### Sign out

```swift
await auth.signOut()                       // revokes the refresh token, ends this session, clears locally
await auth.signOut(everywhere: true)       // every session of the user
try await auth.signOutWithHostedPage()     // also ends the hosted page's browser session (cookie)
```

## 5. Server-side verification

This is a client SDK: it decodes the access token for display (`accessTokenClaims`, `JWT.decodePayload`) but never
trusts it for security decisions. Verify tokens on your server (see "Call your API").

## 6. API reference

`AppAuthClient` is an `actor`: call its methods with `await`. `issuer`, `clientId`, `redirectURI`, `storageKey` are
`nonisolated`.

`init(issuer:clientId:redirectURI:storage:storageKey:urlSession:webAuthenticator:clock:)`

| Member | What it does |
|---|---|
| `currentUser`, `currentOrg`, `authState`, `isSignedIn` | The signed-in user, active organization (B2B), both, whether a session exists |
| `accessTokenClaims` | The access token's claims (`[String: JSONValue]`), decoded, not verified |
| `authStateChanges()` | `AsyncStream<AuthState>`: the current state, then every change |
| `onAuthStateChanged(_:)` | Same with a callback; returns an `AuthStateSubscription` (`cancel()`) |
| `config()` | The pool's public settings (`PoolConfig`) |
| `accessToken()` | A valid access token (renewed if it expires within 60 s) |
| `refresh(orgId:)` | Renews the tokens now (single-flight), optionally for another organization |
| `authorize(_:)` | A `URLRequest` with the Bearer token; `URLSession.data(for:authorizedBy:)`, `upload(for:from:authorizedBy:)` |
| `signUp(email:password:displayName:locale:orgId:)` | → `SignInOutcome` |
| `signInWithPassword(email:password:orgId:)` | → `SignInOutcome` |
| `sendEmailCode(email:)` | Emails a sign-in code |
| `signInWithEmailCode(email:code:token:orgId:)` | → `SignInOutcome` |
| `signInAnonymously()` | Guest account → `SignInOutcome` |
| `verifyMfa(mfaToken:code:)` | Second factor (TOTP or recovery code) → `SignInOutcome` |
| `enrollMfa(mfaToken:)` | → `MfaEnrollment` (`secret`, `otpauthURI`) |
| `confirmMfa(code:mfaToken:)` | → `MfaConfirmation` (`recoveryCodes`, `outcome`) |
| `disableMfa(code:)` | Turns two-step verification off |
| `sendPasswordReset(email:)` | Emails a reset code and link |
| `resetPassword(token:email:code:newPassword:)` | Sets a new password (link token or email + code) |
| `changeForcedPassword(changeToken:newPassword:)` | Answers `.passwordChangeRequired` |
| `verifyEmail(token:email:code:)` | Verifies the address → `PoolUser?` |
| `resendVerification()` | Sends the verification email again |
| `me()` | The user, fresh (also updates `currentUser`) |
| `updateProfile(displayName:photoURL:locale:)` | → `PoolUser` |
| `changePassword(currentPassword:newPassword:)` | Ends every session, clears the local one |
| `changeEmail(newEmail:)` / `confirmEmailChange(code:token:)` | Email change with a code sent to the new address |
| `upgradeAnonymous(email:password:)` | Guest → real account (same id), tokens renewed |
| `deleteAccount(password:)` | Deletes the account, clears the session |
| `signOut(everywhere:)` | Best-effort server sign-out, always clears locally |
| `organizations()` | `OrganizationList` (`orgs`, `active`; B2C: empty) |
| `createOrganization(name:)` | → `Organization` |
| `switchOrganization(_:)` | New tokens for that organization → `ActiveOrg?` |
| `members(orgId:query:skip:limit:)` | → `MemberPage` (owners/admins) |
| `addMember(orgId:email:displayName:password:roles:)` | → `AddedMember` (may carry `temporaryPassword`) |
| `setMemberRoles(orgId:userId:roles:)` / `removeMember(orgId:userId:)` | Member management |
| `buildAuthorizationRequest(_:redirectURI:)` | Low level: `AuthorizationRequest` (`url`, `state`, `nonce`, `codeVerifier`, `redirectURI`), stored for the callback |
| `handleRedirectCallback(_:)` | Low level: checks `error`, `state`, `iss`, exchanges the code, checks the ID token's `nonce` → `PoolUser?` |
| `signInWithHostedPage(_:prefersEphemeralSession:)` | The whole hosted flow (`AuthorizationOptions`: `provider`, `orgId`, `prompt`, `screenHint`, `loginHint`, `maxAge`, `scope`, `uiLocales`) |
| `buildLogoutURL(postLogoutRedirectURI:state:)` | The pool's end-session address |
| `signOutWithHostedPage(postLogoutRedirectURI:everywhere:prefersEphemeralSession:)` | `signOut()` + the hosted page's logout |

Other types: `AppAuthModel` (SwiftUI), `TokenStorage` (`get`, `set`, `remove`), `KeychainTokenStorage` (default),
`InMemoryTokenStorage`, `WebAuthenticator`, `SystemWebAuthenticator`, `PoolUser`, `ActiveOrg`, `AuthState`,
`JSONValue`, `JWT`.

The session is stored as JSON `{accessToken, refreshToken, idToken, expiresAt, user, org}` under
`openback.auth.<clientId>`; a hosted sign-in in progress under `openback.auth.<clientId>.pkce`.

## 7. Outcomes and errors

Sign-up and sign-in return a `SignInOutcome`: `.ok(user:org:)`, `.verificationRequired`, `.mfaRequired(mfaToken:)`,
`.mfaEnrollRequired(mfaToken:)`, `.passwordChangeRequired(changeToken:)`. Only `.ok` stores a session.

Failures throw `AppAuthError` (`status`, `code`, `message`, `detail`, `problems`, `isSessionEnded`):

| Code | Status | Meaning |
|---|---|---|
| `invalid_credentials` | 401 | Wrong email/password (also unknown or locked accounts) |
| `too_many_requests` | 429 | Rate limited |
| `weak_password` | 422 | `error.problems` lists the policy problems |
| `email_in_use` | 409 | |
| `invalid_code`, `method_disabled`, `signup_disabled` | 400/403 | |
| `token_expired`, `token_invalid`, `token_missing`, `token_revoked`, `token_other_app` | 401 | The session is dead: the SDK cleared it |
| `invalid_refresh_token` | 401 | The refresh token was refused: the SDK cleared the session |
| `not_b2b`, `org_creation_disabled`, `not_org_admin`, `owners_only`, `not_a_member` | 403/404 | Organizations |
| `not_signed_in` | 401 | Raised by the SDK: no session |
| `network_error` | 0 | The pool could not be reached (`error.urlError`) |
| `canceled`, `browser_error`, `unsupported_platform` | 0 | Hosted page closed / browser failure / no browser on this platform |
| `invalid_state`, `invalid_issuer`, `invalid_nonce`, `invalid_id_token`, `invalid_callback` | 400 | Hosted sign-in callback refused |
| `invalid_grant`, `invalid_client`, `slow_down` | 400/401/429 | Token endpoint (hosted sign-in) |
| `storage_error` | 0 | Keychain failure (`OSStatus` in the message) |
| `http_<status>` | | Any other answer without a code |

When the session ends (sign-out, refused refresh token, `token_*` answer, password change, account deletion), the state
stream emits a signed-out state.

## 8. Security notes

- **Storage**: the Keychain, `kSecClassGenericPassword`, service = the storage key,
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` (not in backups, not migrated to other devices, readable by
  background refreshes once the device was unlocked). Share it with extensions through `accessGroup`. Pass your own
  `TokenStorage` to keep it elsewhere; `InMemoryTokenStorage` keeps nothing.
- **Refresh token rotation**: every renewal returns a new refresh token and the old one dies; presenting a used one
  revokes the whole session. The actor runs one renewal at a time (concurrent callers share it; a cancelled caller does
  not abort it), stores the new token in a single Keychain write and never retries a renewal automatically after a
  network error (it throws `network_error`; the next call tries again).
- **PKCE, state, nonce**: from `SecRandomCopyBytes`, challenge with CryptoKit SHA-256 (S256 always); the callback's
  `state` is compared in constant time, `iss` must equal the issuer (RFC 9207), the ID token's `nonce`, `aud` and `iss`
  are checked. The ID token is decoded, not signature-checked: it comes straight from the token endpoint over TLS
  (OpenID Connect Core 3.1.3.7).
- **Never log tokens**, codes, secrets or passwords; the SDK never does.
- **Access tokens cannot be revoked** before they expire (default 15 minutes).
- No client secret in apps: register them as `native`.

## 9. Tests

```sh
cd SDK/Auth/ios/1.0.0
swift test                     # macOS, Xcode 15+
# or: xcodebuild test -scheme openback-app-auth-ios -destination 'platform=iOS Simulator,name=iPhone 15'
```

The tests stub HTTP with a `URLProtocol` (no network), sign test tokens with a P-256 key generated at run time (ES256),
use `InMemoryTokenStorage` and a fake `WebAuthenticator`.

## 10. License

MIT — Copyright (c) 2026 GexyLab and the OpenBack contributors. See [LICENSE](LICENSE).
