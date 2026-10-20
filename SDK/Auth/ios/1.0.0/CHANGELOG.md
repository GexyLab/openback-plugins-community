# Changelog

## 1.0.0 — 2026-10-20

First release.

- `AppAuthClient` (actor): sign-up, password, email code, guest and two-step sign-in through the pool's JSON API, with
  a typed `SignInOutcome` enum.
- Hosted sign-in and sign-out with `ASWebAuthenticationSession` (OpenID Connect, code + PKCE S256, state, nonce,
  `iss` checks), ephemeral session option.
- Session in the Keychain (`KeychainTokenStorage`, after first unlock, this device only) or any `TokenStorage`;
  `InMemoryTokenStorage` for tests.
- Single-flight token renewal (refresh tokens rotate), auth state stream, `@MainActor` `AppAuthModel` for SwiftUI,
  authorized `URLSession` requests.
- Account (profile, password, email change, guest upgrade, deletion, MFA enrollment) and B2B organizations and members.
