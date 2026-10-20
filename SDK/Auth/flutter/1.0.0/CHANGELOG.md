# Changelog

## 1.0.0 — 2026-10-20

First release.

- `OpenBackAppAuth`: sign-up, password, email code, guest and two-step sign-in through the pool's JSON API, with a
  typed `SignInOutcome` (sealed class).
- Hosted sign-in and sign-out (OpenID Connect, code + PKCE S256, state, nonce, `iss` checks) through
  `flutter_web_auth_2` on iOS, Android, web, macOS, Windows and Linux.
- Session in `SecureTokenStorage` (`flutter_secure_storage`) or any `TokenStorage`; `MemoryTokenStorage` for tests.
- Single-flight token renewal (refresh tokens rotate), `authStateChanges` stream, `authorizedClient()` for your API.
- Account (profile, password, email change, guest upgrade, deletion, MFA enrollment) and B2B organizations and members.
