# Changelog

## 1.0.0 — 2026-10-20

First release.

- `OpenBackAuth`: JSON API sign-up/sign-in with typed outcomes (sealed `AuthOutcome`), MFA, passwords, emails,
  profile, organizations; `authState: StateFlow<AuthState>` and listeners; single-flight, non-cancellable refresh
  (`Mutex`), OkHttp silent retries disabled for the SDK's calls.
- Hosted sign-in in Custom Tabs: `buildAuthorizationRequest` (PKCE S256, state, nonce), `OpenBackSignInContract`,
  `RedirectReceiverActivity` with the `openbackAppAuthRedirectScheme` manifest placeholder, `handleRedirectCallback`
  (state, `iss`, nonce checks), sign-out with the end session in a Custom Tab (`OpenBackSignOutContract`).
- `KeystoreTokenStorage`: AES-256-GCM with an Android Keystore key; `InMemoryTokenStorage`.
- `OpenBackAuthInterceptor` / `OpenBackAuthAuthenticator` for your API's OkHttpClient.
