# Changelog

## 1.0.0 — 2026-10-20

First release.

- `openback-app-auth-csharp` (netstandard2.0, net8.0): `AppAuthClient` for the pool's JSON API (sign-up, password,
  email code, guest, two-step verification, passwords and emails, profile, organizations and members), single-flight
  token renewal, `ITokenStorage` (in memory; DPAPI-protected files on Windows), `AuthStateChanged`,
  `AppAuthHttpHandler`; hosted sign-in (OIDC code + PKCE S256) with `BuildAuthorizationRequestAsync` /
  `HandleRedirectCallbackAsync` and the desktop loopback flow `SignInWithSystemBrowserAsync`; `TokenVerifier` + `AppUser`
  (local ES256 verification, no IdentityModel dependency); `OidcWebClient` for confidential web apps; `AppAuthException`.
- `openback-app-auth-csharp-aspnetcore` (net8.0): `AddOpenBackAppAuth` authentication scheme `OpenBackAppAuth`,
  claims principal, 401/403 JSON answers, policy helpers `RequireAppUser`, `RequireAppUserOrGuest`, `RequireAppRole`,
  `RequireAppPermission`, `RequireVerifiedAppEmail`, `AddAppUserPolicy`.
- Examples: console sign-in with MFA, protected minimal API, web login with the standard `AddOpenIdConnect`.
