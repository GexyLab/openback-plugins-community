# Changelog

## 1.0.0 — 2026-10-20

First release.

- `openback-app-auth-java`: `AppAuthClient` (JSON API sign-up/sign-in with typed outcomes, MFA, passwords, emails,
  profile, organizations, single-flight refresh, pluggable `TokenStorage`, listeners, authorized `HttpClient` requests,
  async variants), hosted sign-in (OIDC code + PKCE S256, state, nonce, `iss` check), `LoopbackSignIn` for desktop
  apps, `TokenVerifier` (ES256 with `java.security`, JWKS cache, unknown-`kid` refetch, algorithm confusion refused),
  `AppUser`, `AppUserRequirements`, `OidcWebClient` for confidential web apps, `RequireAppUserFilter` (Jakarta Servlet).
- `openback-app-auth-java-spring-boot-starter`: Spring Boot 3 auto-configuration (`openback.app-auth.*`),
  `AppUserAuthenticationProvider`, `OpenBackAppAuthFilter`, `ROLE_<role>` / `PERM_<permission>` authorities, default
  stateless security filter chain.
