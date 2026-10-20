# openback-app-auth-csharp

The .NET client and server SDK for OpenBack's **App authenticator** (user pools): sign your app's users in (your own
forms or the pool's hosted page), keep and renew their tokens, and verify those tokens in your ASP.NET Core APIs.

Version **1.0.0** · License **MIT** · Packages: `openback-app-auth-csharp` (core) and
`openback-app-auth-csharp-aspnetcore` (ASP.NET Core). C# namespace: `OpenBack.AppAuth` (NuGet allows hyphens; the
namespace uses the closest legal form).

## Requirements

| Package | Targets | Runs on |
|---|---|---|
| `openback-app-auth-csharp` | `netstandard2.0`, `net8.0` | .NET 8+, .NET Framework 4.7.2+ / 4.8 (WPF, WinForms), Unity (2021+, .NET Standard 2.x profile), Xamarin, .NET MAUI, console, servers |
| `openback-app-auth-csharp-aspnetcore` | `net8.0` | ASP.NET Core 8+ |

Dependencies: `System.Text.Json` (netstandard2.0 only; built into .NET 8). No IdentityModel: tokens are verified with
`System.Security.Cryptography.ECDsa`. `ProtectedFileTokenStorage` (DPAPI) works on Windows only.

## Installation

Once published on NuGet:

```
dotnet add package openback-app-auth-csharp
dotnet add package openback-app-auth-csharp-aspnetcore      # ASP.NET Core APIs
```

From this repository (`SDK/Auth/csharp/1.0.0` of https://github.com/GexyLab/openback-plugins-community): reference the
projects, or build the packages and use a local feed:

```
dotnet pack OpenBack.AppAuth.sln -c Release -o ../local-feed
dotnet add package openback-app-auth-csharp --source ../local-feed
```

```xml
<ProjectReference Include="path/to/SDK/Auth/csharp/1.0.0/src/OpenBack.AppAuth/OpenBack.AppAuth.csproj" />
```

## Register your app in the pool

In the OpenBack portal open the user pool, tab **Apps**, and register the app. You get its **client ID** (`uapp_...`,
public). The pool's address is the **issuer**, e.g. `https://api.example.com/gateway/shop/auth/main`.

| Your app | Kind | Register |
|---|---|---|
| Desktop (WPF, WinForms, console, Avalonia), Unity, MAUI, Xamarin | `native` | redirect URI: a loopback address with a FIXED port for the system-browser sign-in, e.g. `http://127.0.0.1:53682/callback` (the pool matches redirect URIs exactly), or a custom scheme `com.example.app:/callback` for mobile |
| Server-rendered web app (ASP.NET Core MVC/Razor) | `web` | client secret, redirect URI `https://app.example.com/signin-oidc`, post-logout redirect URIs |
| A server calling the JSON API (no browser) | `backend` | client secret |
| An API that only verifies tokens | — | nothing: accept the client IDs of the apps that call it |

`http://` redirect URIs are accepted only for `localhost` / `127.0.0.1` / `[::1]`. Never ship a client secret in a
desktop, mobile or browser app.

## Quick start

### Sign in with your own form (password, two-step verification)

```csharp
using OpenBack.AppAuth;

var auth = await AppAuthClient.CreateAsync(
    "https://api.example.com/gateway/shop/auth/main", "uapp_...",
    new AppAuthClientOptions { Storage = new ProtectedFileTokenStorage() });   // Windows desktop; default: in memory

auth.AuthStateChanged += (s, e) => Console.WriteLine(e.IsSignedIn ? $"signed in: {e.User?.Email}" : "signed out");

var outcome = await auth.SignInWithPasswordAsync(email, password);
if (outcome.Status == AuthStatus.MfaRequired)
    outcome = await auth.VerifyMfaAsync(outcome.MfaToken!, codeFromAuthenticatorApp);
if (outcome.Status == AuthStatus.PasswordChangeRequired)
    await auth.ChangeForcedPasswordAsync(outcome.ChangeToken!, newPassword);   // then sign in again
if (outcome.IsOk)
    Console.WriteLine($"Hello {auth.CurrentUser!.DisplayName}");
```

### The hosted sign-in page (social providers, SSO)

Desktop apps (WPF, WinForms, console): the SDK listens on the registered loopback redirect URI (HttpListener on
127.0.0.1), opens the system browser and completes the sign-in when the browser comes back:

```csharp
var auth = new AppAuthClient(issuer, clientId, new AppAuthClientOptions { RedirectUri = "http://127.0.0.1:53682/callback" });
var user = await auth.SignInWithSystemBrowserAsync(
    options: new AuthorizationRequestOptions { Provider = "uprov_google" });   // optional: straight to a provider
```

In WPF/WinForms call it from a button handler (`async void OnSignIn(...)`); it does not block the UI thread. Bring your
window back to the front afterwards (`Activate()`).

Other platforms (mobile custom scheme, embedded browsers, Unity deep links) use the low-level pair:

```csharp
var request = await auth.BuildAuthorizationRequestAsync(new AuthorizationRequestOptions { ScreenHint = "signup" });
OpenInBrowser(request.Url);                       // the transaction is saved in the storage ("<key>.pkce")
// ... when the app receives com.example.app:/callback?code=...&state=...
var user = await auth.HandleRedirectCallbackAsync(callbackUrl);
```

Sign out of the hosted session too: `await auth.SignOutWithSystemBrowserAsync()` or open `auth.BuildLogoutUrl(...)`.

### Calling your API

```csharp
using var api = auth.CreateAuthorizedHttpClient();                 // Authorization: Bearer <access token>, renewed when needed
var orders = await api.GetStringAsync("https://api.example.com/gateway/shop/orders");

// IHttpClientFactory:
services.AddHttpClient("api").AddHttpMessageHandler(() => new AppAuthHttpHandler(auth));

// or by hand:
var token = await auth.GetAccessTokenAsync();
```

## Server-side verification and ASP.NET Core

### ASP.NET Core

```csharp
using OpenBack.AppAuth.AspNetCore;

builder.Services.AddOpenBackAppAuth(o =>
{
    o.Issuer = "https://api.example.com/gateway/shop/auth/main";
    o.ClientIds = new[] { "uapp_web", "uapp_mobile" };
    // o.AllowAnonymousUsers = true;   // default policy accepts guest accounts
    // o.RequireVerifiedEmail = true;
});
builder.Services.AddAuthorization(o =>
{
    o.AddAppUserPolicy("admins", p => p.RequireAppRole("admin", "owner"));      // one of the roles
    o.AddAppUserPolicy("invoices", p => p.RequireAppPermission("invoices.read")); // all permissions ("*" = all)
    o.AddAppUserPolicy("verified", p => p.RequireVerifiedAppEmail());
    o.AddAppUserPolicy("guests-ok", p => p.RequireAppUserOrGuest());
});

app.UseAuthentication();
app.UseAuthorization();
app.MapGet("/me", (HttpContext ctx) => ctx.GetAppUser()).RequireAuthorization();   // default policy: app user, no guests
app.MapGet("/admin", () => "ok").RequireAuthorization("admins");
```

- Scheme `OpenBackAppAuth` (`OpenBackAppAuthDefaults.AuthenticationScheme`), registered as the default scheme by
  `services.AddOpenBackAppAuth`. With other schemes (cookies), use `services.AddAuthentication(...).AddOpenBackAppAuth(...)`.
- Claims: `sub` (also `NameIdentifier`, and `User.Identity.Name`), `email`, `email_verified`, roles as
  `ClaimTypes.Role` (`User.IsInRole("admin")`, `[Authorize(Roles = "admin")]`), `permission`, `org_id`, `pool`,
  `client_id`, `sid`, `anon`, `amr`. `HttpContext.GetAppUser()` returns the full `AppUser`.
- Missing / invalid / expired token: **401**, `WWW-Authenticate: Bearer error="invalid_token"`, body
  `{"error":"invalid_token"}`. Valid token refused by a policy (guest, role, permission, email): **403**,
  `{"error":"insufficient_scope"}`.
- Every policy helper refuses guest accounts (`anon: true`) unless it says otherwise (`RequireAppUserOrGuest`,
  `RequireAppUser(allowAnonymous: true)`).

### Any .NET server: `TokenVerifier`

```csharp
var verifier = new TokenVerifier("https://api.example.com/gateway/shop/auth/main", "uapp_web");   // one per pool, reuse it
AppUser user = await verifier.VerifyAsync(bearerToken);    // throws TokenVerificationException (401)
if (!user.HasPermission("orders.read")) return Forbidden();
```

It fetches `<issuer>/.well-known/jwks.json` (cached 10 minutes; an unknown `kid` refetches at most once per 30 s),
accepts **only ES256** (refuses `none`, HS*, RS*), requires `typ: at+jwt`, the exact issuer, an `aud` among your client
IDs, `exp` / `nbf` / `iat` with 60 s leeway. Verification is local: no call to OpenBack. **Access tokens cannot be
revoked before they expire** (default 15 minutes): keep them short-lived; a revoked session shows up at the next refresh.

### Web login with the standard OpenID Connect middleware

A server-rendered app (kind `web`) can use ASP.NET Core's own `AddOpenIdConnect` with `Authority = issuer`
(`examples/AspNetCoreOidcLogin`): code flow, `UsePkce = true`, `MapInboundClaims = false`. Without the middleware,
`OidcWebClient` does the same flow by hand:

```csharp
var oidc = new OidcWebClient(new OidcWebClientOptions
{
    Issuer = issuer, ClientId = "uapp_web", ClientSecret = secret, RedirectUri = "https://app.example.com/auth/callback",
});
var start = oidc.CreateAuthorizationRequest();
HttpContext.Session.SetString("oidc", start.Transaction.ToJson());       // server-side session
return Redirect(start.Url.ToString());
// callback:
var tx = OidcTransaction.FromJson(HttpContext.Session.GetString("oidc")!);
HttpContext.Session.Remove("oidc");
var result = await oidc.HandleCallbackAsync(Request.Query.ToDictionary(q => q.Key, q => q.Value.ToString()), tx);
// result.IdTokenClaims (verified), result.Tokens (store the refresh token server-side)
```

### Without any SDK: the OpenBack gateway

An API published behind the OpenBack gateway can use the endpoint check **"Authenticated app user"** (policy
`app_user_auth`: pool, required roles/permissions, verified email, guests): the gateway verifies the token and your
function receives `event.user`. No SDK is needed there.

## API reference

### `AppAuthClient` (namespace `OpenBack.AppAuth`)

| Member | |
|---|---|
| `new AppAuthClient(issuer, clientId, options?)` / `CreateAsync(...)` | make a client (`CreateAsync` also restores the stored session) |
| `AppAuthClientOptions` | `RedirectUri`, `Storage`, `StorageKey`, `HttpClient`, `ClientSecret` (web/backend only), `RefreshSkew`, `Clock` |
| `InitializeAsync()` | restore the stored session (every async method does it on first use) |
| `Issuer`, `ClientId`, `StorageKey` | configuration |
| `CurrentUser`, `CurrentOrg`, `IsSignedIn`, `AccessTokenClaims` | state (claims decoded, NOT verified) |
| `AuthStateChanged` (event), `OnAuthStateChanged(listener)` → `IDisposable` | changes; the listener is called at once |
| `GetConfigAsync()` | pool configuration: methods, providers, password policy, branding |
| `GetAccessTokenAsync()` | stored token if valid for > 60 s, else renewed (single-flight) |
| `RefreshAsync(orgId?)` | renew now (optionally into an organization) |
| `CreateAuthorizedHttpClient(inner?)`, `AppAuthHttpHandler` | HttpClient / handler adding the Bearer token |
| `SignUpAsync(email, password, displayName?, locale?, orgId?)` | outcome |
| `SignInWithPasswordAsync(email, password, orgId?)` | outcome |
| `SendEmailCodeAsync(email)`, `SignInWithEmailCodeAsync(email, code, orgId?)`, `SignInWithEmailLinkTokenAsync(token, orgId?)` | email code sign-in |
| `SignInAnonymouslyAsync()` | guest account |
| `VerifyMfaAsync(mfaToken, code)` | second step (TOTP or recovery code) |
| `EnrollMfaAsync(mfaToken?)`, `ConfirmMfaAsync(code, mfaToken?)`, `DisableMfaAsync(code)` | authenticator app |
| `SendPasswordResetAsync(email)`, `ResetPasswordWithTokenAsync(token, new)`, `ResetPasswordWithCodeAsync(email, code, new)` | forgotten password |
| `ChangeForcedPasswordAsync(changeToken, new)` | after `PasswordChangeRequired` |
| `VerifyEmailWithTokenAsync(token)`, `VerifyEmailWithCodeAsync(email, code)`, `ResendVerificationAsync()` | email verification |
| `MeAsync()`, `UpdateProfileAsync(ProfileUpdate)` | the user |
| `ChangePasswordAsync(current?, new)` | every session ends: the local one is cleared |
| `ChangeEmailAsync(newEmail)`, `ConfirmEmailChangeWithCodeAsync(code)`, `ConfirmEmailChangeWithTokenAsync(token)` | email change |
| `UpgradeAnonymousAsync(email, password)` | guest → real account (same id) |
| `DeleteAccountAsync(password?)` | clears the session |
| `SignOutAsync(everywhere = false)` | best-effort server call, always clears locally |
| `GetOrganizationsAsync()`, `CreateOrganizationAsync(name)`, `SwitchOrganizationAsync(orgId)` | organizations (B2B) |
| `GetMembersAsync(orgId, q?, skip, limit)`, `AddMemberAsync(...)`, `SetMemberRolesAsync(...)`, `RemoveMemberAsync(...)` | members (org owners/admins) |
| `BuildAuthorizationRequestAsync(AuthorizationRequestOptions?)` | hosted sign-in URL + transaction (`Url`, `State`, `Nonce`, `CodeVerifier`, `RedirectUri`) |
| `HandleRedirectCallbackAsync(url)` | completes it (error, state, iss, code exchange, nonce) → user |
| `SignInWithSystemBrowserAsync(SystemBrowserOptions?, AuthorizationRequestOptions?)` | desktop loopback flow |
| `BuildLogoutUrl(postLogoutRedirectUri?, state?)`, `SignOutWithSystemBrowserAsync(...)` | hosted sign-out |

`AuthorizationRequestOptions`: `Provider`, `OrgId`, `Prompt` (`none`/`login`), `ScreenHint` (`signup`), `LoginHint`,
`MaxAge`, `Scope`, `UiLocales`, `RedirectUri`. `SystemBrowserOptions`: `RedirectUri`, `Timeout`, `OpenBrowser`,
`SuccessHtml`, `ErrorHtml`.

### Storage

| Type | |
|---|---|
| `ITokenStorage` | `GetAsync` / `SetAsync` / `RemoveAsync` of a string by key: plug a file, database, OS keychain, ASP.NET session |
| `InMemoryTokenStorage` | default (lost at exit) |
| `ProtectedFileTokenStorage(directory?, entropy?)` | Windows: DPAPI (current user), `%LOCALAPPDATA%\OpenBack\AppAuth` |

The session is stored as `{accessToken, refreshToken, idToken, expiresAt (epoch ms), user, org}` under
`openback.auth.<clientId>` (the same format as the other OpenBack App Auth SDKs).

### Server side

| Type | |
|---|---|
| `TokenVerifier(issuer, params clientIds)` / `TokenVerifier(TokenVerifierOptions)` | `VerifyAsync(accessToken)` → `AppUser`; `VerifyIdTokenAsync(idToken, nonce?)` → claims |
| `TokenVerifierOptions` | `Issuer`, `ClientIds`, `JwksUri`, `CacheDuration`, `UnknownKeyRefetchInterval`, `ClockSkew`, `HttpClient`, `Clock` |
| `AppUser` | `Id`, `PoolId`, `ClientId`, `Email`, `EmailVerified`, `Anonymous`, `OrgId`, `Roles`, `Permissions`, `Attributes`, `SessionId`, `Amr`, `Scope`, `ExpiresAt`, `Claims`; `HasRole(r)`, `HasPermission(p)` |
| `OidcWebClient(OidcWebClientOptions)` | `CreateAuthorizationRequest(options?)`, `HandleCallbackAsync(params or url, transaction)`, `RefreshAsync(refreshToken, orgId?)`, `RevokeAsync(refreshToken)`, `GetUserInfoAsync(accessToken)`, `BuildLogoutUrl(idTokenHint?, postLogoutRedirectUri?, state?)` |
| `OidcWebClientOptions` | `Issuer`, `ClientId`, `ClientSecret`, `RedirectUri`, `ClientAuthMethod` (`ClientSecretBasic` default, `ClientSecretPost`), `Scope`, `HttpClient`, `TokenVerifier` |
| `Jwt.DecodePayload(token)`, `Jwt.DecodeHeader(token)` | unverified decoding, display only |

### ASP.NET Core (namespace `OpenBack.AppAuth.AspNetCore`)

| Member | |
|---|---|
| `services.AddOpenBackAppAuth(o => ...)` | default scheme + authorization + default policy |
| `authBuilder.AddOpenBackAppAuth([scheme,] o => ...)` | add the scheme next to others |
| `OpenBackAppAuthOptions` | `Issuer`, `ClientIds`, `JwksUri`, `KeyCacheDuration`, `ClockSkew`, `Backchannel`, `SetDefaultPolicy`, `AllowAnonymousUsers`, `RequireVerifiedEmail`, `RequiredRoles`, `RequiredPermissions` |
| `authz.AddAppUserPolicy(name, p => ..., scheme?)` | named policy on the scheme |
| `RequireAppUser(allowAnonymous, requireVerifiedEmail)`, `RequireAppUserOrGuest()`, `RequireAppRole(...)`, `RequireAppPermission(...)`, `RequireVerifiedAppEmail()` | policy builder helpers |
| `HttpContext.GetAppUser()` | the verified `AppUser` of the request |
| `AppUserClaimTypes`, `AppUserPrincipal.Create(user, authType)` | claim names, principal builder |

## Outcomes and errors

Sign-up and sign-in methods return an `AuthOutcome`; the session is kept only when `Status == AuthStatus.Ok`:

| `Status` | Next step |
|---|---|
| `Ok` | signed in (`User`, `Org` for B2B) |
| `VerificationRequired` | the user verifies the email (link/code), then signs in |
| `MfaRequired` | `VerifyMfaAsync(outcome.MfaToken, code)` |
| `MfaEnrollRequired` | `EnrollMfaAsync(outcome.MfaToken)` → show `OtpauthUri` → `ConfirmMfaAsync(code, outcome.MfaToken)` |
| `PasswordChangeRequired` | `ChangeForcedPasswordAsync(outcome.ChangeToken, newPassword)` |
| `Other` | a newer status (`StatusText`) |

Errors are `AppAuthException` with `Status` (HTTP status, 0 for network errors), `Code`, `Message`, `Detail` and
`Problems` (for `weak_password`). Codes: `invalid_credentials` (401), `too_many_requests` (429), `weak_password` (422),
`email_in_use` (409), `invalid_code`, `method_disabled`, `signup_disabled`, `origin_not_allowed` (403), `token_expired`
/ `token_invalid` / `token_missing` / `token_revoked` / `token_other_app` (401), `invalid_refresh_token` (401),
`not_b2b` (404), `org_creation_disabled`, `not_org_admin`, `owners_only`, `not_a_member` (403), OAuth errors of the
hosted flow (`invalid_grant`, `invalid_client`, `slow_down`, `login_required`, `invalid_state`, `invalid_issuer`,
`invalid_nonce`), SDK codes `not_signed_in`, `network_error`, `timeout`, `jwks_unavailable`, and `http_<status>` when
the answer has no code. A 401 `token_*` on a signed-in call or `invalid_refresh_token` means the session is dead: the
client clears it and raises `AuthStateChanged` (signed out); `e.IsSessionEnded` tells you. `TokenVerificationException`
(401) carries `malformed_token`, `invalid_algorithm`, `invalid_type`, `unknown_key`, `invalid_signature`,
`invalid_issuer`, `invalid_audience`, `token_expired`, `token_not_yet_valid`, `invalid_nonce`.

## Security notes

- **Storage**: tokens are secrets. The default storage is in memory; on Windows desktops use `ProtectedFileTokenStorage`
  (DPAPI, current user); on macOS/Linux/mobile implement `ITokenStorage` on the OS keychain / Keystore. Never store
  refresh tokens in plain files, logs, or `PlayerPrefs`.
- **Refresh rotation**: the refresh token changes at every use and a reused one revokes the whole session. The client
  allows one refresh at a time (`SemaphoreSlim`), stores the new token before returning, never retries a refresh
  automatically, and does not cancel a refresh already sent (losing its answer would end the session). Processes that
  share one storage pick up the newest stored refresh token before refreshing; still, prefer one client per app.
- **PKCE and state**: every hosted sign-in uses PKCE S256 (verifier from 48 CSPRNG bytes), a random `state` compared in
  constant time, a `nonce` checked in the ID token, and the RFC 9207 `iss` parameter.
- **Client secrets** only on servers (`web`, `backend`), never in desktop/mobile/browser apps.
- **Never log tokens, codes, passwords or secrets**. The SDK's `ToString()` of results hides them; exceptions carry
  codes and messages only.
- Access tokens are verified locally and cannot be revoked before they expire: keep the pool's access token lifetime
  short; for sensitive operations call `MeAsync()` (the pool checks the session right now).
- Switching to an organization the user does not belong to (`not_a_member`) consumes the refresh token on the pool:
  the client clears the session in that case. Check `GetOrganizationsAsync()` first.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 GexyLab and the OpenBack contributors.
