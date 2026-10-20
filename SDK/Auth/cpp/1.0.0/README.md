# openback-app-auth-cpp

The C++ SDK of the **OpenBack App authenticator** (user pools): sign users in to your desktop, CLI, device or server
app, keep and renew their session, use the hosted sign-in page (OpenID Connect, code + PKCE), and verify the pool's
access tokens in your own server.

Version **1.0.0** · License **MIT** · C++17 · namespace `openback::app_auth`

## 1. Contents

| Part | For |
|---|---|
| `Client` | apps signing users in: your own forms (JSON API), MFA, profile, organizations, hosted sign-in, single-flight token renewal |
| `TokenVerifier` + `AppUser` | servers checking access tokens locally (ES256, JWKS cache) |
| `BearerGuard` | the decision of an HTTP middleware (401 / 403 / pass with the user), for any HTTP framework |
| `OidcWebClient` | "web" apps with their own server (confidential client): authorization URL, callback, refresh, revoke, userinfo |
| `HttpTransport` | the HTTP layer: libcurl by default, or yours (tests, embedded, an existing HTTP stack) |
| `TokenStorage` | where the `Client` keeps the session: in memory by default, or yours (keychain, file, database) |

## 2. Requirements

- A C++17 compiler: MSVC 2019 16.8+ / 2022, GCC 8+, Clang 7+, Apple Clang 11+.
- CMake 3.16 or newer.
- [OpenSSL](https://www.openssl.org/) 3.x (1.1.1 is supported too), [libcurl](https://curl.se/libcurl/) 7.80+
  (optional, see `OPENBACK_APP_AUTH_WITH_CURL`), [nlohmann/json](https://github.com/nlohmann/json) 3.9+.
- Tests: [Catch2](https://github.com/catchorg/Catch2) v3.
- An OpenBack user pool (Settings › Integrations › Services: the **users** service on).

## 3. Installation

There is no registry release yet: the names below are the ones the package will use once published
(vcpkg / Conan port `openback-app-auth-cpp`). Today, build it from this repository:
`SDK/Auth/cpp/1.0.0` of <https://github.com/GexyLab/openback-plugins-community>.

Whatever the way, your project uses it like this:

```cmake
find_package(openback-app-auth-cpp 1.0 REQUIRED)
target_link_libraries(my_app PRIVATE openback::app_auth)
```

```cpp
#include <openback/app_auth.hpp>
```

### With vcpkg (manifest mode)

The directory carries a `vcpkg.json` (curl, openssl, nlohmann-json; the `tests` feature adds catch2).

```sh
# Windows (PowerShell), Linux, macOS -- VCPKG_ROOT points to your vcpkg clone
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake -DVCPKG_MANIFEST_FEATURES=tests
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
cmake --install build --config Release --prefix <install prefix>
```

On Windows pick the triplet you need, e.g. `-DVCPKG_TARGET_TRIPLET=x64-windows` (DLLs) or `x64-windows-static`.
Without the tests: drop `-DVCPKG_MANIFEST_FEATURES=tests` and add `-DOPENBACK_APP_AUTH_BUILD_TESTS=OFF`.
For reproducible builds add a `builtin-baseline` to `vcpkg.json` (`vcpkg x-update-baseline --add-initial-baseline`).

To use it from another vcpkg project before it is in the registry, copy this directory as an overlay port or add it
with `add_subdirectory()` (the target `openback::app_auth` is available either way).

### With Conan 2

```sh
conan profile detect            # once
conan build . --build=missing   # installs openssl, libcurl, nlohmann_json, catch2; builds; runs the tests
conan create . --build=missing  # packages it into the local cache as openback-app-auth-cpp/1.0.0
```

Then in your project's `conanfile.txt`: `[requires] openback-app-auth-cpp/1.0.0` with the `CMakeDeps` and
`CMakeToolchain` generators. Options: `shared` (default False), `with_curl` (default True). Skip the tests with
`-c tools.build:skip_test=True`.

### With plain CMake (dependencies already installed)

```sh
# Linux (Debian/Ubuntu): sudo apt install cmake g++ libssl-dev libcurl4-openssl-dev nlohmann-json3-dev catch2
# macOS (Homebrew):      brew install cmake openssl@3 curl nlohmann-json catch2
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
#   macOS: add -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
#   Windows: add -DCMAKE_PREFIX_PATH="C:/path/to/deps" (or use vcpkg, above)
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
cmake --install build --prefix /usr/local        # or any prefix
```

| CMake option | Default | |
|---|---|---|
| `OPENBACK_APP_AUTH_WITH_CURL` | ON | build the libcurl transport; OFF: pass your own `HttpTransport` |
| `OPENBACK_APP_AUTH_BUILD_TESTS` | ON when top-level | unit tests (Catch2 v3), no network |
| `OPENBACK_APP_AUTH_BUILD_EXAMPLES` | OFF | `examples/` |
| `OPENBACK_APP_AUTH_INSTALL` | ON when top-level | `install()` + the CMake package config |
| `BUILD_SHARED_LIBS` | OFF | a shared library (on Windows all symbols are exported) |

As a subproject: `add_subdirectory(openback-app-auth-cpp)` then link `openback::app_auth`.

## 4. Register your app in the pool

Portal: the user pool › **Apps** tab › new app. The client ID (`uapp_...`) is public.

| Your program | App kind | Register |
|---|---|---|
| desktop / CLI / device signing users in with your own forms | `native` | nothing else (the JSON API is called without `Origin`) |
| desktop app using the hosted page | `native` | the redirect URI, e.g. `com.example.app:/callback` (custom scheme) or `http://127.0.0.1:53682/callback` (loopback; `http://` only for `localhost`, `127.0.0.1`, `[::1]`) |
| a server with its own web pages (`OidcWebClient`) | `web` | redirect URIs (exact match), post-logout redirect URIs; keep the client secret on the server |
| a server calling the pool for its users | `backend` | client secret (only needed at the token endpoint) |

Redirect URIs must match a registered one **exactly** (port and path included).

## 5. Quick start

### Sign in with a password (with the two-step verification branch)

```cpp
#include <openback/app_auth.hpp>
namespace auth = openback::app_auth;

auth::Client client("https://api.example.com/gateway/shop/auth/main", "uapp_...");
client.on_auth_state_changed([](const std::optional<auth::PoolUser>& user, const std::optional<auth::ActiveOrg>&) {
    // called at once, then at every sign-in / sign-out (also when a refresh token is refused)
});

auth::Outcome res = client.sign_in_with_password(email, password);
if (res.status == auth::OutcomeStatus::MfaRequired) {
    res = client.verify_mfa(*res.mfa_token, code_from_authenticator);
} else if (res.status == auth::OutcomeStatus::MfaEnrollRequired) {
    auth::MfaEnrollment e = client.enroll_mfa(*res.mfa_token);          // show e.otpauth_uri as a QR code
    auth::MfaConfirmation c = client.confirm_mfa(code, *res.mfa_token); // c.recovery_codes, c.outcome
} else if (res.status == auth::OutcomeStatus::PasswordChangeRequired) {
    client.change_forced_password(*res.change_token, new_password);
}
if (res.ok()) {
    auth::PoolUser me = client.me();
}
```

### Calling your API

```cpp
std::string token = client.get_access_token();   // renewed 60 s before it expires, one refresh at a time

auth::HttpRequest request;
request.url = "https://api.example.com/gateway/shop/orders";
auth::HttpResponse response = client.authorized_request(request);   // adds Authorization: Bearer ...
```

### The hosted sign-in page (desktop)

```cpp
auth::ClientOptions options;
options.redirect_uri = "http://127.0.0.1:53682/callback";
auth::Client client(issuer, "uapp_...", options);

auth::AuthorizationOptions o;
o.provider = "uprov_...";                       // optional: straight to Google, Microsoft...
auth::AuthorizationRequest request = client.build_authorization_request(o);  // state/nonce/verifier kept in storage
open_in_browser(request.url);                   // ShellExecuteW / xdg-open / open
std::string callback = wait_for_callback();     // the full redirect URL, see below
std::optional<auth::PoolUser> user = client.handle_redirect_callback(callback);
// sign out of the hosted page too:
open_in_browser(client.sign_out_redirect("http://127.0.0.1:53682/signed-out"));
```

**Getting the callback** — the SDK has no built-in listener. Two ways:

- **Loopback**: register `http://127.0.0.1:<fixed port>/callback`, open a TCP socket on `127.0.0.1:<port>` before
  opening the browser, accept one connection, read the request line (`GET /callback?code=..&state=..&iss=.. HTTP/1.1`),
  answer a small "you can close this window" page, close the socket, and pass `"http://127.0.0.1:<port>" + path` to
  `handle_redirect_callback`. Use any socket library (Boost.Asio, cpp-httplib's `Server`, Qt's `QTcpServer`, raw
  sockets). The port must be the registered one: redirect URIs match exactly.
- **Custom scheme**: register `com.example.app:/callback` and associate the scheme with your executable (Windows
  registry `HKCU\Software\Classes\com.example.app`, macOS `CFBundleURLTypes`, Linux `.desktop` file
  `MimeType=x-scheme-handler/com.example.app`); the OS starts your app with the URL as an argument; forward it to the
  running instance and call `handle_redirect_callback(url)`.

### Persisting the session

The default storage is in memory. To keep the user signed in across restarts, implement `TokenStorage`:

```cpp
class KeychainStorage : public auth::TokenStorage {     // or a 0600 file, an encrypted DB column...
public:
    std::optional<std::string> get(const std::string& key) override { /* read */ }
    void set(const std::string& key, const std::string& value) override { /* write ATOMICALLY (temp file + rename) */ }
    void remove(const std::string& key) override { /* delete */ }
};
options.storage = std::make_shared<KeychainStorage>();
```

Use the OS credential store where there is one (Windows Credential Manager / DPAPI, macOS Keychain, libsecret on
Linux). The session is stored as JSON `{accessToken, refreshToken, idToken, expiresAt (epoch ms), user, org}` under
`openback.auth.<client id>` (option `storage_key`). Before each refresh the `Client` re-reads the storage, so two
processes sharing one storage do not present an already-rotated refresh token (a lock across processes is still
up to you).

## 6. Server-side verification

```cpp
auth::VerifierOptions options;
options.audiences = {"uapp_..."};                  // the client IDs whose tokens you accept
auth::TokenVerifier verifier("https://api.example.com/gateway/shop/auth/main", options);

auth::AppUser user = verifier.verify(access_token);  // throws auth::TokenVerificationError (reason())
user.id; user.org_id; user.roles; user.has_permission("orders.read");
```

What is checked: `alg` ES256 only (never `none`, HS*, RS*), `typ` `at+jwt` (or `application/at+jwt`), the signature
with the pool's key (`kid`) from `<issuer>/.well-known/jwks.json` (cached 10 minutes; an unknown `kid` refetches at
most once every 30 s), `iss` exactly, `aud` one of `audiences`, `exp` / `nbf` / `iat` with 60 s leeway (all
configurable). No request to OpenBack per token. **Access tokens cannot be revoked before they expire**: a signed-out
user's token stays valid until `exp` (default lifetime 15 minutes, set per pool).

### Framework integration (BearerGuard)

```cpp
auth::GuardOptions requirements;
requirements.require_roles = {"admin", "owner"};        // any of
requirements.require_permissions = {"orders.read"};     // all of ("*" grants all)
requirements.require_verified_email = false;            // default
requirements.allow_anonymous = false;                   // default: guest tokens (anon: true) refused
auth::BearerGuard guard(verifier, requirements);

auth::GuardResult r = guard.check(request_authorization_header);
if (!r) { send(r.status, r.headers, r.body); return; }  // 401 + WWW-Authenticate: Bearer error="invalid_token"
handle(*r.user);                                        // 403 {"error":"insufficient_scope"}, 503 keys unavailable
```

`examples/verify_token_server.cpp` shows the handler and how to plug it into cpp-httplib; the same three lines work in
Crow, Drogon, Pistache, Boost.Beast or a FastCGI handler.

### Web apps (OidcWebClient)

```cpp
auth::OidcWebClientOptions o;
o.client_secret = secret_from_vault;
o.redirect_uri = "https://app.example.com/callback";
o.auth_method = auth::ClientAuthMethod::ClientSecretBasic;   // default; ClientSecretPost also supported
auth::OidcWebClient oidc(issuer, "uapp_...", o);

auth::AuthorizationRequest tx = oidc.authorization_url();      // session["oidc"] = tx.to_json().dump(); redirect to tx.url
auth::CallbackResult r = oidc.handle_callback(query_params, auth::AuthorizationRequest::from_json(session_tx));
// r.tokens (access, rotated refresh), r.id_token_claims (signature, iss, aud, exp, nonce verified)
auth::TokenSet next = oidc.refresh(r.tokens.refresh_token);    // store next.refresh_token: the old one is spent
oidc.revoke(next.refresh_token);
std::string logout = oidc.logout_url({id_token, "https://app.example.com/", std::nullopt});
```

### No SDK needed behind the gateway

An API published through the OpenBack gateway can use the endpoint check **"Authenticated app user"**: the gateway
verifies the token (roles, permissions, verified email, guests) and the function behind the endpoint receives
`event.user`. Use this SDK's verifier for your own servers outside the gateway.

## 7. API reference

### Client (`openback/app_auth/client.hpp`)

| Method | |
|---|---|
| `Client(issuer, client_id, ClientOptions)` | options: `redirect_uri`, `storage`, `storage_key`, `http`, `client_secret` (+ `client_secret_basic`), `timeout`, `clock` |
| `issuer()`, `client_id()` | the normalized issuer and the client ID |
| `config()` | GET `/config` (methods, providers, password policy, branding) as JSON |
| `current_user()`, `current_org()` | the stored user / organization, or nullopt |
| `access_token_claims()` | the stored access token's claims, decoded, not verified |
| `is_signed_in()` | a session is stored |
| `on_auth_state_changed(listener)` | called at once and at every change; returns the unsubscribe function |
| `get_access_token()` | the access token, renewed when it expires in 60 s or less |
| `refresh(org_id?)` | renews now (single-flight); a 401 ends the session |
| `authorized_request(HttpRequest)` | sends a request with `Authorization: Bearer` |
| `sign_up(SignUpParams)` | email, password, display name, locale?, org? → `Outcome` |
| `sign_in_with_password(email, password, org_id?)` | → `Outcome` |
| `send_email_code(email)` | a sign-in code by email (`{status: "sent"}` always) |
| `sign_in_with_email_code(EmailCodeParams)` | email + code, or the link's token → `Outcome` |
| `sign_in_anonymously()` | a guest account → `Outcome` |
| `verify_mfa(mfa_token, code)` | TOTP or recovery code → `Outcome` |
| `enroll_mfa(mfa_token?)` | a TOTP secret + `otpauth://` URI (with the sign-in's token or signed in) |
| `confirm_mfa(code, mfa_token?)` | recovery codes (+ the sign-in `Outcome` with a token) |
| `disable_mfa(code)` | turns the second factor off |
| `send_password_reset(email)` | reset email (`{status: "sent"}` always) |
| `reset_password(ResetPasswordParams)` | token, or email + code, and the new password |
| `change_forced_password(change_token, new_password)` | after `PasswordChangeRequired` |
| `verify_email(VerifyEmailParams)` | token, or email + code |
| `resend_verification()` | a new verification email (signed in) |
| `me()` | the user (with org, roles, providers, has_password) |
| `update_profile(ProfileUpdate)` | display name, photo URL, locale |
| `change_password(current?, new)` | every session ends: the local one is cleared |
| `change_email(new_email)` / `confirm_email_change({code \| token})` | change of address |
| `upgrade_anonymous(email, password)` | a guest becomes a real account (same id) |
| `delete_account(password?)` | deletes the account, clears the session |
| `sign_out(everywhere = false)` | server sign-out (best effort), always clears locally |
| `organizations()` | `{orgs, active}` (B2C: empty) |
| `create_organization(name)` | a new organization, the user its owner |
| `switch_organization(org_id)` | tokens for that organization (single-flight) |
| `members(org_id, {q, skip, limit})` | members and the pool's roles (owners/admins) |
| `add_member(org_id, NewMember)` | adds a member (may return a temporary password) |
| `set_member_roles(org_id, user_id, roles)` | changes roles |
| `remove_member(org_id, user_id)` | removes a member |
| `build_authorization_request(AuthorizationOptions)` | hosted page URL + state, nonce, PKCE verifier (kept in storage) |
| `handle_redirect_callback(url)` | checks error / state / iss, exchanges the code, checks the ID token nonce, signs in |
| `build_logout_url(post_logout_redirect_uri?, state?)` | `<issuer>/logout` with `id_token_hint` |
| `sign_out_redirect(post_logout_redirect_uri?, state?)` | `sign_out()` + the logout URL to open |

### Tokens and servers

| Symbol | |
|---|---|
| `TokenVerifier(issuer, VerifierOptions)` | `audiences` (required), `jwks_uri`, `jwks_cache_ttl` (600 s), `unknown_kid_refetch_interval` (30 s), `leeway` (60 s), `http`, `timeout`, `clock` |
| `TokenVerifier::verify(token)` | → `AppUser` |
| `TokenVerifier::verify_access_token_claims(token)` | → raw claims |
| `TokenVerifier::verify_id_token(token, nonce?)` | ID token (typ JWT) → raw claims |
| `TokenVerifier::set_jwks(jwks)` / `refresh_jwks()` | preload / fetch the keys now |
| `AppUser` | `id, pool_id, client_id, email, email_verified, anonymous, org_id, roles, permissions, attributes, session_id, amr, claims`; `has_role(r)`, `has_permission(p)` |
| `BearerGuard(verifier, GuardOptions)` / `check(header)` | → `GuardResult {allowed, status, headers, body, error, reason, user}` |
| `extract_bearer_token(header)` | the token of `Bearer <token>` |
| `OidcWebClient(issuer, client_id, OidcWebClientOptions)` | `client_secret`, `redirect_uri`, `auth_method`, `http`, `verifier`, `timeout` |
| `OidcWebClient::authorization_url(options)` | → `AuthorizationRequest` (url + transaction) |
| `OidcWebClient::handle_callback(params, tx)` / `handle_callback_url(url, tx)` | → `CallbackResult {tokens, id_token_claims}` |
| `OidcWebClient::refresh(refresh_token, org_id?)` | → `TokenSet` |
| `OidcWebClient::revoke(refresh_token)` | RFC 7009 |
| `OidcWebClient::userinfo(access_token)` | → JSON |
| `OidcWebClient::logout_url(LogoutOptions)` | `<issuer>/logout?...` |

### Helpers

| Symbol | |
|---|---|
| `build_authorization_request(issuer, client_id, redirect_uri, options)` | low level, no storage |
| `CallbackParams::from_url(url)` / `from_query(map)`, `validate_callback(params, tx, issuer)` | callback parsing and checks |
| `build_logout_url(issuer, client_id, LogoutOptions)` | |
| `generate_code_verifier()`, `code_challenge_s256(v)`, `random_url_token(n)` | PKCE / CSPRNG (OpenSSL `RAND_bytes`) |
| `parse_query_string(q)` | query / form decoding |
| `base64url_encode`, `base64url_decode`, `decode_jwt_header`, `decode_jwt_payload` | unverified decoding |
| `HttpTransport`, `make_curl_transport(CurlTransportOptions)`, `default_transport()` | HTTP layer |
| `TokenStorage`, `MemoryTokenStorage` | session storage |
| `version()` | `"1.0.0"` |

## 8. Outcomes and errors

Sign-up and sign-in calls return an `Outcome`; the session is kept only when `status == OutcomeStatus::Ok`:

| `OutcomeStatus` | Next step |
|---|---|
| `Ok` | signed in (`user`, `org` in B2B pools) |
| `VerificationRequired` | the email must be verified (`verify_email`) |
| `MfaRequired` | `verify_mfa(*mfa_token, code)` |
| `MfaEnrollRequired` | `enroll_mfa(*mfa_token)` then `confirm_mfa(code, *mfa_token)` |
| `PasswordChangeRequired` | `change_forced_password(*change_token, new_password)` |
| `Unknown` | a status this version does not know (`status_name`, `raw`) |

Failures throw `AppAuthError`: `status()` (HTTP status; 0 = no answer, `is_network_error()`), `code()`, `what()`,
`detail()`. Codes from the pool: `invalid_credentials` (401), `too_many_requests` (429), `weak_password` (422,
`detail()["problems"]`), `email_in_use` (409), `invalid_code`, `method_disabled`, `signup_disabled`,
`origin_not_allowed` (403), `token_expired` / `token_invalid` / `token_missing` / `token_revoked` /
`token_other_app` (401), `invalid_refresh_token` (401), `not_b2b` (404), `org_creation_disabled`, `not_org_admin`,
`owners_only`, `not_a_member` (403); FastAPI validation errors: `validation_error` (422); OAuth endpoints:
`invalid_grant`, `invalid_client`, `slow_down`, `login_required`, `access_denied`...; SDK checks: `invalid_state`,
`invalid_issuer`, `invalid_nonce`, `invalid_id_token`, `not_signed_in`, `network_error`, `jwks_unavailable` (503),
`no_transport`. Without a code in the answer: `http_<status>`.

A 401 with a `token_*` code on a signed-in call, or a refused refresh token, ends the local session and notifies
the listeners (signed out). `TokenVerificationError` (status 401, code `invalid_token`) has `reason()`: `malformed`,
`unsupported_alg`, `unsupported_header`, `wrong_type`, `unknown_key`, `bad_signature`, `wrong_issuer`,
`wrong_audience`, `expired`, `not_yet_valid`, `issued_in_future`, `missing_subject`, `nonce_mismatch`.

## 9. Security notes

- **Never log tokens, codes, secrets or passwords.** The SDK does not log anything and its error messages never
  contain them. Do not print `AuthorizationRequest::code_verifier`, `MfaEnrollment::secret` or recovery codes beyond
  showing them once to the user.
- **Storage**: the session holds a refresh token (long-lived). Keep it in the OS credential store or a file only the
  user can read; never in a world-readable place. The default storage is memory only.
- **Refresh rotation**: the refresh token changes at every use and presenting a used one revokes the whole session.
  The `Client` sends one refresh at a time (`std::mutex` + `std::condition_variable`; concurrent callers share the
  result), stores the new token before anyone can use it, and never retries a refresh after a network error (the error
  is surfaced; the next call tries again with the stored token). Do not share one session between processes without
  a lock across them. `switch_organization` uses the refresh token too and shares the same lock.
- **PKCE S256** is always sent (also by confidential clients), with a 64-character verifier from 48 random bytes;
  `state` is compared in constant time, `iss` checked (RFC 9207), the ID token's `nonce` checked.
- **Verification**: ES256 only, so `alg: none` / HS256-with-the-public-key confusion is impossible; JWKs that are not
  P-256 points on the curve are ignored.
- **TLS**: the libcurl transport always verifies the server certificate and host name, never follows redirects and
  only speaks http/https. Use `https://` issuers (`http://` only for local development).
- `Client` with a `client_secret` is for confidential apps only: never ship a secret inside a desktop or mobile app.

## 10. License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 GexyLab and the OpenBack contributors.
