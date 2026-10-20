# openback-app-auth-python

The Python SDK of OpenBack's **App authenticator**: sign the users of your apps in to an OpenBack **user pool** and
verify the pool's tokens in your Python APIs (FastAPI, Flask, Django).

Version **1.0.0** · License **MIT** · Distribution name `openback-app-auth-python` · import package `openback_app_auth`
(PyPI names use hyphens, Python modules cannot: the import name is the closest legal form).

- `Client` / `AsyncClient` — for apps: CLI tools, desktop apps, scripts, and servers acting for a user. Sign-up,
  password, email code, guest accounts, two-step verification, the hosted sign-in page (OpenID Connect + PKCE),
  profile, organizations (B2B).
- `TokenVerifier` → `AppUser` — for APIs: verify access tokens locally with the pool's public keys.
- `OidcWebClient` / `AsyncOidcWebClient` — for `web` apps with a client secret: sign-in through the hosted page.
- `openback_app_auth.fastapi`, `.flask`, `.django` — ready-made guards.

## Requirements

- Python **3.9+**
- [`httpx`](https://www.python-httpx.org/) ≥ 0.24 and [`PyJWT[crypto]`](https://pyjwt.readthedocs.io/) ≥ 2.8
  (brings `cryptography`)
- Optional: FastAPI ≥ 0.100, Flask ≥ 2.2, Django ≥ 4.2 (only for the matching integration module)

## Installation

Once published on PyPI:

```bash
pip install openback-app-auth-python
pip install "openback-app-auth-python[fastapi]"     # or [flask], [django]
```

Until then, from this repository:

```bash
git clone https://github.com/GexyLab/openback-plugins-community.git
pip install "./openback-plugins-community/SDK/Auth/python/1.0.0[fastapi]"
# or, without cloning:
pip install "openback-app-auth-python @ git+https://github.com/GexyLab/openback-plugins-community.git@production#subdirectory=SDK/Auth/python/1.0.0"
```

Build a wheel and an sdist yourself: `python -m pip install build && python -m build` in this directory (output in
`dist/`).

## Register your app in the pool

In the OpenBack portal open the user pool, tab **Apps**, and register the app. Note the pool's address (the
**issuer**, e.g. `https://api.example.com/gateway/shop/auth/main`) and the app's **client ID** (`uapp_...`).

| Your app | Kind | Register |
|---|---|---|
| CLI / desktop app (this SDK's `Client`) | `native` | a redirect URI if you use the hosted page: a loopback one with a fixed port, e.g. `http://127.0.0.1:53682/callback` (`http://` is allowed only for localhost), or a custom scheme `com.example.app:/callback` |
| Web app with its own server (`OidcWebClient`) | `web` | the exact redirect URI(s), e.g. `https://app.example.com/callback`; post-logout redirect URIs; keep the **client secret** on the server |
| A server calling the JSON API for its users | `backend` | nothing else; the JSON API is called without `Origin` |
| An API that only verifies tokens (`TokenVerifier`) | — | nothing: accept the client IDs of the apps that call it |

Redirect URIs must match a registered one **exactly** (scheme, host, port, path).

## Quick start

### Sign in with a password (and the two-step branch)

```python
from openback_app_auth import Client, FileStorage, AppAuthError

ISSUER = "https://api.example.com/gateway/shop/auth/main"
auth = Client(ISSUER, "uapp_...", storage=FileStorage("~/.myapp/session.json"))

try:
    outcome = auth.sign_in_with_password("ada@example.com", "correct horse battery staple")
except AppAuthError as err:          # err.code: "invalid_credentials", "too_many_requests", ...
    raise SystemExit(f"Sign-in failed: {err.message}")

if outcome.status == "mfa_required":
    outcome = auth.verify_mfa(outcome.mfa_token, input("Authenticator code: "))
elif outcome.status == "mfa_enroll_required":
    enrollment = auth.enroll_mfa(outcome.mfa_token)         # show enrollment.otpauth_uri as a QR code
    confirmation = auth.confirm_mfa(input("Code: "), outcome.mfa_token)
    print("Save these recovery codes:", confirmation.recovery_codes)
    outcome = confirmation.outcome
elif outcome.status == "password_change_required":
    auth.change_forced_password(outcome.change_token, input("New password: "))
    outcome = auth.sign_in_with_password("ada@example.com", "<the new password>")
elif outcome.status == "verification_required":
    raise SystemExit("Check your inbox and verify your email first")

if outcome.status == "ok":
    print("Hello", auth.current_user.display_name)
```

On Python 3.10+ you can `match outcome:` on the classes (`case MfaRequired(mfa_token=t): ...`).

### The hosted sign-in page (desktop / CLI)

```python
from openback_app_auth import Client
from openback_app_auth.loopback import sign_in_with_browser

auth = Client(ISSUER, "uapp_...", redirect_uri="http://127.0.0.1:53682/callback")
user = sign_in_with_browser(auth)                       # opens the browser, waits for the redirect
user = sign_in_with_browser(auth, provider="google")    # straight to a social provider
```

The loopback helper is optional: with any other redirect (custom scheme handled by your app, an embedded web view)
call `req = auth.build_authorization_request(...)`, open `req.url`, and pass the callback URL to
`auth.handle_redirect_callback(url)`.

### Calling your API

```python
token = auth.get_access_token()             # renewed automatically when it expires in < 60 s
r = auth.request("GET", "https://api.example.com/orders")          # adds Authorization: Bearer
r = httpx.get("https://api.example.com/orders", auth=auth.auth)    # or with any httpx client
```

### Async

```python
from openback_app_auth import AsyncClient

async with AsyncClient(ISSUER, "uapp_...") as auth:
    outcome = await auth.sign_in_with_password(email, password)
    token = await auth.get_access_token()
```

## Server-side verification

```python
from openback_app_auth import TokenVerifier, TokenVerificationError

verifier = TokenVerifier(ISSUER, ["uapp_web...", "uapp_mobile..."])   # the client IDs you accept
user = verifier.verify(token)              # or: await verifier.verify_async(token)
user.id, user.email, user.org_id, user.roles, user.has_role("admin"), user.has_permission("orders.read")
```

The verifier fetches `<issuer>/.well-known/jwks.json` (cached 10 minutes; an unknown `kid` refetches at most once every
30 s), accepts **only ES256**, requires header `typ` `at+jwt`, `iss` equal to the issuer, `aud` one of your client IDs,
and checks `exp` / `nbf` / `iat` with 60 s of leeway. Verification is local: no call to OpenBack per request. Access
tokens **cannot be revoked before they expire** — keep their lifetime short (pool default: 15 minutes).

### FastAPI

```python
from fastapi import Depends, FastAPI
from openback_app_auth import AppUser, TokenVerifier
from openback_app_auth.fastapi import install_error_handler, require_app_user

verifier = TokenVerifier(ISSUER, "uapp_...")
app = FastAPI()
install_error_handler(app)          # bodies exactly {"error": "..."} (else FastAPI wraps them in "detail")

@app.get("/orders")
async def orders(user: AppUser = Depends(require_app_user(verifier, require_permissions=["orders.read"]))):
    return {"user": user.id}
```

`optional_app_user(verifier)` returns `None` when there is no `Authorization` header.

### Flask

```python
from flask import Flask, g
from openback_app_auth.flask import require_app_user

@app.get("/orders")
@require_app_user(verifier, require_roles=["admin"])
def orders():
    return {"user": g.app_user.id}
```

### Django

```python
# settings.py
OPENBACK_APP_AUTH = {"issuer": ISSUER, "audience": ["uapp_..."]}
MIDDLEWARE = [..., "openback_app_auth.django.AppAuthMiddleware"]     # sets request.app_user

# views.py
from openback_app_auth.django import require_app_user

@require_app_user(require_roles=["admin"])
def orders(request):
    return JsonResponse({"user": request.app_user.id})
```

All three answer **401** `{"error": "invalid_token"}` with `WWW-Authenticate: Bearer error="invalid_token"` when the
token is missing or invalid, **403** `{"error": "insufficient_scope"}` (`WWW-Authenticate: Bearer
error="insufficient_scope"`) when an option fails, and **503** `{"error": "temporarily_unavailable"}` when the pool's
keys were never reachable. Options: `require_roles` (at least one), `require_permissions` (all; `"*"` grants all),
`require_verified_email` (default `False`), `allow_anonymous` (default `False`: guest tokens with `anon: true` are
refused) — the same rules as the gateway check below.

### Web apps: `OidcWebClient`

```python
from openback_app_auth import OidcWebClient

oidc = OidcWebClient(ISSUER, "uapp_...", CLIENT_SECRET, redirect_uri="https://app.example.com/callback")

req = oidc.authorization_url()                       # login route
session["oidc"] = req.to_dict(); return redirect(req.url)

tokens = oidc.handle_callback(request.args, session.pop("oidc"))     # callback route
tokens.id_token_claims["sub"], tokens.access_token, tokens.refresh_token
```

The ID token is verified with the pool's keys (signature, issuer, audience, expiry, nonce, `at_hash`). See
`examples/flask_oidc_web_login.py` for a complete app.

### No SDK needed behind the OpenBack gateway

An API published through the OpenBack gateway can use the endpoint check **"Authenticated app user"** instead: the
gateway verifies the token (roles, permissions, verified email, guests, organization) and the function behind the
endpoint receives `event.user`.

## API reference

### `Client(issuer, client_id, *, redirect_uri=None, storage=None, storage_key=None, http_client=None, client_secret=None, token_endpoint_auth_method="client_secret_basic", timeout=30.0)`

`AsyncClient` has the same constructor (`http_client` is an `httpx.AsyncClient`) and the same methods, awaited.

| Member | |
|---|---|
| `config()` | the pool's public configuration (methods, sign-up, password policy, MFA, providers, branding) |
| `current_user` / `current_org` | the signed-in `PoolUser` / active `ActiveOrg`, or `None` |
| `access_token_claims` | the stored access token's claims, decoded **without** verification |
| `is_signed_in` / `id_token` | session present / ID token of the last hosted-page sign-in |
| `on_auth_state_changed(fn)` | `fn(user, org)` now and on every change; returns `unsubscribe()` |
| `get_access_token()` | a valid access token (refreshes when it expires in < 60 s) |
| `refresh(org_id=None)` | renew now (single-flight); `org_id` asks for another organization |
| `auth` / `request(method, url, **kw)` | `httpx.Auth` adding the bearer token / call your API with it |
| `sign_up(email, password, *, display_name, locale, org_id)` | create an account → `Outcome` |
| `sign_in_with_password(email, password, *, org_id)` | → `Outcome` |
| `send_email_code(email)` | email a one-time code + link |
| `sign_in_with_email_code(email, code, *, token, org_id)` | → `Outcome` |
| `sign_in_anonymously()` | guest account → `Outcome` |
| `verify_mfa(mfa_token, code)` | second factor (TOTP or recovery code) → `Outcome` |
| `enroll_mfa(mfa_token=None)` | new TOTP secret → `MfaEnrollment(secret, otpauth_uri)` |
| `confirm_mfa(code, mfa_token=None)` | → `MfaConfirmation(recovery_codes, outcome)` |
| `disable_mfa(code)` | turn two-step verification off |
| `send_password_reset(email)` | email a reset code + link |
| `reset_password(new_password, *, token \| email+code)` | set a new password |
| `change_forced_password(change_token, new_password)` | answer `password_change_required` |
| `verify_email(*, token \| email+code)` | → `PoolUser` |
| `resend_verification()` | the verification email again |
| `me()` | the user, fresh → `PoolUser` (with `org_id`, `roles`, `providers`, `has_password`) |
| `update_profile(*, display_name, photo_url, locale)` | → `PoolUser` |
| `change_password(new_password, current_password=None)` | every session ends: signs the client out |
| `change_email(new_email)` / `confirm_email_change(*, code \| token)` | change of address → `PoolUser` |
| `upgrade_anonymous(email, password)` | guest → real account → `PoolUser` |
| `delete_account(password=None)` | delete the account, sign out |
| `sign_out(everywhere=False)` | best-effort server call, always clears locally |
| `organizations()` | → `OrganizationList(orgs, active)` (B2C: empty) |
| `create_organization(name)` | → `Organization` (the user is its owner) |
| `switch_organization(org_id)` | tokens for that organization → `ActiveOrg` |
| `members(org_id, *, q, skip, limit)` | → `MemberPage(items, total, roles)` (owners/admins) |
| `add_member(org_id, email, *, display_name, password, roles)` | → `AddedMember` (maybe a `temporary_password`) |
| `set_member_roles(org_id, user_id, roles)` / `remove_member(org_id, user_id)` | |
| `build_authorization_request(*, redirect_uri, provider, org_id, prompt, screen_hint, login_hint, max_age, scope, ui_locales)` | → `AuthorizationRequest(url, state, nonce, code_verifier, redirect_uri)`, saved in the storage |
| `handle_redirect_callback(url, authorization_request=None)` | checks error/state/iss, exchanges the code, checks the nonce → `PoolUser` |
| `build_logout_url(post_logout_redirect_uri=None, state=None)` | the pool's end-session URL |
| `close()` / `aclose()` | close the client's own HTTP connections |

### `openback_app_auth.loopback`

| | |
|---|---|
| `sign_in_with_browser(client, *, redirect_uri, open_browser=True, on_url=None, timeout=300, **options)` | hosted page in the system browser + one-shot server on 127.0.0.1 → `PoolUser` |
| `sign_in_with_browser_async(client, ...)` | the same for `AsyncClient` |
| `sign_out_with_browser(client, *, post_logout_redirect_uri, state, everywhere, open_browser=True)` / `sign_out_with_browser_async` | `sign_out()` + the pool's end-session page in the browser → its URL |
| `LoopbackServer(redirect_uri).wait(timeout)` | the server alone → the callback URL |

### `TokenVerifier(issuer, audience, *, jwks_uri=None, leeway=60, cache_ttl=600, min_refetch_interval=30, http_client=None, async_http_client=None)`

| | |
|---|---|
| `verify(token)` / `verify_async(token)` | → `AppUser`, or `TokenVerificationError` (401: `token_missing`, `token_invalid`, `token_expired`) / `JwksUnavailableError` (503) |
| `verify_id_token(token, *, nonce, access_token, audience)` / `verify_id_token_async(...)` | → the ID token's claims |

`AppUser`: `id`, `pool_id`, `client_id`, `email`, `email_verified`, `anonymous`, `org_id`, `roles`, `permissions`,
`attributes`, `session_id`, `amr`, `scope`, `claims`; `has_role(r)`, `has_any_role(*r)`, `has_permission(p)`.

### `OidcWebClient(issuer, client_id, client_secret, *, redirect_uri=None, scope="openid profile email", token_endpoint_auth_method="client_secret_basic", http_client=None, verifier=None, leeway=60)`

`AsyncOidcWebClient`: same, awaited.

| | |
|---|---|
| `authorization_url(*, redirect_uri, scope, provider, org_id, prompt, screen_hint, login_hint, max_age, ui_locales)` | → `AuthorizationRequest` (`.url`; store `.to_dict()` in the session) |
| `handle_callback(params, transaction)` | → `TokenSet` with verified `id_token_claims` |
| `refresh(refresh_token, *, org_id=None)` | → `TokenSet` (store the NEW refresh token) |
| `revoke(refresh_token)` | RFC 7009 revocation |
| `userinfo(access_token)` | → `dict` |
| `logout_url(*, id_token_hint, post_logout_redirect_uri, state)` | the pool's end-session URL |

### Storage

`Storage` is a protocol with `get(key) -> str | None`, `set(key, value)`, `remove(key)`. Provided: `MemoryStorage`
(default) and `FileStorage(path)` (JSON file, mode 0600, atomic replace). The session is one JSON document
`{accessToken, refreshToken, idToken, expiresAt (epoch ms), user, org}` under `openback.auth.<client_id>` — the same
as the other OpenBack App Auth SDKs. Plug the OS keyring, a database or your web framework's server-side session by
implementing the three methods.

## Outcomes and errors

Every sign-in method returns an `Outcome` with a `status`; the session is kept **only** on `ok`:

| `status` | class | next step |
|---|---|---|
| `ok` | `SignedIn(user, org)` | signed in |
| `verification_required` | `VerificationRequired` | the user verifies the email (code + link sent) |
| `mfa_required` | `MfaRequired(mfa_token)` | `verify_mfa(mfa_token, code)` |
| `mfa_enroll_required` | `MfaEnrollRequired(mfa_token)` | `enroll_mfa(mfa_token)` then `confirm_mfa(code, mfa_token)` |
| `password_change_required` | `PasswordChangeRequired(change_token)` | `change_forced_password(change_token, new)` then sign in |
| anything else | `OtherOutcome(status, raw)` | a newer service; inspect `raw` |

Failures raise `AppAuthError` with `status` (HTTP status; `0` for a network error), `code` (`http_<status>` when the
service gave none), `message` and `detail` (the raw `detail`, e.g. `{"code": "weak_password", "problems": [...]}`).
Common codes: `invalid_credentials` (401), `too_many_requests` (429), `weak_password` (422), `email_in_use` (409),
`invalid_code`, `method_disabled`, `signup_disabled`, `origin_not_allowed` (403), `token_expired` / `token_invalid` /
`token_missing` / `token_revoked` / `token_other_app` (401), `invalid_refresh_token` (401), `not_b2b` (404),
`org_creation_disabled`, `not_org_admin`, `owners_only`, `not_a_member` (403), `not_signed_in` (raised locally);
OIDC: `invalid_state`, `invalid_issuer`, `invalid_nonce`, `invalid_id_token`, `invalid_grant`, `invalid_client`,
`login_required`, `access_denied`. A 401 with a `token_*` code on a signed-in call, or `invalid_refresh_token`, means
the session is dead: the client clears it and notifies the listeners (`err.session_ended` is `True`).

## Security notes

- **Storage**: the default is in memory. `FileStorage` writes a 0600 file (on Windows it relies on the folder's ACL —
  keep it under the user's profile). For desktop apps consider the OS keyring through a custom `Storage`.
- **Refresh rotation**: every refresh returns a new refresh token and kills the old one; presenting a used one revokes
  the whole session. The client therefore refreshes **one at a time** (a lock), stores the new token atomically,
  follows a newer token written to the same storage by another client, and **never retries** a refresh after a
  network error (the request may have reached the server). Within one process that is safe; two processes sharing a
  `FileStorage` can still race — give each process its own session.
- **PKCE** S256 is always sent (also by confidential clients); `state` and `nonce` come from `secrets` and are checked
  in constant time; the `iss` of the callback is checked (RFC 9207). `OidcWebClient` verifies the ID token's
  signature; `Client` checks the ID token's issuer, audience and nonce (it came straight from the token endpoint over
  TLS).
- **Verification** accepts only ES256 (no `none`, `HS*`, `RS*`), checks `typ`, issuer, audience and expiry. Access
  tokens are valid until they expire: keep them short-lived.
- **Never log tokens**, codes, secrets or passwords: the SDK never does, and its objects hide them from `repr()`.
  Keep `client_secret` on servers only.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 GexyLab and the OpenBack contributors.
