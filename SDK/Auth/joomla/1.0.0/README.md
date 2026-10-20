# openback-app-auth-joomla

Joomla 4/5 package **OpenBack App Auth** (`pkg_openbackappauth`): visitors sign in to Joomla with an OpenBack **user
pool** (App authenticator) through the pool's hosted sign-in page — password, email code, two-step verification,
Google, Microsoft and the pool's other providers.

Version **1.0.0** · License **GPL-2.0-or-later** (the bundled PHP SDK is MIT) · package file
`openback-app-auth-joomla-1.0.0.zip` · Joomla element names without hyphens (`openbackappauth`), as Joomla requires.

## Requirements

- Joomla **4.2** or later, or **5.x**; PHP **8.1** or later with `ext-openssl` and `ext-json`.
- The site must reach the pool's address (server-to-server HTTPS).
- An OpenBack user pool with a `web` app registered for the site.

## Installation

Once published on the Joomla Extensions Directory: install "OpenBack App Auth" from System › Install › Extensions.

From this repository (path `SDK/Auth/joomla/1.0.0`):

```bash
php build.php          # or ./build.sh -> dist/openback-app-auth-joomla-1.0.0.zip
```

Then System › Install › Extensions › Upload Package File (or `php cli/joomla.php extension:install --path=...zip`).
The package installs:

| Extension | Element | What |
|---|---|---|
| Library | `lib_openbackappauth` (`libraries/openbackappauth`) | shared code (`OpenBackAppAuthJoomla\Integration`) and the bundled SDK (`OpenBackAppAuthJoomla\Sdk`) |
| System - OpenBack App Auth | `plg_system_openbackappauth` | **the settings**, the sign-in routes (com_ajax), linking, single logout — enabled on install |
| Authentication - OpenBack App Auth | `plg_authentication_openbackappauth` | completes the sign-ins verified by the system plugin — enabled on install |
| API Authentication - OpenBack App Auth | `plg_api-authentication_openbackappauth` | optional bearer tokens on the Web Services API — **disabled** on install |
| OpenBack App Auth - Login button | `mod_openbackappauth_login` (site module) | the "Sign in with OpenBack" button |

## Register your app in the pool

1. Open **System › Plugins › System - OpenBack App Auth**: the first field shows the exact **redirect URI**:
   `https://your-site.example.com/index.php?option=com_ajax&group=system&plugin=openbackappauth&format=raw&task=callback`
   (it does not depend on SEF settings; a site in a subfolder includes the folder).
2. In the OpenBack portal open the user pool, tab **Apps**, add an app of kind **`web`**:
   - **Redirect URIs**: the address above (exact match);
   - **Post-logout redirect URIs**: the site's root (`https://your-site.example.com/`, shown in the plugin's Sign-out tab)
     or the address you set as "Post-logout redirect URI";
   - save, copy the **client ID** (`uapp_...`) and the **client secret** (shown once).
3. Note the pool's address, the **issuer** (e.g. `https://api.example.com/gateway/shop/auth/main`).

## Configuration

In **System - OpenBack App Auth** (the other extensions read these settings):

| Setting | |
|---|---|
| Pool address (issuer) | https only (http only for localhost) |
| Client ID / Client secret | of the `web` app |
| Scopes | default `openid profile email` (`openid` is always added) |
| Provider (optional) | a provider id of the pool (`uprov_...`) to go straight to Google etc. |
| Button label | default label of the module |
| Create a Joomla account for new users | on by default (independent of Users › Options › Allow User Registration) |
| Create accounts only for verified email addresses | on by default; Joomla accounts need an email |
| Link existing accounts by verified email | **off** by default; Super Users are never linked this way |
| Group mapping | rows "OpenBack role → Joomla group": a user gets the groups of **every** rule whose role they have (ID token `roles`, in the active organization); none: the default group |
| Default group | default: the "New User Registration Group" of Users › Options |
| Update the groups at every sign-in | off by default; only groups named in the mapping change, others stay; never Super Users |
| Single logout | on by default |
| Post-logout redirect URI | where the pool returns after signing out; register it on the app |

Then publish the module **OpenBack App Auth - Login button** in a position (Content › Site Modules › New). Module
options: label, address after sign-in (default: the current page), sign-out button for signed-in users, "Link my
OpenBack account" for signed-in users whose account is not linked.

Optional: enable **API Authentication - OpenBack App Auth** to accept pool access tokens on `/api/index.php/v1/...`
(see below). Its option "Other accepted client IDs" lists other apps of the pool (e.g. your mobile app).

## Quick start (what the user sees)

1. A visitor clicks **Sign in with OpenBack** (module) → the pool's sign-in page (password, email code, providers; the
   pool handles two-step verification, password changes and email verification itself).
2. Back on the site the visitor is signed in to the linked Joomla account (created on the first sign-in when allowed)
   and lands on the page where they started.
3. **Log out** (module or the core login module) also ends the pool's session and returns to the post-logout URI.

Calling your own API from the site is not needed: Joomla keeps its own session. For apps (mobile, SPA) calling the
Joomla Web Services API, enable the API authentication plugin.

## How it works

- **Routes** (com_ajax, system plugin): `...&task=login[&return=<base64 URL of this site>]`, `...&task=callback` (the
  redirect URI), `...&task=link&<CSRF token>=1` (signed-in users link their account).
- **Sign-in**: state, nonce and a PKCE verifier (S256) are kept **server-side** in the Joomla session (at most 5 per
  browser, 10 minutes, one use). The callback checks state (constant time) and `iss`, exchanges the code with
  `client_secret_basic`, verifies the ID token (ES256 with the pool's JWKS cached in Joomla's cache group
  `openbackappauth`, issuer, audience, expiry, nonce, `at_hash`), revokes the refresh token it does not need, finds or
  creates the Joomla user, then calls `$app->login()` with a one-time `VerifiedLogin` object in the options: the
  authentication plugin accepts only that object (a request can never create it), so `onUserLogin` and the other user
  plugins run as for any sign-in. Blocked or not activated accounts are refused.
- **Linking**: rows of `#__user_profiles`: `openback.sub` (the pool user id `usr_...`), `openback.iss`, `openback.pool`.
  A link matches by sub and issuer or pool id. Deleting a Joomla user removes its link; uninstalling the package
  removes every link (the Joomla accounts stay).
- **Single logout**: the ID token is kept in the Joomla session; at `onUserLogout` (high priority) it is captured, and
  at `onUserAfterLogout` the browser goes to the pool's `/logout?client_id=…&id_token_hint=…&post_logout_redirect_uri=…`.
- **Web Services API (optional)**: `Authorization: Bearer <pool access token>` is verified locally (ES256, `typ:
  at+jwt`, issuer, audience among this app's and the extra client IDs, expiry); guest tokens are refused; the request
  runs as the linked user, who also needs the **Web Services Login** permission (`core.login.api`, Super Users only by
  default). Tokens that are not JWTs (Joomla API tokens) are left to the core token plugin. Access tokens cannot be
  revoked before they expire (15 minutes by default).
- Joomla 4 calls `onUserAuthenticate($credentials, $options, $response)`; Joomla 5 dispatches an
  `AuthenticationEvent`: both are supported.

## API reference (PHP classes)

| Class | |
|---|---|
| `OpenBackAppAuthJoomla\Integration\Settings` | `load()`, `issuer()`, `clientId()`, `configured()`, `groupRules()`, `defaultGroup()`, `oidc()`, `verifier()`; static `redirectUri()`, `loginUrl($return)`, `linkUrl($return)` |
| `OpenBackAppAuthJoomla\Integration\UserLinker` | `findLinked($sub, $pool)`, `linkedSub($id)`, `link($id, $claims)`, `unlink($id)`, `resolve($claims)` (User or error code), `syncGroups()` |
| `OpenBackAppAuthJoomla\Integration\GroupMapper` | `rules($stored)`, `resolve($rules, $roles, $default)`, `sync($rules, $current, $roles, $default)` (pure) |
| `OpenBackAppAuthJoomla\Integration\PendingSignIns` | `add($list, $tx, $now)`, `take($list, $state, $now)` (pure) |
| `OpenBackAppAuthJoomla\Integration\VerifiedLogin` | the one-time proof passed to `$app->login()` |
| `OpenBackAppAuthJoomla\Integration\JoomlaHttpTransport`, `JoomlaJwksCache` | the SDK on Joomla's HTTP package and cache |
| `OpenBackAppAuthJoomla\Sdk\...` | the bundled [openback-app-auth-php](../../php/1.0.0) (`TokenVerifier`, `OidcWebClient`, ...) |

## Outcomes and errors

A failed sign-in returns to the page (or the login page) with an error message (en-GB / it-IT): invalid or expired
state, cancelled (`access_denied`, `login_required`), sign-in failed, pool unreachable, not configured, email already
used (linking off), email not verified, no account (creation off), no email, Super User link refused, already linked,
registration failed, login refused (blocked / not activated), library missing. The pool's own error texts are never
shown.

## Security notes

- The client secret is stored in the system plugin's parameters (database), visible to whoever can edit plugins;
  never sent to browsers.
- State, nonce and PKCE verifier come from `random_bytes()` and live in the server-side session; one use.
- ID tokens are verified locally: only ES256, issuer, audience, expiry, nonce, `at_hash`.
- Tokens, codes and secrets are never logged. The refresh token is revoked right after sign-in.
- The authentication plugin never accepts passwords; it only completes sign-ins verified in the same request.
- Linking by email is off by default and never applies to Super Users; group sync never changes Super Users.
- The link route requires the session's CSRF token; return addresses must be internal (`Uri::isInternal`).

## Development

- Tests (pure logic without Joomla: group mapping, pending sign-ins, the bundled SDK):
  `composer install && vendor/bin/phpunit` (then remove `vendor/` and `composer.lock`).
- The bundled SDK in `packages/lib_openbackappauth/src/Sdk/` is generated: `php tools/sync-sdk.php` (or
  `php build.php --sync`) copies `SDK/Auth/php/1.0.0/src`, prefixes its namespace and adds Joomla's `_JEXEC` guard.
- `build.php` lints every PHP file (`php -l`) and checks every manifest XML before packing.

## License

GPL-2.0-or-later — see [LICENSE](LICENSE). Copyright (C) 2026 GexyLab and the OpenBack contributors. The bundled
openback-app-auth-php is MIT-licensed (`packages/lib_openbackappauth/LICENSE-SDK.txt`).
