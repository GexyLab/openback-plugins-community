# openback-app-auth-wordpress

WordPress plugin "OpenBack App Auth": visitors sign in to WordPress with an OpenBack **user pool** (App
authenticator) through the pool's hosted sign-in page — password, email code, two-step verification, Google,
Microsoft and the pool's other providers.

Version **1.0.0** · License **GPL-2.0-or-later** (the bundled PHP SDK is MIT) · plugin slug and text domain
`openback-app-auth-wordpress`

## Requirements

- WordPress **6.0** or later, PHP **8.1** or later with `ext-openssl` and `ext-json`.
- The site must reach the pool's address (server-to-server HTTPS) and the WordPress REST API must stay reachable by
  signed-out visitors for the two routes of the plugin.
- An OpenBack user pool with a `web` app registered for the site.

## Installation

Once published on WordPress.org: Plugins › Add New, search "OpenBack App Auth".

From this repository (path `SDK/Auth/wordpress/1.0.0`):

```bash
php build.php          # or ./build.sh -> dist/openback-app-auth-wordpress-1.0.0.zip
```

Then Plugins › Add New › Upload Plugin, choose the zip, activate. (Or copy the directory to
`wp-content/plugins/openback-app-auth-wordpress/`.) Composer is not needed at runtime.

## Register your app in the pool

1. In WordPress open **Settings › OpenBack App Auth**: the page shows the exact **Redirect URI** of the site:
   - pretty permalinks: `https://your-site.example.com/wp-json/openback-app-auth/v1/callback`
   - plain permalinks: `https://your-site.example.com/?rest_route=/openback-app-auth/v1/callback`

   (It follows the permalink settings: change them and register the new address.)
2. In the OpenBack portal open the user pool, tab **Apps**, add an app of kind **`web`**:
   - **Redirect URIs**: the address above (exact match);
   - **Post-logout redirect URIs**: the site's home (`https://your-site.example.com/`) or the address you set in
     "Post-logout redirect URI";
   - save, copy the **client ID** (`uapp_...`) and the **client secret** (shown once).
3. Note the pool's address, the **issuer** (e.g. `https://api.example.com/gateway/shop/auth/main`).

## Configuration (Settings › OpenBack App Auth)

| Setting | |
|---|---|
| Pool address (issuer) | https only (http only for localhost) |
| Client ID / Client secret | of the `web` app; the secret is never shown back; `define( 'OPENBACK_APP_AUTH_CLIENT_SECRET', '...' );` in wp-config.php keeps it out of the database |
| Scopes | default `openid profile email` (`openid` is always added) |
| Provider (optional) | a provider id of the pool (`uprov_...`) to go straight to Google etc. |
| Button label | default "Sign in with OpenBack" |
| Create a WordPress account for new users | on by default |
| Create accounts only for verified email addresses | on by default |
| Link existing accounts by verified email address | **off** by default; administrators are never linked this way |
| Role mapping | one rule per line `openback_role = wordpress_role`; the first rule matching one of the user's roles (ID token `roles`, in the active organization) wins |
| Default role | when no rule matches (default: the site's default role) |
| Update the role at every sign-in | off by default; never changes administrators |
| Hide the WordPress password form | cosmetic; the form stays at `wp-login.php?openback_password=1` |
| Single logout | on by default: signing out of WordPress ends the pool's session too |
| Post-logout redirect URI | where the pool returns after signing out; register it on the app |
| REST API bearer tokens | **off** by default; see below |
| Other accepted client IDs | client IDs of other apps of the same pool whose tokens the REST API accepts (e.g. your mobile app) |

"Check the connection to the pool" fetches the pool's discovery document and checks the issuer.

## Quick start (what the user sees)

1. A visitor clicks **Sign in with OpenBack** (login page, shortcode or block) → the pool's sign-in page (password,
   email code, providers; the pool handles two-step verification, password changes and email verification itself).
2. Back on the site the visitor is signed in to the linked WordPress account (created on the first sign-in when
   allowed) and lands where they started (`redirect_to`) — the dashboard for editors, the home page otherwise.
3. **Log out** also ends the pool's session and returns to the post-logout URI.

Your own API or a mobile app can call the WordPress REST API with the pool's access tokens (option "REST API bearer
tokens"), e.g. `curl -H "Authorization: Bearer <access token>" https://your-site/wp-json/wp/v2/users/me`.

## How it works

- **Sign-in**: the button links to `GET /wp-json/openback-app-auth/v1/login` (`redirect_to` optional), which creates
  state, nonce and a PKCE verifier, keeps them **server-side** in a transient keyed by a random HttpOnly, SameSite=Lax
  cookie (`openback_app_auth_tx`, 10 minutes, one use), and redirects to the pool's `/authorize`. The pool returns to
  `GET /wp-json/openback-app-auth/v1/callback`: the plugin checks state (constant time) and `iss`, exchanges the code
  with `client_secret_basic` and the verifier, verifies the ID token (ES256 signature with the pool's JWKS cached in a
  transient, issuer, audience, expiry, nonce, `at_hash`), revokes the refresh token it does not need, finds or creates
  the WordPress user, and signs in with `wp_set_auth_cookie()` (the core `wp_login` action runs).
- **Linking**: user meta `openback_app_auth_sub` (the pool user id `usr_...`), `openback_app_auth_iss` and
  `openback_app_auth_pool`. A user signs in to the linked account; with "link by verified email" an existing account
  with the same verified email is linked once; administrators link their own account from **Users › Profile › Link my
  OpenBack account** (and can remove the link there).
- **Single logout**: the ID token is kept in the WordPress session; `wp-login.php?action=logout` then redirects to the
  pool's `/logout?client_id=…&id_token_hint=…&post_logout_redirect_uri=…`. (Logouts done by other plugins with their own
  redirect skip this step.)
- **REST API (optional)**: with the option on, a request to the WordPress REST API carrying
  `Authorization: Bearer <pool access token>` runs as the WordPress user linked to the token's user. The token is
  verified locally (ES256, issuer, audience among this app's and the extra client IDs, expiry, `typ: at+jwt`); guest
  tokens are refused; an invalid token answers 401. Access tokens cannot be revoked before they expire (15 minutes by
  default). Apache may drop the `Authorization` header: add `SetEnvIf Authorization "(.*)" HTTP_AUTHORIZATION=$1` to
  `.htaccess` if needed.

## Shortcode, block, hooks

- Shortcode: `[openback_app_auth_login label="Sign in" redirect_to="https://your-site/account/" show_logout="1"]`
  (nothing is shown to signed-in visitors unless `show_logout="1"`).
- Block: **OpenBack sign-in button** (`openback-app-auth/login-button`, attributes `label`, `redirectTo`,
  `showLogout`), rendered by PHP.
- Direct link: `/wp-json/openback-app-auth/v1/login?redirect_to=...`.
- Filters: `openback_app_auth_allow_login` (`true|false|WP_Error`, `$user`, `$claims`), `openback_app_auth_role`
  (`$role`, `$openback_roles`), `openback_app_auth_rest_allow` (`true|false`, `$user`, `$app_user`), and the core
  `login_redirect`.
- Actions: `openback_app_auth_user_created` (`$user`, `$claims`), `openback_app_auth_login` (`$user`, `$claims`).

## API reference (PHP classes)

| Class | |
|---|---|
| `OpenBackAppAuthWp\Plugin` | `instance()`, `boot()`, `settings()`, `users()`, `states()`, `oidc()`, `rest_verifier()`, `transport()` |
| `OpenBackAppAuthWp\Settings` | the option `openback_app_auth_settings`: `all()`, `get()`, `issuer()`, `client_id()`, `client_secret()`, `configured()`, `redirect_uri()`, `sanitize()` |
| `OpenBackAppAuthWp\Login` | REST routes, callback, linking, single logout; `start_url($redirect_to)`, `error_message($code)` |
| `OpenBackAppAuthWp\Users` | `find_linked($sub, $pool)`, `link()`, `unlink()`, `linked_sub()`, `resolve($claims)`, `role_for($roles)`, `apply_role()` |
| `OpenBackAppAuthWp\LoginButton` | `html($label, $redirect_to, $show_logout)`, shortcode, block, login form |
| `OpenBackAppAuthWp\RestBearerAuth` | `determine_current_user` / `rest_authentication_errors` filters |
| `OpenBackAppAuthWp\RoleMapper` | `parse($text)`, `normalize($text, $roles)`, `resolve($rules, $roles, $default, $valid)` (pure) |
| `OpenBackAppAuthWp\StateStore` | `put($tx)`, `take($state)` (pure, backend = transients) |
| `OpenBackAppAuthWp\Sdk\...` | the bundled [openback-app-auth-php](../../php/1.0.0) (`TokenVerifier`, `OidcWebClient`, ...) |

## Outcomes and errors

Failed sign-ins return to `wp-login.php?openback_app_auth_error=<code>` with a message: `invalid_state` (expired or
another browser), `cancelled` (the user cancelled, `access_denied`, `login_required`), `sign_in_failed`,
`unavailable` (the pool cannot be reached), `not_configured`, `email_exists` (an account with that email exists and
linking by email is off), `email_not_verified`, `no_account` (creation off), `admin_link_refused`, `already_linked`,
`registration_failed`, `not_allowed` (refused by the `openback_app_auth_allow_login` filter). The pool's own error
texts are never shown.

## Security notes

- The client secret stays on the server (option or wp-config constant), never in pages; it is never displayed again.
- State, nonce and PKCE verifier come from `random_bytes()` and live server-side; the cookie only holds a random id
  (its SHA-256 names the transient). One use, 10 minutes.
- ID tokens are verified locally: only ES256, issuer, audience, expiry, nonce, `at_hash`.
- Tokens, codes and secrets are never logged. The refresh token is revoked right after sign-in (WordPress keeps its
  own session); the ID token is kept in the WordPress session only for the logout hint.
- Settings: `manage_options` capability, Settings API nonces, sanitized options; profile actions: nonces and the
  `edit_user` capability; every output escaped.
- Linking by email is off by default and never applies to administrators; role mapping never changes administrators.
- Hiding the password form is not a security control.

## Development

- Tests (pure logic without WordPress: role mapping, state store, the bundled SDK): `composer install && vendor/bin/phpunit`
  (then remove `vendor/` and `composer.lock`).
- The bundled SDK in `lib/openback-app-auth-php/` is generated: `php tools/sync-sdk.php` (or `php build.php --sync`)
  copies `SDK/Auth/php/1.0.0/src` and prefixes its namespace.
- Lint: `build.php` runs `php -l` on every packed PHP file.

## License

GPL-2.0-or-later — see [LICENSE](LICENSE). Copyright (C) 2026 GexyLab and the OpenBack contributors. The bundled
openback-app-auth-php is MIT-licensed (`lib/openback-app-auth-php/LICENSE`).
