=== OpenBack App Auth ===
Contributors: gexylab
Tags: openid connect, oidc, single sign-on, login, authentication
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 8.1
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Sign in to WordPress with an OpenBack user pool: OpenID Connect with PKCE, account linking, role mapping, single logout.

== Description ==

OpenBack App Auth connects your site to an OpenBack **user pool** (OpenBack's App authenticator). Visitors sign in with
the pool's hosted sign-in page (password, email code, two-step verification, Google, Microsoft and the other providers
of the pool) and arrive in WordPress signed in.

* "Sign in with ..." button on the login page, as a shortcode `[openback_app_auth_login]` and as a block.
* OpenID Connect authorization code flow with PKCE S256; state, nonce and verifier kept server-side; ID token verified
  locally with the pool's public keys (ES256).
* Links WordPress users to pool users (user meta), creates accounts for new users (optional), links existing accounts
  by verified email (optional, off by default; never administrators), "Link my OpenBack account" on the profile.
* Role mapping: OpenBack role → WordPress role, default role, optional update at every sign-in.
* Single logout: signing out of WordPress also ends the pool's session.
* Optional: the WordPress REST API accepts the pool's access tokens (`Authorization: Bearer`) for linked users.
* Optional: hide the WordPress password form.

The plugin contacts **only the pool address you configure** (sign-in, token exchange, public keys). No data is sent
anywhere else.

== Installation ==

1. Upload the plugin (the zip `openback-app-auth-wordpress-1.0.0.zip`) in Plugins › Add New › Upload, and activate it.
2. Open Settings › OpenBack App Auth and copy the **Redirect URI** shown at the top
   (`https://your-site/wp-json/openback-app-auth/v1/callback`, or `https://your-site/?rest_route=/openback-app-auth/v1/callback`
   with plain permalinks).
3. In the OpenBack portal, open the user pool, tab **Apps**, add an app of kind **web**: paste the redirect URI, add
   your site's home address (or the address you choose) as **post-logout redirect URI**, save, and copy the client
   ID and the client secret.
4. Back in WordPress fill in the pool address (issuer), the client ID and the client secret, choose the account
   options, save, and press "Check the connection to the pool".

The client secret can be kept out of the database: `define( 'OPENBACK_APP_AUTH_CLIENT_SECRET', '...' );` in wp-config.php.

== Frequently Asked Questions ==

= Which redirect URI do I register? =

Exactly the one shown on the settings page. It depends on the permalink settings: change them and you must register
the new address.

= Can administrators use it? =

Yes, by linking their account from their profile ("Link my OpenBack account"). Administrators are never linked by
email automatically and their role is never changed by the role mapping.

= What if the REST API is disabled for visitors? =

The sign-in uses two REST routes (`/openback-app-auth/v1/login` and `/callback`) that must stay reachable by
signed-out visitors.

= Is the password form disabled when hidden? =

No: hiding is cosmetic (the form stays reachable at `wp-login.php?openback_password=1`) so that you can never lock
yourself out.

== Changelog ==

= 1.0.0 =
* First release.

== Upgrade Notice ==

= 1.0.0 =
First release.
