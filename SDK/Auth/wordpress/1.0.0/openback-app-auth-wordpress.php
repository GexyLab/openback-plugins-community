<?php
/**
 * Plugin Name:       OpenBack App Auth
 * Plugin URI:        https://github.com/GexyLab/openback-plugins-community/tree/main/SDK/Auth/wordpress/1.0.0
 * Description:       Sign in to WordPress with an OpenBack user pool (App authenticator): "Sign in with ..." button, OpenID Connect with PKCE, account linking, role mapping, single logout and optional REST API bearer tokens.
 * Version:           1.0.0
 * Requires at least: 6.0
 * Requires PHP:      8.1
 * Author:            GexyLab
 * Author URI:        https://github.com/GexyLab
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       openback-app-auth-wordpress
 * Domain Path:       /languages
 *
 * @package openback-app-auth-wordpress
 */

defined( 'ABSPATH' ) || exit;

// Two copies of this plugin (e.g. a renamed folder): only the first one runs.
if ( defined( 'OPENBACK_APP_AUTH_WP_VERSION' ) ) {
	return;
}

define( 'OPENBACK_APP_AUTH_WP_VERSION', '1.0.0' );
define( 'OPENBACK_APP_AUTH_WP_FILE', __FILE__ );
define( 'OPENBACK_APP_AUTH_WP_DIR', __DIR__ );

if ( version_compare( PHP_VERSION, '8.1', '<' ) ) {
	add_action(
		'admin_notices',
		static function () {
			echo '<div class="notice notice-error"><p>' . esc_html__( 'OpenBack App Auth needs PHP 8.1 or later.', 'openback-app-auth-wordpress' ) . '</p></div>';
		}
	);
	return;
}

require_once __DIR__ . '/includes/autoload.php';

\OpenBackAppAuthWp\Plugin::instance()->boot();
