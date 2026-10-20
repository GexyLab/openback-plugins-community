<?php
/**
 * Removes the plugin's data when it is deleted from WordPress: settings, transients (sign-ins in progress, JWKS cache)
 * and the account links (user meta). WordPress accounts created by the plugin stay.
 *
 * @package openback-app-auth-wordpress
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

/** Cleans one site. */
function openback_app_auth_uninstall_site(): void {
	global $wpdb;
	delete_option( 'openback_app_auth_settings' );
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- uninstall cleanup
	$wpdb->query(
		$wpdb->prepare(
			"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
			$wpdb->esc_like( '_transient_openback_app_auth_' ) . '%',
			$wpdb->esc_like( '_transient_timeout_openback_app_auth_' ) . '%'
		)
	);
}

if ( is_multisite() ) {
	foreach ( get_sites( array( 'fields' => 'ids', 'number' => 0 ) ) as $openback_app_auth_site ) {
		switch_to_blog( (int) $openback_app_auth_site );
		openback_app_auth_uninstall_site();
		restore_current_blog();
	}
} else {
	openback_app_auth_uninstall_site();
}

foreach ( array( 'openback_app_auth_sub', 'openback_app_auth_iss', 'openback_app_auth_pool', 'openback_app_auth_created' ) as $openback_app_auth_meta ) {
	delete_metadata( 'user', 0, $openback_app_auth_meta, '', true );
}
