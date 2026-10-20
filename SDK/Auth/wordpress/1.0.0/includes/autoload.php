<?php
/**
 * The plugin's own autoloader (no Composer at runtime):
 *   OpenBackAppAuthWp\Sdk\...  -> lib/openback-app-auth-php/src/  (the bundled SDK, namespace prefixed)
 *   OpenBackAppAuthWp\...      -> includes/
 * The prefixed namespace cannot clash with another plugin loading openback-app-auth-php (OpenBack\AppAuth).
 *
 * @package openback-app-auth-wordpress
 */

defined( 'ABSPATH' ) || exit;

spl_autoload_register(
	static function ( string $class_name ): void {
		$map = array(
			'OpenBackAppAuthWp\\Sdk\\' => dirname( __DIR__ ) . '/lib/openback-app-auth-php/src/',
			'OpenBackAppAuthWp\\'      => __DIR__ . '/',
		);
		foreach ( $map as $prefix => $dir ) {
			if ( strncmp( $class_name, $prefix, strlen( $prefix ) ) !== 0 ) {
				continue;
			}
			$relative = substr( $class_name, strlen( $prefix ) );
			if ( ! preg_match( '/^[A-Za-z0-9_\\\\]+$/', $relative ) ) {
				return;
			}
			$file = $dir . str_replace( '\\', '/', $relative ) . '.php';
			if ( is_file( $file ) ) {
				require_once $file;
			}
			return;
		}
	}
);
