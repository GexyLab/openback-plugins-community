<?php
/**
 * Sign-ins in progress kept in transients (server-side).
 *
 * @package openback-app-auth-wordpress
 */

declare(strict_types=1);

namespace OpenBackAppAuthWp;

defined( 'ABSPATH' ) || exit;

final class TransientStateBackend implements StateBackend {

	public function get( string $key ): ?array {
		$value = get_transient( $key );
		return is_array( $value ) ? $value : null;
	}

	public function set( string $key, array $value, int $ttl_seconds ): void {
		set_transient( $key, $value, $ttl_seconds );
	}

	public function delete( string $key ): void {
		delete_transient( $key );
	}
}
