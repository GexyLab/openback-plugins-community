<?php
/**
 * The pool's public keys (JWKS) cached in a transient (or the object cache when the site has one).
 *
 * @package openback-app-auth-wordpress
 */

declare(strict_types=1);

namespace OpenBackAppAuthWp;

use OpenBackAppAuthWp\Sdk\Cache\JwksCache;

defined( 'ABSPATH' ) || exit;

final class TransientJwksCache implements JwksCache {

	public function get( string $key ): ?array {
		$value = get_transient( $key );
		return is_array( $value ) ? $value : null;
	}

	public function set( string $key, array $value, int $ttl_seconds ): void {
		set_transient( $key, $value, max( 1, $ttl_seconds ) );
	}
}
