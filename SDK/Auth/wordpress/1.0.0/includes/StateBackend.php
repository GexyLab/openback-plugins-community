<?php
/**
 * Server-side storage of the sign-ins in progress (transients in WordPress, an array in the tests).
 *
 * @package openback-app-auth-wordpress
 */

declare(strict_types=1);

namespace OpenBackAppAuthWp;

interface StateBackend {

	/** @return array<mixed>|null */
	public function get( string $key ): ?array;

	/** @param array<mixed> $value */
	public function set( string $key, array $value, int $ttl_seconds ): void;

	public function delete( string $key ): void;
}
