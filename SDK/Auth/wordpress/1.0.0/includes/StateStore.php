<?php
/**
 * The sign-ins in progress (state, nonce, PKCE verifier, where to go next), kept SERVER-SIDE (pure logic: tested).
 *
 * The browser only holds a random identifier in an HttpOnly cookie; the data lives in the backend (transients) under a
 * hash of that identifier, for 10 minutes, at most 5 per browser (several tabs). A transaction is found by its `state`
 * (compared in constant time) and can be taken only once.
 *
 * @package openback-app-auth-wordpress
 */

declare(strict_types=1);

namespace OpenBackAppAuthWp;

final class StateStore {

	public const COOKIE = 'openback_app_auth_tx';
	public const TTL    = 600;
	public const MAX    = 5;

	/** @var callable(): ?string */
	private $read_cookie;
	/** @var callable(string, int): void */
	private $write_cookie;
	/** @var callable(): int */
	private $clock;

	/**
	 * @param callable(): ?string         $read_cookie  the cookie's value in this request, or null
	 * @param callable(string, int): void $write_cookie sets the cookie (value, lifetime in seconds)
	 * @param callable(): int|null        $clock
	 */
	public function __construct( private readonly StateBackend $backend, callable $read_cookie, callable $write_cookie, ?callable $clock = null ) {
		$this->read_cookie  = $read_cookie;
		$this->write_cookie = $write_cookie;
		$this->clock        = $clock ?? static fn (): int => time();
	}

	/**
	 * Remembers a transaction for this browser.
	 *
	 * @param array<string, mixed> $transaction must hold a non-empty string `state`
	 */
	public function put( array $transaction ): void {
		if ( ! is_string( $transaction['state'] ?? null ) || '' === $transaction['state'] ) {
			throw new \InvalidArgumentException( 'transaction without state' );
		}
		$browser = $this->browser_id();
		if ( null === $browser ) {
			$browser = rtrim( strtr( base64_encode( random_bytes( 32 ) ), '+/', '-_' ), '=' );
		}
		$now     = ( $this->clock )();
		$entries = array_values(
			array_filter(
				$this->backend->get( self::key( $browser ) ) ?? array(),
				static fn ( $e ) => is_array( $e ) && ( $e['expires'] ?? 0 ) > $now
			)
		);
		$entries[] = array(
			'expires' => $now + self::TTL,
			'tx'      => $transaction,
		);
		$entries   = array_slice( $entries, -self::MAX );
		$this->backend->set( self::key( $browser ), $entries, self::TTL );
		( $this->write_cookie )( $browser, self::TTL );
	}

	/**
	 * Takes (and forgets) the transaction of this browser with this state.
	 *
	 * @return array<string, mixed>|null
	 */
	public function take( ?string $state ): ?array {
		$browser = $this->browser_id();
		if ( null === $browser || null === $state || '' === $state ) {
			return null;
		}
		$key     = self::key( $browser );
		$now     = ( $this->clock )();
		$found   = null;
		$entries = array();
		foreach ( $this->backend->get( $key ) ?? array() as $entry ) {
			if ( ! is_array( $entry ) || ( $entry['expires'] ?? 0 ) <= $now || ! is_array( $entry['tx'] ?? null ) ) {
				continue;
			}
			$entry_state = $entry['tx']['state'] ?? null;
			if ( null === $found && is_string( $entry_state ) && hash_equals( $entry_state, $state ) ) {
				$found = $entry['tx'];
				continue;
			}
			$entries[] = $entry;
		}
		if ( array() === $entries ) {
			$this->backend->delete( $key );
		} else {
			$this->backend->set( $key, $entries, self::TTL );
		}
		return $found;
	}

	private function browser_id(): ?string {
		$value = ( $this->read_cookie )();
		return is_string( $value ) && preg_match( '/^[A-Za-z0-9_-]{43}$/', $value ) ? $value : null;
	}

	/** The backend key: a hash of the browser's identifier (the identifier itself is never stored). */
	public static function key( string $browser_id ): string {
		return 'openback_app_auth_tx_' . hash( 'sha256', $browser_id );
	}
}
