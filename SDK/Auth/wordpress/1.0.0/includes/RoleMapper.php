<?php
/**
 * OpenBack role -> WordPress role mapping (pure logic, no WordPress call: unit-tested).
 *
 * The mapping is a text, one rule per line: `openback_role = wordpress_role` (also `openback_role: wordpress_role`).
 * Blank lines and lines starting with # are ignored. The FIRST rule whose OpenBack role the user has wins; no rule
 * matching gives the default role.
 *
 * @package openback-app-auth-wordpress
 */

declare(strict_types=1);

namespace OpenBackAppAuthWp;

final class RoleMapper {

	/**
	 * Parses the mapping text.
	 *
	 * @return list<array{0: string, 1: string}> the rules in order: [openback role, WordPress role]
	 */
	public static function parse( string $text ): array {
		$rules = array();
		foreach ( preg_split( '/\R/', $text ) ?: array() as $line ) {
			$line = trim( $line );
			if ( '' === $line || str_starts_with( $line, '#' ) ) {
				continue;
			}
			if ( ! preg_match( '/^([^=:]+)[=:](.+)$/', $line, $m ) ) {
				continue;
			}
			$from = trim( $m[1] );
			$to   = strtolower( trim( $m[2] ) );
			if ( '' === $from || ! preg_match( '/^[a-z0-9_\-]+$/', $to ) ) {
				continue;
			}
			$rules[] = array( $from, $to );
		}
		return $rules;
	}

	/**
	 * Keeps the rules whose WordPress role exists; returns them as a normalized text and the refused lines.
	 *
	 * @param string[] $valid_roles the WordPress role slugs
	 * @return array{0: string, 1: list<string>}
	 */
	public static function normalize( string $text, array $valid_roles ): array {
		$kept    = array();
		$refused = array();
		foreach ( self::parse( $text ) as [ $from, $to ] ) {
			if ( in_array( $to, $valid_roles, true ) ) {
				$kept[] = $from . ' = ' . $to;
			} else {
				$refused[] = $from . ' = ' . $to;
			}
		}
		return array( implode( "\n", $kept ), $refused );
	}

	/**
	 * The WordPress role for a user with these OpenBack roles.
	 *
	 * @param list<array{0: string, 1: string}> $rules
	 * @param string[]                         $openback_roles the `roles` claim
	 * @param string[]|null                    $valid_roles    when given, rules to a missing role are skipped
	 */
	public static function resolve( array $rules, array $openback_roles, string $default_role, ?array $valid_roles = null ): string {
		foreach ( $rules as [ $from, $to ] ) {
			if ( in_array( $from, $openback_roles, true ) && ( null === $valid_roles || in_array( $to, $valid_roles, true ) ) ) {
				return $to;
			}
		}
		return $default_role;
	}
}
