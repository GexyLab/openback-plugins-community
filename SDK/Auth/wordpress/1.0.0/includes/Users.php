<?php
/**
 * Links OpenBack users to WordPress users (user meta) and creates WordPress users.
 *
 * A WordPress user is linked by the meta `openback_app_auth_sub` (the pool user's id, `usr_...`) with the pool's
 * issuer (`openback_app_auth_iss`) and pool id (`openback_app_auth_pool`): a link matches when the sub is equal and
 * either the issuer or the pool id is (the pool keeps its id if its address changes).
 *
 * @package openback-app-auth-wordpress
 */

declare(strict_types=1);

namespace OpenBackAppAuthWp;

defined( 'ABSPATH' ) || exit;

final class Users {

	public const META_SUB     = 'openback_app_auth_sub';
	public const META_ISS     = 'openback_app_auth_iss';
	public const META_POOL    = 'openback_app_auth_pool';
	public const META_CREATED = 'openback_app_auth_created';

	public function __construct( private readonly Settings $settings ) {
	}

	/** The WordPress user linked to this pool user, if any. */
	public function find_linked( string $sub, ?string $pool = null ): ?\WP_User {
		$ids = get_users(
			array(
				'meta_key'    => self::META_SUB, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key
				'meta_value'  => $sub, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_value
				'fields'      => 'ID',
				'number'      => 5,
				'blog_id'     => 0,
				'count_total' => false,
			)
		);
		foreach ( $ids as $id ) {
			$iss       = (string) get_user_meta( (int) $id, self::META_ISS, true );
			$user_pool = (string) get_user_meta( (int) $id, self::META_POOL, true );
			if ( $iss === $this->settings->issuer() || ( null !== $pool && '' !== $pool && $user_pool === $pool ) ) {
				$user = get_user_by( 'id', (int) $id );
				return $user instanceof \WP_User ? $user : null;
			}
		}
		return null;
	}

	/** @param array<string, mixed> $claims verified ID token claims */
	public function link( int $user_id, array $claims ): void {
		update_user_meta( $user_id, self::META_SUB, (string) $claims['sub'] );
		update_user_meta( $user_id, self::META_ISS, $this->settings->issuer() );
		update_user_meta( $user_id, self::META_POOL, is_string( $claims['pool'] ?? null ) ? $claims['pool'] : '' );
	}

	public function unlink( int $user_id ): void {
		delete_user_meta( $user_id, self::META_SUB );
		delete_user_meta( $user_id, self::META_ISS );
		delete_user_meta( $user_id, self::META_POOL );
	}

	public function linked_sub( int $user_id ): ?string {
		$sub = (string) get_user_meta( $user_id, self::META_SUB, true );
		return '' !== $sub ? $sub : null;
	}

	/** Administrators are never linked by email automatically, nor have their role changed. */
	public static function is_protected( \WP_User $user ): bool {
		return user_can( $user, 'manage_options' ) || ( is_multisite() && is_super_admin( $user->ID ) );
	}

	/**
	 * The WordPress user for a verified ID token: linked, linked now by email, or created — per the settings.
	 *
	 * @param array<string, mixed> $claims
	 */
	public function resolve( array $claims ): \WP_User|\WP_Error {
		$sub      = (string) $claims['sub'];
		$pool     = is_string( $claims['pool'] ?? null ) ? $claims['pool'] : null;
		$email    = is_string( $claims['email'] ?? null ) ? sanitize_email( $claims['email'] ) : '';
		$verified = true === ( $claims['email_verified'] ?? false );
		$roles    = is_array( $claims['roles'] ?? null ) ? array_values( array_filter( $claims['roles'], 'is_string' ) ) : array();

		$user = $this->find_linked( $sub, $pool );
		if ( $user ) {
			if ( $this->settings->flag( 'sync_roles' ) ) {
				$this->apply_role( $user, $roles );
			}
			return $this->ensure_member( $user, $roles );
		}

		$existing = '' !== $email ? get_user_by( 'email', $email ) : false;
		if ( $existing instanceof \WP_User ) {
			if ( ! $this->settings->flag( 'link_by_email' ) ) {
				return new \WP_Error( 'email_exists' );
			}
			if ( ! $verified ) {
				return new \WP_Error( 'email_not_verified' );
			}
			if ( self::is_protected( $existing ) ) {
				return new \WP_Error( 'admin_link_refused' );
			}
			if ( null !== $this->linked_sub( $existing->ID ) ) {
				return new \WP_Error( 'already_linked' );
			}
			$this->link( $existing->ID, $claims );
			if ( $this->settings->flag( 'sync_roles' ) ) {
				$this->apply_role( $existing, $roles );
			}
			return $this->ensure_member( $existing, $roles );
		}

		if ( ! $this->settings->flag( 'auto_create' ) ) {
			return new \WP_Error( 'no_account' );
		}
		if ( '' !== $email && ! $verified && $this->settings->flag( 'require_verified_email' ) ) {
			return new \WP_Error( 'email_not_verified' );
		}
		return $this->create( $claims, $email, $roles );
	}

	/**
	 * @param array<string, mixed> $claims
	 * @param string[]             $roles
	 */
	private function create( array $claims, string $email, array $roles ): \WP_User|\WP_Error {
		$name    = is_string( $claims['name'] ?? null ) ? sanitize_text_field( $claims['name'] ) : '';
		$login   = $this->unique_login( '' !== $email ? strstr( $email, '@', true ) : $name, (string) $claims['sub'] );
		$display = '' !== $name ? $name : ( '' !== $email ? (string) strstr( $email, '@', true ) : $login );
		$user_id = wp_insert_user(
			array(
				'user_login'   => $login,
				'user_pass'    => wp_generate_password( 40, true, true ),
				'user_email'   => $email,
				'display_name' => $display,
				'nickname'     => $display,
				'role'         => $this->role_for( $roles ),
			)
		);
		if ( is_wp_error( $user_id ) ) {
			return new \WP_Error( 'registration_failed' );
		}
		$this->link( (int) $user_id, $claims );
		update_user_meta( (int) $user_id, self::META_CREATED, 1 );
		$user = get_user_by( 'id', (int) $user_id );
		if ( ! $user instanceof \WP_User ) {
			return new \WP_Error( 'registration_failed' );
		}
		/**
		 * A WordPress user was created for an OpenBack user.
		 *
		 * @param \WP_User             $user
		 * @param array<string, mixed> $claims the verified ID token claims
		 */
		do_action( 'openback_app_auth_user_created', $user, $claims );
		return $user;
	}

	/** @param string[] $roles */
	public function role_for( array $roles ): string {
		$role = RoleMapper::resolve( RoleMapper::parse( (string) $this->settings->get( 'role_map' ) ), $roles, $this->settings->default_role(), array_keys( wp_roles()->roles ) );
		/**
		 * The WordPress role given to an OpenBack user.
		 *
		 * @param string   $role
		 * @param string[] $roles the OpenBack roles
		 */
		return (string) apply_filters( 'openback_app_auth_role', $role, $roles );
	}

	/** @param string[] $roles */
	public function apply_role( \WP_User $user, array $roles ): void {
		if ( self::is_protected( $user ) ) {
			return;
		}
		$role = $this->role_for( $roles );
		if ( '' !== $role && ! in_array( $role, (array) $user->roles, true ) ) {
			$user->set_role( $role );
		}
	}

	/**
	 * Multisite: the user must belong to this site; added when accounts may be created.
	 *
	 * @param string[] $roles
	 */
	private function ensure_member( \WP_User $user, array $roles ): \WP_User|\WP_Error {
		if ( ! is_multisite() || is_user_member_of_blog( $user->ID, get_current_blog_id() ) ) {
			return $user;
		}
		if ( ! $this->settings->flag( 'auto_create' ) ) {
			return new \WP_Error( 'no_account' );
		}
		add_user_to_blog( get_current_blog_id(), $user->ID, $this->role_for( $roles ) );
		return $user;
	}

	private function unique_login( string $wanted, string $sub ): string {
		$base = sanitize_user( strtolower( remove_accents( $wanted ) ), true );
		$base = substr( preg_replace( '/[^a-z0-9_.\-]/', '', $base ) ?? '', 0, 50 );
		if ( strlen( $base ) < 3 ) {
			$base = 'openback_' . substr( hash( 'sha256', $sub ), 0, 10 );
		}
		$login = $base;
		for ( $i = 2; username_exists( $login ) || ! validate_username( $login ); $i++ ) {
			$login = $base . $i;
			if ( $i > 50 ) {
				$login = 'openback_' . substr( hash( 'sha256', $sub . wp_rand() ), 0, 12 );
			}
		}
		return $login;
	}
}
