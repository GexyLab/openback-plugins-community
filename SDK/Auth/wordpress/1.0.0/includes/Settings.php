<?php
/**
 * The plugin's settings: one option (array) `openback_app_auth_settings`, sanitized on save.
 *
 * The client secret can also come from the constant OPENBACK_APP_AUTH_CLIENT_SECRET (wp-config.php), which then wins
 * over the stored value and keeps the secret out of the database.
 *
 * @package openback-app-auth-wordpress
 */

declare(strict_types=1);

namespace OpenBackAppAuthWp;

defined( 'ABSPATH' ) || exit;

final class Settings {

	public const OPTION = 'openback_app_auth_settings';

	/** @var array<string, mixed>|null */
	private ?array $values = null;

	/** @return array<string, mixed> */
	public static function defaults(): array {
		return array(
			'issuer'                 => '',
			'client_id'              => '',
			'client_secret'          => '',
			'scopes'                 => 'openid profile email',
			'provider'               => '',
			'button_label'           => '',
			'auto_create'            => true,
			'require_verified_email' => true,
			'link_by_email'          => false,
			'role_map'               => '',
			'default_role'           => '',
			'sync_roles'             => false,
			'hide_password_login'    => false,
			'single_logout'          => true,
			'post_logout_redirect'   => '',
			'rest_bearer'            => false,
			'rest_client_ids'        => '',
		);
	}

	/** @return array<string, mixed> */
	public function all(): array {
		if ( null === $this->values ) {
			$stored       = get_option( self::OPTION, array() );
			$this->values = array_merge( self::defaults(), is_array( $stored ) ? $stored : array() );
		}
		return $this->values;
	}

	public function get( string $name ): mixed {
		return $this->all()[ $name ] ?? null;
	}

	public function flush(): void {
		$this->values = null;
	}

	public function issuer(): string {
		return rtrim( (string) $this->get( 'issuer' ), '/' );
	}

	public function client_id(): string {
		return (string) $this->get( 'client_id' );
	}

	public function client_secret(): string {
		if ( defined( 'OPENBACK_APP_AUTH_CLIENT_SECRET' ) && is_string( OPENBACK_APP_AUTH_CLIENT_SECRET ) && '' !== OPENBACK_APP_AUTH_CLIENT_SECRET ) {
			return OPENBACK_APP_AUTH_CLIENT_SECRET;
		}
		return (string) $this->get( 'client_secret' );
	}

	public function secret_from_constant(): bool {
		return defined( 'OPENBACK_APP_AUTH_CLIENT_SECRET' ) && is_string( OPENBACK_APP_AUTH_CLIENT_SECRET ) && '' !== OPENBACK_APP_AUTH_CLIENT_SECRET;
	}

	/** Issuer, client ID and secret are set: sign-in can work. */
	public function configured(): bool {
		return '' !== $this->issuer() && '' !== $this->client_id() && '' !== $this->client_secret();
	}

	public function flag( string $name ): bool {
		return (bool) $this->get( $name );
	}

	public function button_label(): string {
		$label = trim( (string) $this->get( 'button_label' ) );
		return '' !== $label ? $label : __( 'Sign in with OpenBack', 'openback-app-auth-wordpress' );
	}

	public function default_role(): string {
		$role = (string) $this->get( 'default_role' );
		return '' !== $role ? $role : (string) get_option( 'default_role', 'subscriber' );
	}

	public function post_logout_redirect(): string {
		$url = (string) $this->get( 'post_logout_redirect' );
		return '' !== $url ? $url : home_url( '/' );
	}

	/** The redirect URI to register on the `web` app (the OIDC callback route). */
	public static function redirect_uri(): string {
		return rest_url( 'openback-app-auth/v1/callback' );
	}

	/** @return string[] the client IDs accepted on the REST API (this app + the extra ones) */
	public function rest_client_ids(): array {
		$extra = preg_split( '/[\s,]+/', (string) $this->get( 'rest_client_ids' ) ) ?: array();
		return array_values( array_unique( array_filter( array_merge( array( $this->client_id() ), $extra ) ) ) );
	}

	/**
	 * Sanitizes the submitted settings (register_setting's sanitize_callback).
	 *
	 * @param mixed $input
	 * @return array<string, mixed>
	 */
	public function sanitize( $input ): array {
		$input    = is_array( $input ) ? $input : array();   // options.php already unslashed it
		$previous = $this->all();
		$out      = self::defaults();

		$issuer = esc_url_raw( trim( (string) ( $input['issuer'] ?? '' ) ), array( 'https', 'http' ) );
		$issuer = rtrim( $issuer, '/' );
		if ( '' !== $issuer && ! self::valid_issuer( $issuer ) ) {
			add_settings_error( self::OPTION, 'issuer', __( 'The pool address must be an https:// address (http:// only for localhost).', 'openback-app-auth-wordpress' ) );
			$issuer = (string) $previous['issuer'];
		}
		$out['issuer'] = $issuer;

		$client_id        = sanitize_text_field( (string) ( $input['client_id'] ?? '' ) );
		$out['client_id'] = preg_match( '/^[A-Za-z0-9_\-]{0,64}$/', $client_id ) ? $client_id : (string) $previous['client_id'];

		// The secret is never shown back: an empty field keeps the stored one; the checkbox clears it.
		$secret               = trim( (string) ( $input['client_secret'] ?? '' ) );
		$out['client_secret'] = ! empty( $input['clear_client_secret'] ) ? '' : ( '' !== $secret ? $secret : (string) $previous['client_secret'] );

		$scopes = preg_split( '/\s+/', sanitize_text_field( (string) ( $input['scopes'] ?? '' ) ) ) ?: array();
		$scopes = array_values( array_unique( array_filter( $scopes, static fn ( $s ) => (bool) preg_match( '/^[A-Za-z0-9_.:\-]+$/', $s ) ) ) );
		if ( ! in_array( 'openid', $scopes, true ) ) {
			array_unshift( $scopes, 'openid' );
		}
		$out['scopes'] = implode( ' ', $scopes );

		$provider        = sanitize_text_field( (string) ( $input['provider'] ?? '' ) );
		$out['provider'] = preg_match( '/^[A-Za-z0-9_\-]{0,64}$/', $provider ) ? $provider : '';

		$out['button_label'] = sanitize_text_field( (string) ( $input['button_label'] ?? '' ) );

		foreach ( array( 'auto_create', 'require_verified_email', 'link_by_email', 'sync_roles', 'hide_password_login', 'single_logout', 'rest_bearer' ) as $flag ) {
			$out[ $flag ] = ! empty( $input[ $flag ] );
		}

		$roles = array_keys( wp_roles()->roles );
		[ $map, $refused ] = RoleMapper::normalize( sanitize_textarea_field( (string) ( $input['role_map'] ?? '' ) ), $roles );
		if ( array() !== $refused ) {
			add_settings_error(
				self::OPTION,
				'role_map',
				/* translators: %s: the refused mapping lines */
				sprintf( __( 'Mapping lines to unknown WordPress roles were removed: %s', 'openback-app-auth-wordpress' ), implode( ', ', $refused ) )
			);
		}
		$out['role_map'] = $map;

		$default_role        = sanitize_key( (string) ( $input['default_role'] ?? '' ) );
		$out['default_role'] = in_array( $default_role, $roles, true ) ? $default_role : '';

		$post_logout = esc_url_raw( trim( (string) ( $input['post_logout_redirect'] ?? '' ) ), array( 'https', 'http' ) );
		$out['post_logout_redirect'] = $post_logout;

		$ids = preg_split( '/[\s,]+/', sanitize_text_field( (string) ( $input['rest_client_ids'] ?? '' ) ) ) ?: array();
		$out['rest_client_ids'] = implode( ', ', array_filter( $ids, static fn ( $id ) => (bool) preg_match( '/^[A-Za-z0-9_\-]{1,64}$/', $id ) ) );

		$this->values = null;
		return $out;
	}

	public static function valid_issuer( string $issuer ): bool {
		return (bool) preg_match( '#^https://[^/\s]+(/\S*)?$#i', $issuer )
			|| (bool) preg_match( '#^http://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?(/\S*)?$#i', $issuer );
	}
}
