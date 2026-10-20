<?php
/**
 * Optional (off by default): the WordPress REST API accepts `Authorization: Bearer <pool access token>` and runs the
 * request as the WordPress user LINKED to that pool user. The token is verified locally (pool keys, ES256, issuer,
 * audience among the accepted client IDs, expiry); guest tokens are refused. Requests without a bearer JWT are left
 * to WordPress (cookies + nonce, application passwords).
 *
 * @package openback-app-auth-wordpress
 */

declare(strict_types=1);

namespace OpenBackAppAuthWp;

use OpenBackAppAuthWp\Sdk\AppAuthException;

defined( 'ABSPATH' ) || exit;

final class RestBearerAuth {

	private ?\WP_Error $error = null;
	private bool $done        = false;
	private ?int $user_id     = null;

	public function __construct( private readonly Plugin $plugin ) {
	}

	public function register(): void {
		add_filter( 'determine_current_user', array( $this, 'determine_current_user' ), 20 );
		add_filter( 'rest_authentication_errors', array( $this, 'authentication_errors' ), 20 );
	}

	/**
	 * @param int|false $user_id
	 * @return int|false
	 */
	public function determine_current_user( $user_id ) {
		if ( $user_id || ! $this->plugin->settings()->flag( 'rest_bearer' ) || ! $this->plugin->settings()->configured() ) {
			return $user_id;
		}
		if ( $this->done ) {
			return $this->user_id ?? $user_id;
		}
		$token = self::bearer_jwt();
		if ( null === $token || ! self::is_rest_request() ) {
			return $user_id;
		}
		$this->done = true;
		try {
			$app_user = $this->plugin->rest_verifier()->verify( $token );
		} catch ( AppAuthException $e ) {
			$this->error = 503 === $e->status
				? new \WP_Error( 'openback_app_auth_unavailable', __( 'The token cannot be checked right now.', 'openback-app-auth-wordpress' ), array( 'status' => 503 ) )
				: new \WP_Error( 'openback_app_auth_invalid_token', __( 'Invalid or expired access token.', 'openback-app-auth-wordpress' ), array( 'status' => 401 ) );
			return $user_id;
		}
		if ( $app_user->anonymous ) {
			$this->error = new \WP_Error( 'openback_app_auth_invalid_token', __( 'Guest accounts cannot use the REST API.', 'openback-app-auth-wordpress' ), array( 'status' => 401 ) );
			return $user_id;
		}
		$user = $this->plugin->users()->find_linked( $app_user->id, $app_user->poolId );
		if ( ! $user || ( is_multisite() && ! is_user_member_of_blog( $user->ID, get_current_blog_id() ) ) ) {
			$this->error = new \WP_Error( 'openback_app_auth_no_user', __( 'No WordPress account is linked to this user.', 'openback-app-auth-wordpress' ), array( 'status' => 401 ) );
			return $user_id;
		}
		/**
		 * Whether a verified app user may act as $user on the REST API. Return false to refuse.
		 *
		 * @param bool                       $allowed
		 * @param \WP_User                   $user
		 * @param \OpenBackAppAuthWp\Sdk\AppUser $app_user
		 */
		if ( true !== apply_filters( 'openback_app_auth_rest_allow', true, $user, $app_user ) ) {
			$this->error = new \WP_Error( 'openback_app_auth_forbidden', __( 'Not allowed.', 'openback-app-auth-wordpress' ), array( 'status' => 403 ) );
			return $user_id;
		}
		$this->user_id = $user->ID;
		return $user->ID;
	}

	/**
	 * @param \WP_Error|null|true $result
	 * @return \WP_Error|null|true
	 */
	public function authentication_errors( $result ) {
		if ( ! empty( $result ) ) {
			return $result;
		}
		return $this->error ?? $result;
	}

	/** A bearer token shaped like a JWT, from the Authorization header (also when the server renames it). */
	private static function bearer_jwt(): ?string {
		$header = '';
		foreach ( array( 'HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION' ) as $name ) {
			if ( ! empty( $_SERVER[ $name ] ) && is_string( $_SERVER[ $name ] ) ) {
				$header = trim( wp_unslash( $_SERVER[ $name ] ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- matched below
				break;
			}
		}
		if ( ! preg_match( '/^Bearer\s+([A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)$/i', $header, $m ) ) {
			return null;
		}
		return $m[1];
	}

	/** determine_current_user runs before REST_REQUEST is defined: look at the address. */
	private static function is_rest_request(): bool {
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return true;
		}
		if ( isset( $_GET['rest_route'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return true;
		}
		$uri    = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_parse_url( wp_unslash( $_SERVER['REQUEST_URI'] ), PHP_URL_PATH ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$prefix = '/' . trim( rest_get_url_prefix(), '/' ) . '/';
		return str_contains( $uri, $prefix );
	}
}
