<?php
/**
 * The sign-in flow: start (REST GET /openback-app-auth/v1/login), OIDC callback (REST GET /openback-app-auth/v1/callback),
 * account linking from the profile (admin-post), single logout, error messages on wp-login.php.
 *
 * @package openback-app-auth-wordpress
 */

declare(strict_types=1);

namespace OpenBackAppAuthWp;

use OpenBackAppAuthWp\Sdk\AppAuthException;

defined( 'ABSPATH' ) || exit;

final class Login {

	public const ROUTE_NAMESPACE = 'openback-app-auth/v1';
	public const SESSION_KEY     = 'openback_app_auth_id_token';

	/** The error codes shown on the login page (anything else is "sign_in_failed"). */
	private const ERRORS = array(
		'invalid_state', 'cancelled', 'sign_in_failed', 'not_configured', 'email_exists', 'email_not_verified', 'no_account',
		'admin_link_refused', 'already_linked', 'registration_failed', 'not_allowed', 'unavailable',
	);

	private ?string $logout_id_token = null;

	public function __construct( private readonly Plugin $plugin ) {
	}

	public function register(): void {
		add_action( 'rest_api_init', array( $this, 'routes' ) );
		add_action( 'admin_post_openback_app_auth_link', array( $this, 'start_link' ) );
		add_action( 'admin_post_openback_app_auth_unlink', array( $this, 'unlink' ) );
		add_action( 'login_form_logout', array( $this, 'capture_logout' ) );
		add_filter( 'logout_redirect', array( $this, 'logout_redirect' ), 20, 3 );
		add_filter( 'allowed_redirect_hosts', array( $this, 'allowed_hosts' ) );
		add_filter( 'wp_login_errors', array( $this, 'login_errors' ) );
	}

	/** The address that starts a sign-in (the button's link). */
	public static function start_url( string $redirect_to = '' ): string {
		$url = rest_url( self::ROUTE_NAMESPACE . '/login' );
		return '' !== $redirect_to ? add_query_arg( 'redirect_to', rawurlencode( $redirect_to ), $url ) : $url;
	}

	public function routes(): void {
		register_rest_route(
			self::ROUTE_NAMESPACE,
			'/login',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'start' ),
				'permission_callback' => '__return_true',
				'args'                => array(
					'redirect_to' => array(
						'type'              => 'string',
						'sanitize_callback' => 'esc_url_raw',
					),
				),
			)
		);
		register_rest_route(
			self::ROUTE_NAMESPACE,
			'/callback',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'callback' ),
				'permission_callback' => '__return_true',
			)
		);
	}

	/** REST GET /login: to the pool's hosted page. */
	public function start( \WP_REST_Request $request ): void {
		$redirect_to = (string) $request->get_param( 'redirect_to' );
		$this->begin( (string) wp_validate_redirect( $redirect_to, '' ), 0 );
	}

	/** admin-post: link the signed-in user's account (from the profile page). */
	public function start_link(): void {
		check_admin_referer( 'openback_app_auth_link' );
		if ( ! is_user_logged_in() ) {
			wp_die( esc_html__( 'Sign in first.', 'openback-app-auth-wordpress' ), '', array( 'response' => 403 ) );
		}
		$this->begin( admin_url( 'profile.php' ), get_current_user_id() );
	}

	/** admin-post: remove a link (own profile, or a user the current user may edit). */
	public function unlink(): void {
		$user_id = isset( $_GET['user_id'] ) ? absint( $_GET['user_id'] ) : 0; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- checked below
		check_admin_referer( 'openback_app_auth_unlink_' . $user_id );
		if ( ! $user_id || ! current_user_can( 'edit_user', $user_id ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'openback-app-auth-wordpress' ), '', array( 'response' => 403 ) );
		}
		$this->plugin->users()->unlink( $user_id );
		$target = get_current_user_id() === $user_id ? admin_url( 'profile.php' ) : add_query_arg( 'user_id', $user_id, admin_url( 'user-edit.php' ) );
		wp_safe_redirect( add_query_arg( 'openback_app_auth', 'unlinked', $target ) );
		exit;
	}

	private function begin( string $redirect_to, int $link_user ): void {
		$settings = $this->plugin->settings();
		if ( ! $settings->configured() ) {
			$this->fail( 'not_configured', $link_user );
		}
		$options = array(
			'scope'     => (string) $settings->get( 'scopes' ),
			'uiLocales' => str_starts_with( determine_locale(), 'it' ) ? 'it' : 'en',
		);
		if ( '' !== (string) $settings->get( 'provider' ) ) {
			$options['provider'] = (string) $settings->get( 'provider' );
		}
		$auth = $this->plugin->oidc()->authorizationUrl( $options );
		$this->plugin->states()->put(
			$auth->transaction->toArray() + array(
				'redirect_to' => $redirect_to,
				'link_user'   => $link_user,
			)
		);
		nocache_headers();
		wp_redirect( $auth->url ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- the pool's own address
		exit;
	}

	/** REST GET /callback: back from the hosted page. */
	public function callback( \WP_REST_Request $request ): void {
		nocache_headers();
		$params = array_map( static fn ( $v ) => is_string( $v ) ? $v : '', $request->get_query_params() );
		$tx     = $this->plugin->states()->take( $params['state'] ?? null );
		if ( null === $tx ) {
			$this->fail( 'invalid_state', 0 );
		}
		$link_user = (int) ( $tx['link_user'] ?? 0 );
		try {
			$tokens = $this->plugin->oidc()->handleCallback( $params, $tx );
		} catch ( AppAuthException $e ) {
			$code = in_array( $e->errorCode, array( 'access_denied', 'login_required', 'consent_required', 'interaction_required' ), true ) ? 'cancelled'
				: ( in_array( $e->errorCode, array( 'network_error', 'jwks_unavailable' ), true ) ? 'unavailable' : 'sign_in_failed' );
			$this->fail( $code, $link_user );
		}
		// WordPress keeps its own session: the refresh token is not needed, revoke it (best effort).
		if ( null !== $tokens->refreshToken ) {
			try {
				$this->plugin->oidc()->revoke( $tokens->refreshToken );
			} catch ( AppAuthException ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch
				// not fatal
			}
		}
		$claims = (array) $tokens->idTokenClaims;

		if ( $link_user > 0 ) {
			$this->finish_link( $link_user, $claims );
		}

		$user = $this->plugin->users()->resolve( $claims );
		if ( is_wp_error( $user ) ) {
			$this->fail( $user->get_error_code(), 0 );
		}
		/**
		 * Whether this OpenBack user may sign in to WordPress as $user. Return false or a WP_Error to refuse.
		 *
		 * @param bool|\WP_Error       $allowed
		 * @param \WP_User             $user
		 * @param array<string, mixed> $claims the verified ID token claims
		 */
		$allowed = apply_filters( 'openback_app_auth_allow_login', true, $user, $claims );
		if ( true !== $allowed ) {
			$this->fail( 'not_allowed', 0 );
		}

		$id_token = (string) $tokens->idToken;
		$attach   = static function ( $session ) use ( $id_token ) {
			$session[ self::SESSION_KEY ] = $id_token;
			return $session;
		};
		add_filter( 'attach_session_information', $attach );
		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID, false, is_ssl() );
		remove_filter( 'attach_session_information', $attach );
		do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core hook
		/**
		 * An OpenBack user signed in to WordPress.
		 *
		 * @param \WP_User             $user
		 * @param array<string, mixed> $claims
		 */
		do_action( 'openback_app_auth_login', $user, $claims );

		$requested   = (string) ( $tx['redirect_to'] ?? '' );
		$redirect_to = '' !== $requested ? $requested : ( user_can( $user, 'edit_posts' ) ? admin_url() : home_url( '/' ) );
		$redirect_to = apply_filters( 'login_redirect', $redirect_to, $requested, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core hook
		wp_safe_redirect( $redirect_to );
		exit;
	}

	/** @param array<string, mixed> $claims */
	private function finish_link( int $user_id, array $claims ): void {
		$users = $this->plugin->users();
		$user  = get_user_by( 'id', $user_id );
		$other = $users->find_linked( (string) $claims['sub'], is_string( $claims['pool'] ?? null ) ? $claims['pool'] : null );
		$mine  = $user instanceof \WP_User ? $users->linked_sub( $user_id ) : null;
		if ( ! $user instanceof \WP_User || ( $other && $other->ID !== $user_id ) || ( null !== $mine && $mine !== $claims['sub'] ) ) {
			$this->fail( 'already_linked', $user_id );
		}
		$users->link( $user_id, $claims );
		wp_safe_redirect( add_query_arg( 'openback_app_auth', 'linked', admin_url( 'profile.php' ) ) );
		exit;
	}

	private function fail( string $code, int $link_user ): never {
		$code = in_array( $code, self::ERRORS, true ) ? $code : 'sign_in_failed';
		$url  = $link_user > 0
			? add_query_arg( 'openback_app_auth_error', $code, admin_url( 'profile.php' ) )
			: add_query_arg( 'openback_app_auth_error', $code, wp_login_url() );
		wp_safe_redirect( $url );
		exit;
	}

	/** The message of an error code (escaped by the caller). */
	public static function error_message( string $code ): string {
		switch ( $code ) {
			case 'invalid_state':
				return __( 'The sign-in expired or was started in another browser. Please try again.', 'openback-app-auth-wordpress' );
			case 'cancelled':
				return __( 'The sign-in was cancelled.', 'openback-app-auth-wordpress' );
			case 'not_configured':
				return __( 'Sign-in with OpenBack is not configured yet.', 'openback-app-auth-wordpress' );
			case 'email_exists':
				return __( 'An account with this email address already exists. Sign in with your password, then link your OpenBack account from your profile.', 'openback-app-auth-wordpress' );
			case 'email_not_verified':
				return __( 'Your email address is not verified yet.', 'openback-app-auth-wordpress' );
			case 'no_account':
				return __( 'There is no account on this site for you.', 'openback-app-auth-wordpress' );
			case 'admin_link_refused':
				return __( 'Administrator accounts are not linked automatically: sign in with your password and link the account from your profile.', 'openback-app-auth-wordpress' );
			case 'already_linked':
				return __( 'This account is already linked to another OpenBack account.', 'openback-app-auth-wordpress' );
			case 'registration_failed':
				return __( 'Your account could not be created.', 'openback-app-auth-wordpress' );
			case 'not_allowed':
				return __( 'You are not allowed to sign in to this site.', 'openback-app-auth-wordpress' );
			case 'unavailable':
				return __( 'The sign-in service cannot be reached right now. Please try again later.', 'openback-app-auth-wordpress' );
			default:
				return __( 'The sign-in failed. Please try again.', 'openback-app-auth-wordpress' );
		}
	}

	/** wp_login_errors: shows our error on wp-login.php. */
	public function login_errors( \WP_Error $errors ): \WP_Error {
		$code = isset( $_GET['openback_app_auth_error'] ) ? sanitize_key( wp_unslash( $_GET['openback_app_auth_error'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only
		if ( '' !== $code ) {
			$errors->add( 'openback_app_auth', esc_html( self::error_message( $code ) ) );
		}
		return $errors;
	}

	/** login_form_logout: remembers the ID token of the session being closed (single logout). */
	public function capture_logout(): void {
		if ( ! $this->plugin->settings()->flag( 'single_logout' ) || ! is_user_logged_in() ) {
			return;
		}
		$session = \WP_Session_Tokens::get_instance( get_current_user_id() )->get( wp_get_session_token() );
		if ( is_array( $session ) && is_string( $session[ self::SESSION_KEY ] ?? null ) && '' !== $session[ self::SESSION_KEY ] ) {
			$this->logout_id_token = $session[ self::SESSION_KEY ];
		}
	}

	/**
	 * logout_redirect: to the pool's end-session address, which then returns to the registered post-logout URI.
	 *
	 * @param string $redirect_to
	 */
	public function logout_redirect( $redirect_to, $requested = '', $user = null ): string {
		if ( null === $this->logout_id_token || ! $this->plugin->settings()->configured() ) {
			return (string) $redirect_to;
		}
		return $this->plugin->oidc()->logoutUrl( $this->logout_id_token, $this->plugin->settings()->post_logout_redirect() );
	}

	/**
	 * @param string[] $hosts
	 * @return string[]
	 */
	public function allowed_hosts( $hosts ): array {
		$hosts = (array) $hosts;
		if ( null !== $this->logout_id_token ) {
			$host = wp_parse_url( $this->plugin->settings()->issuer(), PHP_URL_HOST );
			if ( is_string( $host ) && '' !== $host ) {
				$hosts[] = $host;
			}
		}
		return $hosts;
	}
}
