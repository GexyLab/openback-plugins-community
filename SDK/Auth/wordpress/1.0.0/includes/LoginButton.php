<?php
/**
 * The "Sign in with ..." button: on wp-login.php, as the shortcode [openback_app_auth_login] and as the block
 * openback-app-auth/login-button. Optionally hides the WordPress password form on wp-login.php.
 *
 * @package openback-app-auth-wordpress
 */

declare(strict_types=1);

namespace OpenBackAppAuthWp;

defined( 'ABSPATH' ) || exit;

final class LoginButton {

	public const SHORTCODE = 'openback_app_auth_login';

	public function __construct( private readonly Plugin $plugin ) {
	}

	public function register(): void {
		add_action( 'login_form', array( $this, 'login_form' ) );
		add_action( 'login_enqueue_scripts', array( $this, 'login_styles' ) );
		add_action( 'init', array( $this, 'register_block_and_shortcode' ) );
	}

	public function register_block_and_shortcode(): void {
		wp_register_style( 'openback-app-auth', plugins_url( 'assets/login.css', OPENBACK_APP_AUTH_WP_FILE ), array(), OPENBACK_APP_AUTH_WP_VERSION );
		add_shortcode( self::SHORTCODE, array( $this, 'shortcode' ) );
		register_block_type(
			OPENBACK_APP_AUTH_WP_DIR . '/blocks/login-button',
			array( 'render_callback' => array( $this, 'render_block' ) )
		);
	}

	/**
	 * The button's HTML (escaped). Signed-in visitors get nothing, or a sign-out link with $show_logout.
	 */
	public function html( string $label = '', string $redirect_to = '', bool $show_logout = false ): string {
		if ( is_user_logged_in() ) {
			if ( ! $show_logout ) {
				return '';
			}
			return '<a class="openback-app-auth-button openback-app-auth-logout" href="' . esc_url( wp_logout_url( home_url( '/' ) ) ) . '">'
				. esc_html__( 'Sign out', 'openback-app-auth-wordpress' ) . '</a>';
		}
		if ( ! $this->plugin->settings()->configured() ) {
			return current_user_can( 'manage_options' )
				? '<p class="openback-app-auth-notice">' . esc_html__( 'OpenBack App Auth is not configured yet (Settings > OpenBack App Auth).', 'openback-app-auth-wordpress' ) . '</p>'
				: '';
		}
		$label = '' !== trim( $label ) ? $label : $this->plugin->settings()->button_label();
		$url   = Login::start_url( $redirect_to );
		return '<a class="openback-app-auth-button button button-large" href="' . esc_url( $url ) . '" rel="nofollow">' . esc_html( $label ) . '</a>';
	}

	/** wp-login.php: the button under the form. */
	public function login_form(): void {
		$redirect_to = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- a link, nothing changes
		$button      = $this->html( '', $redirect_to );
		if ( '' === $button ) {
			return;
		}
		echo '<div class="openback-app-auth-login">';
		if ( ! $this->hide_password_form() ) {
			echo '<p class="openback-app-auth-separator"><span>' . esc_html__( 'or', 'openback-app-auth-wordpress' ) . '</span></p>';
		}
		echo $button; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built escaped in html()
		if ( $this->hide_password_form() ) {
			echo '<p class="openback-app-auth-password-link"><a href="' . esc_url( add_query_arg( 'openback_password', '1', wp_login_url( $redirect_to ) ) ) . '">'
				. esc_html__( 'Sign in with a WordPress password', 'openback-app-auth-wordpress' ) . '</a></p>';
		}
		echo '</div>';
	}

	public function login_styles(): void {
		wp_enqueue_style( 'openback-app-auth', plugins_url( 'assets/login.css', OPENBACK_APP_AUTH_WP_FILE ), array(), OPENBACK_APP_AUTH_WP_VERSION );
		if ( $this->hide_password_form() ) {
			// Only the button stays visible; ?openback_password=1 shows the password form again.
			wp_add_inline_style(
				'openback-app-auth',
				'#loginform > :not(.openback-app-auth-login), #nav, .user-pass-wrap, .forgetmenot, #loginform .submit { display: none !important; }'
			);
		}
	}

	private function hide_password_form(): bool {
		$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : 'login'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		return $this->plugin->settings()->flag( 'hide_password_login' )
			&& $this->plugin->settings()->configured()
			&& 'login' === $action
			&& empty( $_GET['openback_password'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
	}

	/**
	 * [openback_app_auth_login label="..." redirect_to="..." show_logout="1"]
	 *
	 * @param array<string, string>|string $atts
	 */
	public function shortcode( $atts ): string {
		$atts = shortcode_atts(
			array(
				'label'       => '',
				'redirect_to' => '',
				'show_logout' => '0',
			),
			is_array( $atts ) ? $atts : array(),
			self::SHORTCODE
		);
		wp_enqueue_style( 'openback-app-auth' );
		$redirect = (string) wp_validate_redirect( esc_url_raw( (string) $atts['redirect_to'] ), '' );
		if ( '' === $redirect ) {
			$redirect = self::current_url();
		}
		return '<div class="openback-app-auth-shortcode">' . $this->html( sanitize_text_field( (string) $atts['label'] ), $redirect, '1' === (string) $atts['show_logout'] ) . '</div>';
	}

	/**
	 * The block's server-side rendering.
	 *
	 * @param array<string, mixed> $attributes
	 */
	public function render_block( array $attributes ): string {
		wp_enqueue_style( 'openback-app-auth' );
		$label    = sanitize_text_field( (string) ( $attributes['label'] ?? '' ) );
		$redirect = (string) wp_validate_redirect( esc_url_raw( (string) ( $attributes['redirectTo'] ?? '' ) ), '' );
		$html     = $this->html( $label, '' !== $redirect ? $redirect : self::current_url(), ! empty( $attributes['showLogout'] ) );
		if ( '' === $html ) {
			return '';
		}
		$wrapper = function_exists( 'get_block_wrapper_attributes' ) ? get_block_wrapper_attributes( array( 'class' => 'openback-app-auth-block' ) ) : 'class="openback-app-auth-block"';
		return '<div ' . $wrapper . '>' . $html . '</div>';
	}

	private static function current_url(): string {
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '/'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- validated below
		$host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		$port = wp_parse_url( home_url(), PHP_URL_PORT );
		$url  = ( is_ssl() ? 'https://' : 'http://' ) . $host . ( $port ? ':' . $port : '' ) . '/' . ltrim( (string) $uri, '/' );
		return (string) wp_validate_redirect( esc_url_raw( $url ), home_url( '/' ) );
	}
}
