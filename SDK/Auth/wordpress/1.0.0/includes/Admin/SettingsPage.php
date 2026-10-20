<?php
/**
 * Settings > OpenBack App Auth.
 *
 * @package openback-app-auth-wordpress
 */

declare(strict_types=1);

namespace OpenBackAppAuthWp\Admin;

use OpenBackAppAuthWp\Login;
use OpenBackAppAuthWp\Plugin;
use OpenBackAppAuthWp\Settings;
use OpenBackAppAuthWp\Sdk\AppAuthException;

defined( 'ABSPATH' ) || exit;

final class SettingsPage {

	public const SLUG = 'openback-app-auth';

	public function __construct( private readonly Plugin $plugin ) {
	}

	public function register(): void {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_init', array( $this, 'register_setting' ) );
		add_action( 'admin_post_openback_app_auth_check', array( $this, 'check' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( OPENBACK_APP_AUTH_WP_FILE ), array( $this, 'action_links' ) );
	}

	public function menu(): void {
		add_options_page(
			__( 'OpenBack App Auth', 'openback-app-auth-wordpress' ),
			__( 'OpenBack App Auth', 'openback-app-auth-wordpress' ),
			'manage_options',
			self::SLUG,
			array( $this, 'render' )
		);
	}

	public function register_setting(): void {
		register_setting(
			'openback_app_auth',
			Settings::OPTION,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this->plugin->settings(), 'sanitize' ),
				'default'           => Settings::defaults(),
				'show_in_rest'      => false,
			)
		);
	}

	/**
	 * @param string[] $links
	 * @return string[]
	 */
	public function action_links( $links ): array {
		$links   = (array) $links;
		$links[] = '<a href="' . esc_url( admin_url( 'options-general.php?page=' . self::SLUG ) ) . '">' . esc_html__( 'Settings', 'openback-app-auth-wordpress' ) . '</a>';
		return $links;
	}

	/** admin-post: fetches the pool's discovery document and checks the issuer. */
	public function check(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'openback-app-auth-wordpress' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'openback_app_auth_check' );
		$settings = $this->plugin->settings();
		$result   = array(
			'ok'      => false,
			'message' => __( 'Set the pool address first.', 'openback-app-auth-wordpress' ),
		);
		if ( '' !== $settings->issuer() ) {
			try {
				$response = $this->plugin->transport()->send( 'GET', $settings->issuer() . '/.well-known/openid-configuration', array( 'Accept' => 'application/json' ) );
				$data     = $response->json();
				if ( ! $response->ok() || ! is_array( $data ) ) {
					/* translators: %d: HTTP status */
					$result['message'] = sprintf( __( 'The pool answered with HTTP %d.', 'openback-app-auth-wordpress' ), $response->status );
				} elseif ( ( $data['issuer'] ?? null ) !== $settings->issuer() ) {
					/* translators: %s: the issuer announced by the pool */
					$result['message'] = sprintf( __( 'The pool announces another issuer: %s. Use exactly that address.', 'openback-app-auth-wordpress' ), (string) ( $data['issuer'] ?? '' ) );
				} else {
					$result = array(
						'ok'      => true,
						/* translators: %s: pool mode (b2c or b2b) */
						'message' => sprintf( __( 'The pool answers (mode %s).', 'openback-app-auth-wordpress' ), (string) ( $data['x_openback']['mode'] ?? '?' ) ),
					);
				}
			} catch ( AppAuthException $e ) {
				$result['message'] = __( 'The pool cannot be reached from this server.', 'openback-app-auth-wordpress' );
			}
		}
		set_transient( 'openback_app_auth_check_' . get_current_user_id(), $result, 60 );
		wp_safe_redirect( admin_url( 'options-general.php?page=' . self::SLUG ) );
		exit;
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$s     = $this->plugin->settings()->all();
		$name  = Settings::OPTION;
		$check = get_transient( 'openback_app_auth_check_' . get_current_user_id() );
		if ( is_array( $check ) ) {
			delete_transient( 'openback_app_auth_check_' . get_current_user_id() );
		}
		$roles = wp_roles()->get_names();
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'OpenBack App Auth', 'openback-app-auth-wordpress' ); ?></h1>
			<?php if ( is_array( $check ) ) : ?>
				<div class="notice <?php echo $check['ok'] ? 'notice-success' : 'notice-error'; ?> is-dismissible"><p><?php echo esc_html( (string) $check['message'] ); ?></p></div>
			<?php endif; ?>

			<h2><?php esc_html_e( 'Register this site in the user pool', 'openback-app-auth-wordpress' ); ?></h2>
			<p><?php esc_html_e( 'In the OpenBack portal, open the user pool, tab Apps, and add an app of kind "web" with these addresses (they must match exactly):', 'openback-app-auth-wordpress' ); ?></p>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e( 'Redirect URI', 'openback-app-auth-wordpress' ); ?></th>
					<td><code><?php echo esc_html( Settings::redirect_uri() ); ?></code>
						<p class="description"><?php esc_html_e( 'It changes if you change the permalink settings: register the new one then.', 'openback-app-auth-wordpress' ); ?></p></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Post-logout redirect URI', 'openback-app-auth-wordpress' ); ?></th>
					<td><code><?php echo esc_html( $this->plugin->settings()->post_logout_redirect() ); ?></code></td>
				</tr>
			</table>

			<form method="post" action="options.php">
				<?php settings_fields( 'openback_app_auth' ); ?>
				<h2><?php esc_html_e( 'Connection', 'openback-app-auth-wordpress' ); ?></h2>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="oba-issuer"><?php esc_html_e( 'Pool address (issuer)', 'openback-app-auth-wordpress' ); ?></label></th>
						<td><input type="url" class="regular-text code" id="oba-issuer" name="<?php echo esc_attr( $name ); ?>[issuer]" value="<?php echo esc_attr( (string) $s['issuer'] ); ?>" placeholder="https://api.example.com/gateway/shop/auth/main" />
							<p class="description"><?php esc_html_e( 'Shown in the pool\'s page of the OpenBack portal.', 'openback-app-auth-wordpress' ); ?></p></td>
					</tr>
					<tr>
						<th scope="row"><label for="oba-client-id"><?php esc_html_e( 'Client ID', 'openback-app-auth-wordpress' ); ?></label></th>
						<td><input type="text" class="regular-text code" id="oba-client-id" name="<?php echo esc_attr( $name ); ?>[client_id]" value="<?php echo esc_attr( (string) $s['client_id'] ); ?>" placeholder="uapp_..." autocomplete="off" /></td>
					</tr>
					<tr>
						<th scope="row"><label for="oba-client-secret"><?php esc_html_e( 'Client secret', 'openback-app-auth-wordpress' ); ?></label></th>
						<td>
							<?php if ( $this->plugin->settings()->secret_from_constant() ) : ?>
								<p><?php esc_html_e( 'Set by the constant OPENBACK_APP_AUTH_CLIENT_SECRET in wp-config.php.', 'openback-app-auth-wordpress' ); ?></p>
							<?php else : ?>
								<input type="password" class="regular-text" id="oba-client-secret" name="<?php echo esc_attr( $name ); ?>[client_secret]" value="" autocomplete="new-password"
									placeholder="<?php echo '' !== (string) $s['client_secret'] ? esc_attr__( '(stored: leave empty to keep it)', 'openback-app-auth-wordpress' ) : ''; ?>" />
								<?php if ( '' !== (string) $s['client_secret'] ) : ?>
									<label><input type="checkbox" name="<?php echo esc_attr( $name ); ?>[clear_client_secret]" value="1" /> <?php esc_html_e( 'Remove the stored secret', 'openback-app-auth-wordpress' ); ?></label>
								<?php endif; ?>
								<p class="description"><?php esc_html_e( 'Or define OPENBACK_APP_AUTH_CLIENT_SECRET in wp-config.php to keep it out of the database.', 'openback-app-auth-wordpress' ); ?></p>
							<?php endif; ?>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="oba-scopes"><?php esc_html_e( 'Scopes', 'openback-app-auth-wordpress' ); ?></label></th>
						<td><input type="text" class="regular-text code" id="oba-scopes" name="<?php echo esc_attr( $name ); ?>[scopes]" value="<?php echo esc_attr( (string) $s['scopes'] ); ?>" /></td>
					</tr>
					<tr>
						<th scope="row"><label for="oba-provider"><?php esc_html_e( 'Provider (optional)', 'openback-app-auth-wordpress' ); ?></label></th>
						<td><input type="text" class="regular-text code" id="oba-provider" name="<?php echo esc_attr( $name ); ?>[provider]" value="<?php echo esc_attr( (string) $s['provider'] ); ?>" placeholder="uprov_..." />
							<p class="description"><?php esc_html_e( 'A provider id of the pool to go straight to it (e.g. Google) instead of the pool\'s sign-in page.', 'openback-app-auth-wordpress' ); ?></p></td>
					</tr>
					<tr>
						<th scope="row"><label for="oba-label"><?php esc_html_e( 'Button label', 'openback-app-auth-wordpress' ); ?></label></th>
						<td><input type="text" class="regular-text" id="oba-label" name="<?php echo esc_attr( $name ); ?>[button_label]" value="<?php echo esc_attr( (string) $s['button_label'] ); ?>" placeholder="<?php esc_attr_e( 'Sign in with OpenBack', 'openback-app-auth-wordpress' ); ?>" /></td>
					</tr>
				</table>

				<h2><?php esc_html_e( 'Accounts', 'openback-app-auth-wordpress' ); ?></h2>
				<table class="form-table" role="presentation">
					<?php
					$this->checkbox( 'auto_create', __( 'Create a WordPress account for new users', 'openback-app-auth-wordpress' ), (bool) $s['auto_create'] );
					$this->checkbox( 'require_verified_email', __( 'Create accounts only for verified email addresses', 'openback-app-auth-wordpress' ), (bool) $s['require_verified_email'] );
					$this->checkbox(
						'link_by_email',
						__( 'Link existing accounts by verified email address', 'openback-app-auth-wordpress' ),
						(bool) $s['link_by_email'],
						__( 'Off by default. Trust the pool\'s email verification before turning it on. Administrators are never linked this way: they link their account from their profile.', 'openback-app-auth-wordpress' )
					);
					?>
					<tr>
						<th scope="row"><label for="oba-role-map"><?php esc_html_e( 'Role mapping', 'openback-app-auth-wordpress' ); ?></label></th>
						<td><textarea class="large-text code" rows="4" id="oba-role-map" name="<?php echo esc_attr( $name ); ?>[role_map]" placeholder="admin = editor&#10;member = subscriber"><?php echo esc_textarea( (string) $s['role_map'] ); ?></textarea>
							<p class="description"><?php esc_html_e( 'One rule per line: OpenBack role = WordPress role. The first rule matching one of the user\'s roles wins.', 'openback-app-auth-wordpress' ); ?></p></td>
					</tr>
					<tr>
						<th scope="row"><label for="oba-default-role"><?php esc_html_e( 'Default role', 'openback-app-auth-wordpress' ); ?></label></th>
						<td><select id="oba-default-role" name="<?php echo esc_attr( $name ); ?>[default_role]">
							<option value=""><?php esc_html_e( '(the site\'s default role)', 'openback-app-auth-wordpress' ); ?></option>
							<?php foreach ( $roles as $slug => $label ) : ?>
								<option value="<?php echo esc_attr( (string) $slug ); ?>" <?php selected( (string) $s['default_role'], (string) $slug ); ?>><?php echo esc_html( translate_user_role( (string) $label ) ); ?></option>
							<?php endforeach; ?>
						</select></td>
					</tr>
					<?php $this->checkbox( 'sync_roles', __( 'Update the role at every sign-in (never for administrators)', 'openback-app-auth-wordpress' ), (bool) $s['sync_roles'] ); ?>
				</table>

				<h2><?php esc_html_e( 'Sign-in and sign-out', 'openback-app-auth-wordpress' ); ?></h2>
				<table class="form-table" role="presentation">
					<?php
					$this->checkbox(
						'hide_password_login',
						__( 'Hide the WordPress password form on the login page', 'openback-app-auth-wordpress' ),
						(bool) $s['hide_password_login'],
						__( 'The form stays reachable at wp-login.php?openback_password=1. This hides the form; it does not disable password sign-in.', 'openback-app-auth-wordpress' )
					);
					$this->checkbox( 'single_logout', __( 'Sign out of the pool too when signing out of WordPress (single logout)', 'openback-app-auth-wordpress' ), (bool) $s['single_logout'] );
					?>
					<tr>
						<th scope="row"><label for="oba-post-logout"><?php esc_html_e( 'Post-logout redirect URI', 'openback-app-auth-wordpress' ); ?></label></th>
						<td><input type="url" class="regular-text code" id="oba-post-logout" name="<?php echo esc_attr( $name ); ?>[post_logout_redirect]" value="<?php echo esc_attr( (string) $s['post_logout_redirect'] ); ?>" placeholder="<?php echo esc_attr( home_url( '/' ) ); ?>" />
							<p class="description"><?php esc_html_e( 'Where the pool sends the browser after signing out. Register it on the app.', 'openback-app-auth-wordpress' ); ?></p></td>
					</tr>
				</table>

				<h2><?php esc_html_e( 'REST API', 'openback-app-auth-wordpress' ); ?></h2>
				<table class="form-table" role="presentation">
					<?php
					$this->checkbox(
						'rest_bearer',
						__( 'Accept pool access tokens (Authorization: Bearer) on the WordPress REST API', 'openback-app-auth-wordpress' ),
						(bool) $s['rest_bearer'],
						__( 'Requests run as the WordPress user linked to the token\'s user. Off by default.', 'openback-app-auth-wordpress' )
					);
					?>
					<tr>
						<th scope="row"><label for="oba-rest-ids"><?php esc_html_e( 'Other accepted client IDs', 'openback-app-auth-wordpress' ); ?></label></th>
						<td><input type="text" class="regular-text code" id="oba-rest-ids" name="<?php echo esc_attr( $name ); ?>[rest_client_ids]" value="<?php echo esc_attr( (string) $s['rest_client_ids'] ); ?>" placeholder="uapp_mobile..., uapp_spa..." />
							<p class="description"><?php esc_html_e( 'Tokens of these apps of the same pool are accepted too (e.g. your mobile app).', 'openback-app-auth-wordpress' ); ?></p></td>
					</tr>
				</table>
				<?php submit_button(); ?>
			</form>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="openback_app_auth_check" />
				<?php wp_nonce_field( 'openback_app_auth_check' ); ?>
				<?php submit_button( __( 'Check the connection to the pool', 'openback-app-auth-wordpress' ), 'secondary', 'submit', false ); ?>
			</form>

			<h2><?php esc_html_e( 'The button elsewhere', 'openback-app-auth-wordpress' ); ?></h2>
			<p><?php esc_html_e( 'Shortcode:', 'openback-app-auth-wordpress' ); ?> <code>[openback_app_auth_login label="" redirect_to="" show_logout="0"]</code>
				&middot; <?php esc_html_e( 'Block: "OpenBack sign-in button".', 'openback-app-auth-wordpress' ); ?>
				&middot; <?php esc_html_e( 'Direct link:', 'openback-app-auth-wordpress' ); ?> <code><?php echo esc_html( Login::start_url() ); ?></code></p>
		</div>
		<?php
	}

	private function checkbox( string $key, string $label, bool $checked, string $description = '' ): void {
		?>
		<tr>
			<th scope="row"><?php echo esc_html( $label ); ?></th>
			<td>
				<label><input type="checkbox" name="<?php echo esc_attr( Settings::OPTION . '[' . $key . ']' ); ?>" value="1" <?php checked( $checked ); ?> /> <?php esc_html_e( 'On', 'openback-app-auth-wordpress' ); ?></label>
				<?php if ( '' !== $description ) : ?>
					<p class="description"><?php echo esc_html( $description ); ?></p>
				<?php endif; ?>
			</td>
		</tr>
		<?php
	}
}
