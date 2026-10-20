<?php
/**
 * The OpenBack link on the user profile: status, "Link my OpenBack account", "Remove the link".
 *
 * @package openback-app-auth-wordpress
 */

declare(strict_types=1);

namespace OpenBackAppAuthWp\Admin;

use OpenBackAppAuthWp\Login;
use OpenBackAppAuthWp\Plugin;

defined( 'ABSPATH' ) || exit;

final class Profile {

	public function __construct( private readonly Plugin $plugin ) {
	}

	public function register(): void {
		add_action( 'show_user_profile', array( $this, 'render' ) );
		add_action( 'edit_user_profile', array( $this, 'render' ) );
		add_action( 'admin_notices', array( $this, 'notices' ) );
	}

	public function render( \WP_User $user ): void {
		if ( ! current_user_can( 'edit_user', $user->ID ) ) {
			return;
		}
		$sub = $this->plugin->users()->linked_sub( $user->ID );
		$own = get_current_user_id() === $user->ID;
		?>
		<h2><?php esc_html_e( 'OpenBack account', 'openback-app-auth-wordpress' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'Link', 'openback-app-auth-wordpress' ); ?></th>
				<td>
					<?php if ( null !== $sub ) : ?>
						<p><?php esc_html_e( 'Linked to the pool user', 'openback-app-auth-wordpress' ); ?> <code><?php echo esc_html( $sub ); ?></code></p>
						<p><a class="button" href="<?php echo esc_url( wp_nonce_url( add_query_arg( array( 'action' => 'openback_app_auth_unlink', 'user_id' => $user->ID ), admin_url( 'admin-post.php' ) ), 'openback_app_auth_unlink_' . $user->ID ) ); ?>"><?php esc_html_e( 'Remove the link', 'openback-app-auth-wordpress' ); ?></a></p>
					<?php else : ?>
						<p><?php esc_html_e( 'Not linked.', 'openback-app-auth-wordpress' ); ?></p>
						<?php if ( $own && $this->plugin->settings()->configured() ) : ?>
							<p><a class="button" href="<?php echo esc_url( wp_nonce_url( add_query_arg( 'action', 'openback_app_auth_link', admin_url( 'admin-post.php' ) ), 'openback_app_auth_link' ) ); ?>"><?php esc_html_e( 'Link my OpenBack account', 'openback-app-auth-wordpress' ); ?></a></p>
						<?php endif; ?>
					<?php endif; ?>
				</td>
			</tr>
		</table>
		<?php
	}

	public function notices(): void {
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( ! $screen || ! in_array( $screen->id, array( 'profile', 'user-edit' ), true ) ) {
			return;
		}
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- display only
		$done  = isset( $_GET['openback_app_auth'] ) ? sanitize_key( wp_unslash( $_GET['openback_app_auth'] ) ) : '';
		$error = isset( $_GET['openback_app_auth_error'] ) ? sanitize_key( wp_unslash( $_GET['openback_app_auth_error'] ) ) : '';
		// phpcs:enable
		if ( 'linked' === $done ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Your OpenBack account is linked.', 'openback-app-auth-wordpress' ) . '</p></div>';
		} elseif ( 'unlinked' === $done ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'The OpenBack link was removed.', 'openback-app-auth-wordpress' ) . '</p></div>';
		} elseif ( '' !== $error ) {
			echo '<div class="notice notice-error is-dismissible"><p>' . esc_html( Login::error_message( $error ) ) . '</p></div>';
		}
	}
}
