<?php
/**
 * Wires the plugin into WordPress and builds its services lazily.
 *
 * @package openback-app-auth-wordpress
 */

declare(strict_types=1);

namespace OpenBackAppAuthWp;

use OpenBackAppAuthWp\Admin\Profile;
use OpenBackAppAuthWp\Admin\SettingsPage;
use OpenBackAppAuthWp\Sdk\Http\HttpTransport;
use OpenBackAppAuthWp\Sdk\OidcWebClient;
use OpenBackAppAuthWp\Sdk\TokenVerifier;

defined( 'ABSPATH' ) || exit;

final class Plugin {

	private static ?Plugin $instance = null;

	private ?Settings $settings          = null;
	private ?Users $users                = null;
	private ?StateStore $states          = null;
	private ?HttpTransport $transport    = null;
	private ?OidcWebClient $oidc         = null;
	private ?TokenVerifier $rest_verifier = null;

	public static function instance(): self {
		return self::$instance ??= new self();
	}

	public function boot(): void {
		add_action( 'init', array( $this, 'load_textdomain' ) );
		( new Login( $this ) )->register();
		( new LoginButton( $this ) )->register();
		( new RestBearerAuth( $this ) )->register();
		if ( is_admin() ) {
			( new SettingsPage( $this ) )->register();
			( new Profile( $this ) )->register();
		}
		add_action( 'update_option_' . Settings::OPTION, array( $this, 'settings_changed' ) );
		add_action( 'add_option_' . Settings::OPTION, array( $this, 'settings_changed' ) );
	}

	public function load_textdomain(): void {
		load_plugin_textdomain( 'openback-app-auth-wordpress', false, dirname( plugin_basename( OPENBACK_APP_AUTH_WP_FILE ) ) . '/languages' );
	}

	public function settings_changed(): void {
		$this->settings?->flush();
		$this->oidc          = null;
		$this->rest_verifier = null;
	}

	public function settings(): Settings {
		return $this->settings ??= new Settings();
	}

	public function users(): Users {
		return $this->users ??= new Users( $this->settings() );
	}

	public function transport(): HttpTransport {
		return $this->transport ??= new WpHttpTransport();
	}

	public function states(): StateStore {
		return $this->states ??= new StateStore(
			new TransientStateBackend(),
			static function (): ?string {
				return isset( $_COOKIE[ StateStore::COOKIE ] ) && is_string( $_COOKIE[ StateStore::COOKIE ] ) ? sanitize_text_field( wp_unslash( $_COOKIE[ StateStore::COOKIE ] ) ) : null;
			},
			static function ( string $value, int $ttl ): void {
				if ( headers_sent() ) {
					return;
				}
				setcookie(
					StateStore::COOKIE,
					$value,
					array(
						'expires'  => time() + $ttl,
						'path'     => COOKIEPATH ? COOKIEPATH : '/',
						'domain'   => COOKIE_DOMAIN ? COOKIE_DOMAIN : '',
						'secure'   => is_ssl(),
						'httponly' => true,
						'samesite' => 'Lax',      // sent on the top-level redirect back from the pool
					)
				);
				$_COOKIE[ StateStore::COOKIE ] = $value;
			}
		);
	}

	/** The OIDC client of the configured `web` app. */
	public function oidc(): OidcWebClient {
		if ( null === $this->oidc ) {
			$settings   = $this->settings();
			$this->oidc = new OidcWebClient(
				$settings->issuer(),
				$settings->client_id(),
				$settings->client_secret(),
				Settings::redirect_uri(),
				array(
					'transport' => $this->transport(),
					'cache'     => new TransientJwksCache(),
					'scope'     => (string) $settings->get( 'scopes' ),
				)
			);
		}
		return $this->oidc;
	}

	/** The access-token verifier of the REST API (this app's client ID and the extra ones). */
	public function rest_verifier(): TokenVerifier {
		return $this->rest_verifier ??= new TokenVerifier(
			$this->settings()->issuer(),
			$this->settings()->rest_client_ids(),
			array(
				'transport' => $this->transport(),
				'cache'     => new TransientJwksCache(),
			)
		);
	}
}
