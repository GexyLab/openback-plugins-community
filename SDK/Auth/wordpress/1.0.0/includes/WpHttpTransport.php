<?php
/**
 * The SDK's HTTP layer on WordPress's HTTP API (proxies, certificates and filters of the site apply).
 *
 * @package openback-app-auth-wordpress
 */

declare(strict_types=1);

namespace OpenBackAppAuthWp;

use OpenBackAppAuthWp\Sdk\AppAuthException;
use OpenBackAppAuthWp\Sdk\Http\HttpResponse;
use OpenBackAppAuthWp\Sdk\Http\HttpTransport;

defined( 'ABSPATH' ) || exit;

final class WpHttpTransport implements HttpTransport {

	public function send( string $method, string $url, array $headers = array(), ?string $body = null ): HttpResponse {
		$args = array(
			'method'      => strtoupper( $method ),
			'headers'     => $headers,
			'timeout'     => 15,
			'redirection' => 0,
			'sslverify'   => true,
			'user-agent'  => 'openback-app-auth-wordpress/' . OPENBACK_APP_AUTH_WP_VERSION,
		);
		if ( null !== $body ) {
			$args['body'] = $body;
		}
		$response = wp_remote_request( $url, $args );
		if ( is_wp_error( $response ) ) {
			throw new AppAuthException( 0, 'network_error', 'The server could not be reached: ' . $response->get_error_message() );
		}
		$out_headers = array();
		$raw_headers = wp_remote_retrieve_headers( $response );
		if ( is_object( $raw_headers ) && method_exists( $raw_headers, 'getAll' ) ) {
			$raw_headers = $raw_headers->getAll();
		}
		foreach ( (array) $raw_headers as $name => $value ) {
			$out_headers[ (string) $name ] = is_array( $value ) ? implode( ', ', $value ) : (string) $value;
		}
		return new HttpResponse( (int) wp_remote_retrieve_response_code( $response ), $out_headers, (string) wp_remote_retrieve_body( $response ) );
	}
}
