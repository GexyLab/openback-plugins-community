<?php

declare(strict_types=1);

// Bundled copy of openback-app-auth-php 1.0.0 (MIT), namespace prefixed for this plugin.

namespace OpenBackAppAuthWp\Sdk\Http;

use OpenBackAppAuthWp\Sdk\AppAuthException;

/**
 * The SDK's HTTP layer: one method. Implementations: {@see CurlTransport} (ext-curl, the default),
 * {@see Psr18Transport} (any PSR-18 client), or your own (the WordPress and Joomla plugins use their CMS's HTTP API).
 */
interface HttpTransport
{
    /**
     * Sends a request. Answers with any status are returned (not thrown); a failure to reach the server throws.
     *
     * @param array<string, string> $headers
     * @throws AppAuthException status 0, code `network_error`, when the server could not be reached
     */
    public function send(string $method, string $url, array $headers = [], ?string $body = null): HttpResponse;
}
