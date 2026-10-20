<?php

declare(strict_types=1);

// Bundled copy of openback-app-auth-php 1.0.0 (MIT), namespace prefixed for this extension.

namespace OpenBackAppAuthJoomla\Sdk\Http;

\defined('_JEXEC') or die;

use OpenBackAppAuthJoomla\Sdk\AppAuthException;

/** The built-in transport on ext-curl: no HTTP library needed. TLS certificates are verified; redirects are not followed. */
final class CurlTransport implements HttpTransport
{
    public function __construct(private readonly int $timeoutSeconds = 15, private readonly int $connectTimeoutSeconds = 10)
    {
        if (!function_exists('curl_init')) {
            throw new \LogicException('CurlTransport needs ext-curl; install it or pass a PSR-18 client (httpClient option)');
        }
    }

    public function send(string $method, string $url, array $headers = [], ?string $body = null): HttpResponse
    {
        if (!preg_match('#^https?://#i', $url)) {
            throw new AppAuthException(0, 'invalid_url', 'Only http(s) addresses are allowed');
        }
        $handle = curl_init($url);
        if ($handle === false) {
            throw new AppAuthException(0, 'network_error', 'Could not start the HTTP request');
        }
        $lines = [];
        foreach ($headers as $name => $value) {
            $lines[] = $name . ': ' . $value;
        }
        $responseHeaders = [];
        $options = [
            CURLOPT_CUSTOMREQUEST => strtoupper($method),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => $this->timeoutSeconds,
            CURLOPT_CONNECTTIMEOUT => $this->connectTimeoutSeconds,
            CURLOPT_HTTPHEADER => $lines,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HEADERFUNCTION => static function ($ch, string $line) use (&$responseHeaders): int {
                $parts = explode(':', $line, 2);
                if (count($parts) === 2) {
                    $responseHeaders[strtolower(trim($parts[0]))] = trim($parts[1]);
                } elseif (str_starts_with($line, 'HTTP/')) {
                    $responseHeaders = [];     // a new answer (100 Continue, proxies)
                }
                return strlen($line);
            },
        ];
        if (defined('CURLOPT_PROTOCOLS') && defined('CURLPROTO_HTTP')) {
            $options[CURLOPT_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS;
        }
        if ($body !== null) {
            $options[CURLOPT_POSTFIELDS] = $body;
        }
        curl_setopt_array($handle, $options);
        $result = curl_exec($handle);
        if ($result === false) {
            $error = curl_error($handle);
            throw new AppAuthException(0, 'network_error', 'The server could not be reached: ' . $error);
        }
        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        return new HttpResponse($status, $responseHeaders, (string) $result);
    }
}
