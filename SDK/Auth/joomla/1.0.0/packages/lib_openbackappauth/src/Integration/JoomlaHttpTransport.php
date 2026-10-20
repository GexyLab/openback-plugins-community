<?php

/**
 * The SDK's HTTP layer on Joomla's HTTP package (the site's proxy settings and transports apply).
 *
 * @copyright  (C) 2026 GexyLab and the OpenBack contributors
 * @license    GPL-2.0-or-later
 */

declare(strict_types=1);

namespace OpenBackAppAuthJoomla\Integration;

\defined('_JEXEC') or die;

use Joomla\CMS\Http\HttpFactory;
use Joomla\Registry\Registry;
use OpenBackAppAuthJoomla\Sdk\AppAuthException;
use OpenBackAppAuthJoomla\Sdk\Http\HttpResponse;
use OpenBackAppAuthJoomla\Sdk\Http\HttpTransport;

final class JoomlaHttpTransport implements HttpTransport
{
    private const TIMEOUT = 15;

    public function send(string $method, string $url, array $headers = [], ?string $body = null): HttpResponse
    {
        if (!preg_match('#^https?://#i', $url)) {
            throw new AppAuthException(0, 'invalid_url', 'Only http(s) addresses are allowed');
        }
        $headers['User-Agent'] = 'openback-app-auth-joomla/1.0.0';
        try {
            $http = HttpFactory::getHttp(new Registry(['follow_location' => false]));
            $response = match (strtoupper($method)) {
                'GET'    => $http->get($url, $headers, self::TIMEOUT),
                'POST'   => $http->post($url, $body ?? '', $headers, self::TIMEOUT),
                'PUT'    => $http->put($url, $body ?? '', $headers, self::TIMEOUT),
                'PATCH'  => $http->patch($url, $body ?? '', $headers, self::TIMEOUT),
                'DELETE' => $http->delete($url, $headers, self::TIMEOUT, $body),
                default  => throw new AppAuthException(0, 'invalid_method', 'Unsupported HTTP method'),
            };
        } catch (AppAuthException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new AppAuthException(0, 'network_error', 'The server could not be reached: ' . $e->getMessage(), null, $e);
        }
        $out = [];
        foreach ($response->getHeaders() as $name => $values) {
            $out[(string) $name] = implode(', ', (array) $values);
        }
        return new HttpResponse((int) $response->getStatusCode(), $out, (string) $response->getBody());
    }
}
