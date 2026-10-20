<?php

declare(strict_types=1);

// Bundled copy of openback-app-auth-php 1.0.0 (MIT), namespace prefixed for this extension.

namespace OpenBackAppAuthJoomla\Sdk\Http;

\defined('_JEXEC') or die;

/** Picks the transport from the SDK's options. */
final class Transport
{
    /**
     * `transport` (an {@see HttpTransport}), else `httpClient` (PSR-18) with `requestFactory` and `streamFactory`
     * (PSR-17; one object implementing both is fine), else the built-in {@see CurlTransport}.
     *
     * @param array<string, mixed> $options
     */
    public static function fromOptions(array $options): HttpTransport
    {
        if (isset($options['transport'])) {
            if (!$options['transport'] instanceof HttpTransport) {
                throw new \InvalidArgumentException('option "transport" must implement OpenBackAppAuthJoomla\\Sdk\\Http\\HttpTransport');
            }
            return $options['transport'];
        }
        if (isset($options['httpClient'])) {
            $requestFactory = $options['requestFactory'] ?? null;
            $streamFactory = $options['streamFactory'] ?? $requestFactory;
            if ($requestFactory === null || $streamFactory === null) {
                throw new \InvalidArgumentException('option "httpClient" needs "requestFactory" and "streamFactory" (PSR-17)');
            }
            return new Psr18Transport($options['httpClient'], $requestFactory, $streamFactory);
        }
        return new CurlTransport();
    }
}
