<?php

declare(strict_types=1);

namespace OpenBack\AppAuth\Http;

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
                throw new \InvalidArgumentException('option "transport" must implement OpenBack\\AppAuth\\Http\\HttpTransport');
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
