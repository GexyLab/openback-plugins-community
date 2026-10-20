<?php

declare(strict_types=1);

// Bundled copy of openback-app-auth-php 1.0.0 (MIT), namespace prefixed for this extension.

namespace OpenBackAppAuthJoomla\Sdk\Http;

\defined('_JEXEC') or die;

use OpenBackAppAuthJoomla\Sdk\AppAuthException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

/** A transport over any PSR-18 client (Guzzle, Symfony HttpClient's Psr18Client, ...) and PSR-17 factories. */
final class Psr18Transport implements HttpTransport
{
    public function __construct(
        private readonly ClientInterface $client,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly StreamFactoryInterface $streamFactory,
    ) {
    }

    public function send(string $method, string $url, array $headers = [], ?string $body = null): HttpResponse
    {
        $request = $this->requestFactory->createRequest(strtoupper($method), $url);
        foreach ($headers as $name => $value) {
            $request = $request->withHeader($name, $value);
        }
        if ($body !== null) {
            $request = $request->withBody($this->streamFactory->createStream($body));
        }
        try {
            $response = $this->client->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw new AppAuthException(0, 'network_error', 'The server could not be reached: ' . $e->getMessage(), null, $e);
        }
        $out = [];
        foreach ($response->getHeaders() as $name => $values) {
            $out[(string) $name] = implode(', ', $values);
        }
        return new HttpResponse($response->getStatusCode(), $out, (string) $response->getBody());
    }
}
