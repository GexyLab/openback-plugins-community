<?php

declare(strict_types=1);

namespace OpenBack\AppAuth\Tests\Support;

use OpenBack\AppAuth\AppAuthException;
use OpenBack\AppAuth\Http\HttpResponse;
use OpenBack\AppAuth\Http\HttpTransport;

/** An HTTP layer that never touches the network: routes "METHOD url-without-query" to handlers, records requests. */
final class FakeTransport implements HttpTransport
{
    /** @var array<string, callable|list<callable>> */
    private array $routes = [];
    /** @var list<array{method: string, url: string, headers: array<string, string>, body: ?string}> */
    public array $requests = [];

    /** @param callable(string $method, string $url, array $headers, ?string $body): HttpResponse $handler */
    public function on(string $method, string $url, callable $handler): self
    {
        $this->routes[strtoupper($method) . ' ' . $url] = $handler;
        return $this;
    }

    /** @param array<mixed>|null $body */
    public function json(string $method, string $url, int $status, ?array $body): self
    {
        return $this->on($method, $url, static fn () => new HttpResponse($status, ['Content-Type' => 'application/json'],
            $body === null ? '' : (string) json_encode($body)));
    }

    public function fail(string $method, string $url): self
    {
        return $this->on($method, $url, static function () {
            throw new AppAuthException(0, 'network_error', 'The server could not be reached: test');
        });
    }

    public function send(string $method, string $url, array $headers = [], ?string $body = null): HttpResponse
    {
        $this->requests[] = ['method' => strtoupper($method), 'url' => $url, 'headers' => $headers, 'body' => $body];
        $path = strtok($url, '?');
        $handler = $this->routes[strtoupper($method) . ' ' . $url] ?? $this->routes[strtoupper($method) . ' ' . $path] ?? null;
        if ($handler === null) {
            return new HttpResponse(404, [], '{"detail":"no route in FakeTransport"}');
        }
        return $handler($method, $url, $headers, $body);
    }

    /** @return list<array{method: string, url: string, headers: array<string, string>, body: ?string}> */
    public function to(string $method, string $urlPrefix): array
    {
        return array_values(array_filter($this->requests,
            static fn ($r) => $r['method'] === strtoupper($method) && str_starts_with($r['url'], $urlPrefix)));
    }

    public function last(): array
    {
        return $this->requests[count($this->requests) - 1];
    }
}
