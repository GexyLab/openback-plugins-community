<?php

declare(strict_types=1);

// Bundled copy of openback-app-auth-php 1.0.0 (MIT), namespace prefixed for this plugin.

namespace OpenBackAppAuthWp\Sdk\Http;

/** An HTTP answer: status, headers (names lower-cased) and body. */
final class HttpResponse
{
    /** @var array<string, string> */
    public readonly array $headers;

    /**
     * @param array<string, string|string[]> $headers
     */
    public function __construct(public readonly int $status, array $headers = [], public readonly string $body = '')
    {
        $normalized = [];
        foreach ($headers as $name => $value) {
            $normalized[strtolower((string) $name)] = is_array($value) ? implode(', ', $value) : (string) $value;
        }
        $this->headers = $normalized;
    }

    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }

    public function ok(): bool
    {
        return $this->status >= 200 && $this->status < 300;
    }

    /**
     * The body decoded as a JSON object or list; null when it is empty or not JSON.
     *
     * @return array<mixed>|null
     */
    public function json(): ?array
    {
        if ($this->body === '') {
            return null;
        }
        try {
            $data = json_decode($this->body, true, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
        return is_array($data) ? $data : null;
    }
}
