<?php

declare(strict_types=1);

namespace OpenBack\AppAuth\Internal;

/** @internal Splitting and decoding a compact JWS (no verification here: see TokenVerifier). */
final class Jwt
{
    public const MAX_LENGTH = 16384;

    /**
     * @param array<string, mixed> $header
     * @param array<string, mixed> $claims
     */
    private function __construct(
        public readonly array $header,
        public readonly array $claims,
        public readonly string $signingInput,
        public readonly string $signature,
    ) {
    }

    /** @throws \InvalidArgumentException when the token is not a well-formed compact JWS with JSON objects */
    public static function parse(string $token): self
    {
        if ($token === '' || strlen($token) > self::MAX_LENGTH) {
            throw new \InvalidArgumentException('token missing or too long');
        }
        $parts = explode('.', $token);
        if (count($parts) !== 3 || $parts[0] === '' || $parts[1] === '') {
            throw new \InvalidArgumentException('not a compact JWS');
        }
        $header = self::object(Base64Url::decode($parts[0]));
        $claims = self::object(Base64Url::decode($parts[1]));
        return new self($header, $claims, $parts[0] . '.' . $parts[1], Base64Url::decode($parts[2]));
    }

    /**
     * The claims of a token WITHOUT checking it (for display: the client's own access token). Null when unreadable.
     *
     * @return array<string, mixed>|null
     */
    public static function unverifiedClaims(?string $token): ?array
    {
        if ($token === null || $token === '') {
            return null;
        }
        try {
            return self::parse($token)->claims;
        } catch (\InvalidArgumentException) {
            return null;
        }
    }

    /** @return array<string, mixed> */
    private static function object(string $json): array
    {
        try {
            $data = json_decode($json, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new \InvalidArgumentException('invalid JSON in token');
        }
        if (!is_array($data) || ($data !== [] && array_is_list($data)) || !str_starts_with(ltrim($json), '{')) {
            throw new \InvalidArgumentException('token part is not a JSON object');
        }
        return $data;
    }
}
