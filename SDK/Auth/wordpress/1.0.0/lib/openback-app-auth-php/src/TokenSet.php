<?php

declare(strict_types=1);

// Bundled copy of openback-app-auth-php 1.0.0 (MIT), namespace prefixed for this plugin.

namespace OpenBackAppAuthWp\Sdk;

/** The answer of the token endpoint (code exchange or refresh). Never log it. */
final class TokenSet
{
    /**
     * @param array<string, mixed>|null $idTokenClaims verified claims of the ID token (code exchange), null on refresh
     * @param array<string, mixed>|null $org the active organization (B2B pools)
     * @param array<string, mixed> $raw the whole answer
     */
    public function __construct(
        public readonly string $accessToken,
        public readonly string $tokenType,
        public readonly int $expiresIn,
        public readonly int $expiresAt,
        public readonly ?string $scope,
        public readonly ?string $refreshToken,
        public readonly ?int $refreshExpiresIn,
        public readonly ?string $idToken,
        public readonly ?array $idTokenClaims,
        public readonly ?array $org,
        public readonly array $raw,
    ) {
    }

    /**
     * @param array<string, mixed> $data
     * @param array<string, mixed>|null $idTokenClaims
     */
    public static function fromResponse(array $data, ?array $idTokenClaims = null, ?int $now = null): self
    {
        if (!is_string($data['access_token'] ?? null) || $data['access_token'] === '') {
            throw new AppAuthException(502, 'invalid_response', 'The token endpoint answered without an access token');
        }
        $expiresIn = (int) ($data['expires_in'] ?? 900);
        return new self(
            $data['access_token'],
            is_string($data['token_type'] ?? null) ? $data['token_type'] : 'Bearer',
            $expiresIn,
            ($now ?? time()) + $expiresIn,
            is_string($data['scope'] ?? null) ? $data['scope'] : null,
            is_string($data['refresh_token'] ?? null) ? $data['refresh_token'] : null,
            isset($data['refresh_expires_in']) ? (int) $data['refresh_expires_in'] : null,
            is_string($data['id_token'] ?? null) ? $data['id_token'] : null,
            $idTokenClaims,
            is_array($data['org'] ?? null) ? $data['org'] : null,
            $data,
        );
    }
}
