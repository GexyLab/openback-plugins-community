<?php

declare(strict_types=1);

// Bundled copy of openback-app-auth-php 1.0.0 (MIT), namespace prefixed for this extension.

namespace OpenBackAppAuthJoomla\Sdk;

\defined('_JEXEC') or die;

use OpenBackAppAuthJoomla\Sdk\Internal\Base64Url;

/**
 * What a sign-in through the hosted page must remember until its callback: state, nonce, PKCE verifier, redirect
 * address. Keep it SERVER-SIDE (the PHP session, a cache entry keyed by an HttpOnly cookie...), never in a plain cookie
 * or in the page. {@see toArray()} / {@see fromArray()} serialize it.
 */
final class AuthTransaction
{
    public function __construct(
        public readonly string $state,
        public readonly string $nonce,
        public readonly string $codeVerifier,
        public readonly string $redirectUri,
        public readonly int $createdAt,
    ) {
    }

    /** A new transaction with CSPRNG state, nonce and PKCE verifier (43 characters from 32 random bytes). */
    public static function create(string $redirectUri): self
    {
        return new self(Base64Url::random(24), Base64Url::random(24), Base64Url::random(32), $redirectUri, time());
    }

    /** The PKCE S256 challenge of the verifier. */
    public function codeChallenge(): string
    {
        return Base64Url::encode(hash('sha256', $this->codeVerifier, true));
    }

    /** @return array{state: string, nonce: string, code_verifier: string, redirect_uri: string, created_at: int} */
    public function toArray(): array
    {
        return [
            'state' => $this->state,
            'nonce' => $this->nonce,
            'code_verifier' => $this->codeVerifier,
            'redirect_uri' => $this->redirectUri,
            'created_at' => $this->createdAt,
        ];
    }

    /**
     * @param array<string, mixed> $data
     * @throws AppAuthException 400 `invalid_state` when the data is incomplete
     */
    public static function fromArray(array $data): self
    {
        foreach (['state', 'nonce', 'code_verifier', 'redirect_uri'] as $field) {
            if (!is_string($data[$field] ?? null) || $data[$field] === '') {
                throw new AppAuthException(400, 'invalid_state', 'No sign-in in progress');
            }
        }
        return new self($data['state'], $data['nonce'], $data['code_verifier'], $data['redirect_uri'], (int) ($data['created_at'] ?? 0));
    }
}
