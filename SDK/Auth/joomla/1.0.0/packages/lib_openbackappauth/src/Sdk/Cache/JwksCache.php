<?php

declare(strict_types=1);

// Bundled copy of openback-app-auth-php 1.0.0 (MIT), namespace prefixed for this extension.

namespace OpenBackAppAuthJoomla\Sdk\Cache;

\defined('_JEXEC') or die;

/**
 * Where {@see \OpenBackAppAuthJoomla\Sdk\TokenVerifier} keeps the pool's public keys between requests.
 * Implementations: {@see Psr16JwksCache} (any PSR-16 cache), {@see ApcuJwksCache}, {@see MemoryJwksCache}.
 */
interface JwksCache
{
    /** @return array<string, mixed>|null */
    public function get(string $key): ?array;

    /** @param array<string, mixed> $value */
    public function set(string $key, array $value, int $ttlSeconds): void;
}
