<?php

declare(strict_types=1);

namespace OpenBack\AppAuth\Cache;

/**
 * Where {@see \OpenBack\AppAuth\TokenVerifier} keeps the pool's public keys between requests.
 * Implementations: {@see Psr16JwksCache} (any PSR-16 cache), {@see ApcuJwksCache}, {@see MemoryJwksCache}.
 */
interface JwksCache
{
    /** @return array<string, mixed>|null */
    public function get(string $key): ?array;

    /** @param array<string, mixed> $value */
    public function set(string $key, array $value, int $ttlSeconds): void;
}
