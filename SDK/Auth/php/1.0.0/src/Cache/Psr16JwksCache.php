<?php

declare(strict_types=1);

namespace OpenBack\AppAuth\Cache;

use Psr\SimpleCache\CacheInterface;

/** Any PSR-16 cache (Symfony, Laravel, Redis, Memcached adapters...). Needs psr/simple-cache. */
final class Psr16JwksCache implements JwksCache
{
    public function __construct(private readonly CacheInterface $cache)
    {
    }

    public function get(string $key): ?array
    {
        try {
            $value = $this->cache->get($key);
        } catch (\Throwable) {
            return null;                           // a cache failing must not break verification
        }
        return is_array($value) ? $value : null;
    }

    public function set(string $key, array $value, int $ttlSeconds): void
    {
        try {
            $this->cache->set($key, $value, max(1, $ttlSeconds));
        } catch (\Throwable) {
            // not cached: the next request fetches the keys again
        }
    }
}
