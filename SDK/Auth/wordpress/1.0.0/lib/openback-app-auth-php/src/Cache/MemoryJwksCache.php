<?php

declare(strict_types=1);

// Bundled copy of openback-app-auth-php 1.0.0 (MIT), namespace prefixed for this plugin.

namespace OpenBackAppAuthWp\Sdk\Cache;

/** In-process cache, shared by every verifier of the process (long-running workers keep it; PHP-FPM requests do not). */
final class MemoryJwksCache implements JwksCache
{
    /** @var array<string, array{0: int, 1: array<string, mixed>}> */
    private static array $entries = [];

    public function get(string $key): ?array
    {
        $entry = self::$entries[$key] ?? null;
        if ($entry === null) {
            return null;
        }
        if ($entry[0] <= time()) {
            unset(self::$entries[$key]);
            return null;
        }
        return $entry[1];
    }

    public function set(string $key, array $value, int $ttlSeconds): void
    {
        self::$entries[$key] = [time() + max(1, $ttlSeconds), $value];
    }

    /** Empties the cache (tests). */
    public static function clear(): void
    {
        self::$entries = [];
    }
}
