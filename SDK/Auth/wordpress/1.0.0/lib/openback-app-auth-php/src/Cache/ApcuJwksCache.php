<?php

declare(strict_types=1);

// Bundled copy of openback-app-auth-php 1.0.0 (MIT), namespace prefixed for this plugin.

namespace OpenBackAppAuthWp\Sdk\Cache;

/** APCu cache: shared by the requests of a PHP-FPM / mod_php server. Used by default when APCu is enabled. */
final class ApcuJwksCache implements JwksCache
{
    public static function available(): bool
    {
        return function_exists('apcu_enabled') && apcu_enabled();
    }

    public function get(string $key): ?array
    {
        $success = false;
        $value = apcu_fetch($key, $success);
        return $success && is_array($value) ? $value : null;
    }

    public function set(string $key, array $value, int $ttlSeconds): void
    {
        apcu_store($key, $value, max(1, $ttlSeconds));
    }
}
