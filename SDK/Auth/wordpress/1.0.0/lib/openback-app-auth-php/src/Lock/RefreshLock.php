<?php

declare(strict_types=1);

// Bundled copy of openback-app-auth-php 1.0.0 (MIT), namespace prefixed for this plugin.

namespace OpenBackAppAuthWp\Sdk\Lock;

/**
 * Serializes the refreshes of one session: refresh tokens ROTATE, and a refresh token presented twice revokes the
 * whole session. Within one PHP process the Client is already single-flight; across processes sharing a storage
 * (several requests of the same user, workers) use {@see FileLock} or your own (Redis, database advisory lock).
 */
interface RefreshLock
{
    /**
     * Runs $critical while holding the lock named $name and returns its result.
     *
     * @template T
     * @param callable(): T $critical
     * @return T
     */
    public function synchronized(string $name, callable $critical): mixed;
}
