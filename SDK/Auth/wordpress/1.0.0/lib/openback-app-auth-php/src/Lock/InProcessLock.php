<?php

declare(strict_types=1);

// Bundled copy of openback-app-auth-php 1.0.0 (MIT), namespace prefixed for this plugin.

namespace OpenBackAppAuthWp\Sdk\Lock;

/** No cross-process lock (the default): enough for one process, a PHP session (locked by PHP) or a CLI script. */
final class InProcessLock implements RefreshLock
{
    public function synchronized(string $name, callable $critical): mixed
    {
        return $critical();
    }
}
