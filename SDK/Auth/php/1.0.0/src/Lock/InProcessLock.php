<?php

declare(strict_types=1);

namespace OpenBack\AppAuth\Lock;

/** No cross-process lock (the default): enough for one process, a PHP session (locked by PHP) or a CLI script. */
final class InProcessLock implements RefreshLock
{
    public function synchronized(string $name, callable $critical): mixed
    {
        return $critical();
    }
}
