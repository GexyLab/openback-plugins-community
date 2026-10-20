<?php

declare(strict_types=1);

namespace OpenBack\AppAuth\Lock;

/** An exclusive flock() on a file per lock name, in $directory (default: the system's temporary directory). */
final class FileLock implements RefreshLock
{
    private readonly string $directory;

    public function __construct(?string $directory = null)
    {
        $this->directory = rtrim($directory ?? sys_get_temp_dir(), '/\\');
    }

    public function synchronized(string $name, callable $critical): mixed
    {
        $path = $this->directory . DIRECTORY_SEPARATOR . 'openback-app-auth-' . hash('sha256', $name) . '.lock';
        $handle = fopen($path, 'c');
        if ($handle === false) {
            throw new \RuntimeException('FileLock: cannot open the lock file');
        }
        try {
            if (!flock($handle, LOCK_EX)) {
                throw new \RuntimeException('FileLock: cannot lock');
            }
            return $critical();
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }
}
