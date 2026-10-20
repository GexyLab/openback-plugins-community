<?php

declare(strict_types=1);

namespace OpenBack\AppAuth\Storage;

/**
 * Keeps the session in the PHP session ($_SESSION), server-side, per browser. Starts the session when none is active
 * (call it before any output). The default file session handler locks the session for the whole request, which also
 * serializes the refreshes of the same browser session.
 */
final class SessionStorage implements Storage
{
    public function __construct(private readonly string $namespace = 'openback_app_auth')
    {
    }

    public function get(string $key): ?string
    {
        $this->start();
        $value = $_SESSION[$this->namespace][$key] ?? null;
        return is_string($value) ? $value : null;
    }

    public function set(string $key, string $value): void
    {
        $this->start();
        $_SESSION[$this->namespace][$key] = $value;
    }

    public function remove(string $key): void
    {
        $this->start();
        unset($_SESSION[$this->namespace][$key]);
    }

    private function start(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }
        if (session_status() === PHP_SESSION_DISABLED) {
            throw new \LogicException('SessionStorage: PHP sessions are disabled');
        }
        if (headers_sent()) {
            throw new \LogicException('SessionStorage: start the session before any output');
        }
        session_start();
    }
}
