<?php

declare(strict_types=1);

// Bundled copy of openback-app-auth-php 1.0.0 (MIT), namespace prefixed for this extension.

namespace OpenBackAppAuthJoomla\Sdk\Storage;

\defined('_JEXEC') or die;

/**
 * Where the {@see \OpenBackAppAuthJoomla\Sdk\Client} keeps its session (a JSON string under `openback.auth.<clientId>`).
 * Implementations: {@see MemoryStorage} (default), {@see SessionStorage} (PHP session). For a file, a database or a
 * cache, implement these three methods; the value holds tokens: keep it private to the user it belongs to.
 */
interface Storage
{
    public function get(string $key): ?string;

    public function set(string $key, string $value): void;

    public function remove(string $key): void;
}
