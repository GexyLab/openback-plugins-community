<?php

declare(strict_types=1);

// Bundled copy of openback-app-auth-php 1.0.0 (MIT), namespace prefixed for this extension.

namespace OpenBackAppAuthJoomla\Sdk\Storage;

\defined('_JEXEC') or die;

/** Keeps the session in this object only (a CLI script, a worker, tests). */
final class MemoryStorage implements Storage
{
    /** @var array<string, string> */
    private array $data = [];

    public function get(string $key): ?string
    {
        return $this->data[$key] ?? null;
    }

    public function set(string $key, string $value): void
    {
        $this->data[$key] = $value;
    }

    public function remove(string $key): void
    {
        unset($this->data[$key]);
    }
}
