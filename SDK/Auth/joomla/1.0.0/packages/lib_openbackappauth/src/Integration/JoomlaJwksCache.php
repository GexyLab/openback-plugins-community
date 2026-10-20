<?php

/**
 * The pool's public keys (JWKS) in Joomla's cache (group "openbackappauth", forced on even when the site's cache is off).
 *
 * @copyright  (C) 2026 GexyLab and the OpenBack contributors
 * @license    GPL-2.0-or-later
 */

declare(strict_types=1);

namespace OpenBackAppAuthJoomla\Integration;

\defined('_JEXEC') or die;

use Joomla\CMS\Cache\CacheControllerFactoryInterface;
use Joomla\CMS\Factory;
use OpenBackAppAuthJoomla\Sdk\Cache\JwksCache;
use OpenBackAppAuthJoomla\Sdk\Cache\MemoryJwksCache;

final class JoomlaJwksCache implements JwksCache
{
    private ?object $controller = null;
    private MemoryJwksCache $fallback;

    public function __construct()
    {
        $this->fallback = new MemoryJwksCache();
        try {
            $this->controller = Factory::getContainer()->get(CacheControllerFactoryInterface::class)->createCacheController(
                'output',
                ['defaultgroup' => 'openbackappauth', 'caching' => true, 'lifetime' => 10]
            );
        } catch (\Throwable) {
            $this->controller = null;
        }
    }

    public function get(string $key): ?array
    {
        if ($this->controller !== null) {
            try {
                $data = $this->controller->get($key);
                $decoded = is_string($data) ? json_decode($data, true) : null;
                if (is_array($decoded)) {
                    return $decoded;
                }
            } catch (\Throwable) {
                // fall back to the in-process cache
            }
        }
        return $this->fallback->get($key);
    }

    public function set(string $key, array $value, int $ttlSeconds): void
    {
        $this->fallback->set($key, $value, $ttlSeconds);
        if ($this->controller !== null) {
            try {
                $this->controller->store((string) json_encode($value), $key);
            } catch (\Throwable) {
                // not cached: fetched again next time
            }
        }
    }
}
