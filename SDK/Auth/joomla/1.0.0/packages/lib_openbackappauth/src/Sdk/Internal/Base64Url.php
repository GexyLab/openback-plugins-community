<?php

declare(strict_types=1);

// Bundled copy of openback-app-auth-php 1.0.0 (MIT), namespace prefixed for this extension.

namespace OpenBackAppAuthJoomla\Sdk\Internal;

\defined('_JEXEC') or die;

/** @internal base64url without padding (RFC 4648 section 5), strict decoding. */
final class Base64Url
{
    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /** @throws \InvalidArgumentException on characters outside the alphabet or a bad length */
    public static function decode(string $text): string
    {
        if (!preg_match('/^[A-Za-z0-9_-]*$/', $text) || strlen($text) % 4 === 1) {
            throw new \InvalidArgumentException('invalid base64url');
        }
        $padded = strtr($text, '-_', '+/') . str_repeat('=', (4 - strlen($text) % 4) % 4);
        $out = base64_decode($padded, true);
        if ($out === false) {
            throw new \InvalidArgumentException('invalid base64url');
        }
        return $out;
    }

    /** A random URL-safe string from $bytes CSPRNG bytes. */
    public static function random(int $bytes = 32): string
    {
        return self::encode(random_bytes($bytes));
    }
}
