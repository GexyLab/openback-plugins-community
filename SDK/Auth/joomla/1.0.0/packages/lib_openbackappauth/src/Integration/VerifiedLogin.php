<?php

/**
 * Proof, passed in the options of $app->login(), that the system plugin has just verified an OpenBack ID token for
 * this Joomla user. Only PHP code can create it (never a request), and it can be used once.
 *
 * @copyright  (C) 2026 GexyLab and the OpenBack contributors
 * @license    GPL-2.0-or-later
 */

declare(strict_types=1);

namespace OpenBackAppAuthJoomla\Integration;

\defined('_JEXEC') or die;

final class VerifiedLogin
{
    public const OPTION = 'openbackappauth';

    private bool $used = false;

    public function __construct(public readonly int $userId, public readonly string $username)
    {
    }

    /** True the first time only. */
    public function consume(): bool
    {
        if ($this->used) {
            return false;
        }
        $this->used = true;
        return true;
    }
}
