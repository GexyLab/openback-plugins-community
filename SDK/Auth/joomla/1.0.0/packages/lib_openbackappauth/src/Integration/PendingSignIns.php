<?php

/**
 * The sign-ins in progress of a browser (state, nonce, PKCE verifier, return address), kept server-side in the Joomla
 * session (pure list logic: unit-tested). At most 5 at a time (several tabs), 10 minutes each, found by `state` in
 * constant time and taken once.
 *
 * @copyright  (C) 2026 GexyLab and the OpenBack contributors
 * @license    GPL-2.0-or-later
 */

declare(strict_types=1);

namespace OpenBackAppAuthJoomla\Integration;

\defined('_JEXEC') or die;

final class PendingSignIns
{
    public const SESSION_KEY = 'openbackappauth.pending';
    public const TTL         = 600;
    public const MAX         = 5;

    /**
     * @param array<mixed>         $list        the stored list
     * @param array<string, mixed> $transaction must hold a non-empty `state`
     * @return list<array{expires: int, tx: array<string, mixed>}>
     */
    public static function add(array $list, array $transaction, int $now): array
    {
        if (!is_string($transaction['state'] ?? null) || $transaction['state'] === '') {
            throw new \InvalidArgumentException('transaction without state');
        }
        $list   = self::alive($list, $now);
        $list[] = ['expires' => $now + self::TTL, 'tx' => $transaction];
        return array_slice($list, -self::MAX);
    }

    /**
     * @param array<mixed> $list
     * @return array{0: array<string, mixed>|null, 1: list<array{expires: int, tx: array<string, mixed>}>} [the transaction or null, the list left]
     */
    public static function take(array $list, ?string $state, int $now): array
    {
        $found = null;
        $left  = [];
        foreach (self::alive($list, $now) as $entry) {
            $entryState = $entry['tx']['state'] ?? null;
            if ($found === null && $state !== null && $state !== '' && is_string($entryState) && hash_equals($entryState, $state)) {
                $found = $entry['tx'];
                continue;
            }
            $left[] = $entry;
        }
        return [$found, $left];
    }

    /**
     * @param array<mixed> $list
     * @return list<array{expires: int, tx: array<string, mixed>}>
     */
    private static function alive(array $list, int $now): array
    {
        return array_values(array_filter(
            $list,
            static fn ($e): bool => is_array($e) && (int) ($e['expires'] ?? 0) > $now && is_array($e['tx'] ?? null)
        ));
    }
}
