<?php

/**
 * OpenBack role -> Joomla user group mapping (pure logic: unit-tested without Joomla).
 *
 * The rules come from the system plugin's repeatable "Group mapping" field: a list of {role, group}. A user gets the
 * groups of EVERY rule whose OpenBack role they have; with none, the default group. When the groups are synchronized
 * at sign-in, only the groups named in the rules are managed: other groups of the user are kept.
 *
 * @copyright  (C) 2026 GexyLab and the OpenBack contributors
 * @license    GPL-2.0-or-later
 */

declare(strict_types=1);

namespace OpenBackAppAuthJoomla\Integration;

\defined('_JEXEC') or die;

final class GroupMapper
{
    /**
     * The rules from the field's stored value (object or array of {role, group}).
     *
     * @return list<array{0: string, 1: int}>
     */
    public static function rules(mixed $value): array
    {
        if (is_string($value)) {
            $value = json_decode($value, true);
        }
        $rules = [];
        foreach ((array) $value as $row) {
            $row   = (array) $row;
            $role  = trim((string) ($row['role'] ?? ''));
            $group = (int) ($row['group'] ?? 0);
            if ($role !== '' && $group > 0) {
                $rules[] = [$role, $group];
            }
        }
        return $rules;
    }

    /**
     * The groups for a user with these OpenBack roles (never empty).
     *
     * @param list<array{0: string, 1: int}> $rules
     * @param string[]                       $roles
     * @return list<int>
     */
    public static function resolve(array $rules, array $roles, int $defaultGroup): array
    {
        $groups = [];
        foreach ($rules as [$role, $group]) {
            if (in_array($role, $roles, true) && !in_array($group, $groups, true)) {
                $groups[] = $group;
            }
        }
        return $groups !== [] ? $groups : [$defaultGroup];
    }

    /**
     * The user's groups after a synchronization: groups named in the rules follow the roles, the others stay.
     *
     * @param list<array{0: string, 1: int}> $rules
     * @param int[]                          $current the user's groups now
     * @param string[]                       $roles
     * @return list<int>
     */
    public static function sync(array $rules, array $current, array $roles, int $defaultGroup): array
    {
        $managed = array_map(static fn (array $rule): int => $rule[1], $rules);
        $kept    = array_values(array_filter(array_map('intval', $current), static fn (int $g): bool => !in_array($g, $managed, true)));
        $matched = [];
        foreach ($rules as [$role, $group]) {
            if (in_array($role, $roles, true)) {
                $matched[] = $group;
            }
        }
        $groups = array_values(array_unique(array_merge($kept, $matched)));
        return $groups !== [] ? $groups : [$defaultGroup];
    }
}
