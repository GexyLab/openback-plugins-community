<?php

/**
 * Links OpenBack users to Joomla users and creates Joomla users.
 *
 * A link is three rows of #__user_profiles: `openback.sub` (the pool user id `usr_...`), `openback.iss` (the pool's
 * issuer) and `openback.pool` (the pool id). A link matches when the sub is equal and either the issuer or the pool id
 * is (the pool keeps its id if its address changes).
 *
 * @copyright  (C) 2026 GexyLab and the OpenBack contributors
 * @license    GPL-2.0-or-later
 */

declare(strict_types=1);

namespace OpenBackAppAuthJoomla\Integration;

\defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\User\User;
use Joomla\CMS\User\UserFactoryInterface;
use Joomla\CMS\User\UserHelper;
use Joomla\Database\DatabaseInterface;

final class UserLinker
{
    public const KEY_SUB  = 'openback.sub';
    public const KEY_ISS  = 'openback.iss';
    public const KEY_POOL = 'openback.pool';

    private readonly DatabaseInterface $db;

    public function __construct(private readonly Settings $settings, ?DatabaseInterface $db = null)
    {
        $this->db = $db ?? Factory::getContainer()->get(DatabaseInterface::class);
    }

    /** The Joomla user linked to this pool user, if any. */
    public function findLinked(string $sub, ?string $pool = null): ?User
    {
        $db    = $this->db;
        $query = $db->getQuery(true)
            ->select($db->quoteName('user_id'))
            ->from($db->quoteName('#__user_profiles'))
            ->where($db->quoteName('profile_key') . ' = ' . $db->quote(self::KEY_SUB))
            ->where($db->quoteName('profile_value') . ' = ' . $db->quote($sub));
        $ids = $db->setQuery($query, 0, 5)->loadColumn();
        foreach ($ids as $id) {
            $values = $this->profile((int) $id);
            if (($values[self::KEY_ISS] ?? '') === $this->settings->issuer()
                || ($pool !== null && $pool !== '' && ($values[self::KEY_POOL] ?? '') === $pool)) {
                $user = $this->userById((int) $id);
                if ($user !== null) {
                    return $user;
                }
            }
        }
        return null;
    }

    public function linkedSub(int $userId): ?string
    {
        $sub = $this->profile($userId)[self::KEY_SUB] ?? '';
        return $sub !== '' ? $sub : null;
    }

    /** @param array<string, mixed> $claims verified ID token claims */
    public function link(int $userId, array $claims): void
    {
        $this->unlink($userId);
        $rows = [
            self::KEY_SUB  => (string) $claims['sub'],
            self::KEY_ISS  => $this->settings->issuer(),
            self::KEY_POOL => is_string($claims['pool'] ?? null) ? $claims['pool'] : '',
        ];
        $order = 1;
        foreach ($rows as $key => $value) {
            $row = (object) ['user_id' => $userId, 'profile_key' => $key, 'profile_value' => $value, 'ordering' => $order++];
            $this->db->insertObject('#__user_profiles', $row);
        }
    }

    public function unlink(int $userId): void
    {
        $db    = $this->db;
        $query = $db->getQuery(true)
            ->delete($db->quoteName('#__user_profiles'))
            ->where($db->quoteName('user_id') . ' = ' . (int) $userId)
            ->where($db->quoteName('profile_key') . ' IN (' . implode(',', array_map([$db, 'quote'], [self::KEY_SUB, self::KEY_ISS, self::KEY_POOL])) . ')');
        $db->setQuery($query)->execute();
    }

    /** Super Users are never linked by email automatically, nor have their groups changed. */
    public static function isProtected(User $user): bool
    {
        return (bool) $user->authorise('core.admin');
    }

    /**
     * The Joomla user for a verified ID token: linked, linked now by email, or created — per the settings.
     *
     * @param array<string, mixed> $claims
     * @return User|string the user, or an error code
     */
    public function resolve(array $claims): User|string
    {
        $sub      = (string) $claims['sub'];
        $pool     = is_string($claims['pool'] ?? null) ? $claims['pool'] : null;
        $email    = is_string($claims['email'] ?? null) ? trim($claims['email']) : '';
        $verified = ($claims['email_verified'] ?? false) === true;
        $roles    = is_array($claims['roles'] ?? null) ? array_values(array_filter($claims['roles'], 'is_string')) : [];

        $user = $this->findLinked($sub, $pool);
        if ($user !== null) {
            if ($this->settings->syncGroups()) {
                $this->syncGroups($user, $roles);
            }
            return $user;
        }

        $existing = $email !== '' ? $this->userByEmail($email) : null;
        if ($existing !== null) {
            if (!$this->settings->linkByEmail()) {
                return 'email_exists';
            }
            if (!$verified) {
                return 'email_not_verified';
            }
            if (self::isProtected($existing)) {
                return 'admin_link_refused';
            }
            if ($this->linkedSub((int) $existing->id) !== null) {
                return 'already_linked';
            }
            $this->link((int) $existing->id, $claims);
            if ($this->settings->syncGroups()) {
                $this->syncGroups($existing, $roles);
            }
            return $existing;
        }

        if (!$this->settings->autoCreate()) {
            return 'no_account';
        }
        if ($email === '') {
            return 'no_email';
        }
        if (!$verified && $this->settings->requireVerifiedEmail()) {
            return 'email_not_verified';
        }
        return $this->create($claims, $email, $roles);
    }

    /**
     * @param array<string, mixed> $claims
     * @param string[]             $roles
     */
    private function create(array $claims, string $email, array $roles): User|string
    {
        $name     = is_string($claims['name'] ?? null) && trim($claims['name']) !== '' ? trim(strip_tags($claims['name'])) : (string) strstr($email, '@', true);
        $password = UserHelper::genRandomPassword(32);
        $user     = new User();
        $data     = [
            'name'      => mb_substr($name, 0, 255),
            'username'  => $this->uniqueUsername((string) strstr($email, '@', true), (string) $claims['sub']),
            'email'     => $email,
            'password'  => $password,
            'password2' => $password,
            'groups'    => GroupMapper::resolve($this->settings->groupRules(), $roles, $this->settings->defaultGroup()),
            'block'     => 0,
        ];
        if (!$user->bind($data) || !$user->save()) {
            return 'registration_failed';
        }
        $this->link((int) $user->id, $claims);
        return $this->userById((int) $user->id) ?? $user;
    }

    /** @param string[] $roles */
    public function syncGroups(User $user, array $roles): void
    {
        if (self::isProtected($user)) {
            return;
        }
        $groups = GroupMapper::sync($this->settings->groupRules(), array_map('intval', array_values($user->groups)), $roles, $this->settings->defaultGroup());
        $current = array_map('intval', array_values($user->groups));
        sort($groups);
        sort($current);
        if ($groups !== $current) {
            UserHelper::setUserGroups((int) $user->id, $groups);
        }
    }

    private function uniqueUsername(string $wanted, string $sub): string
    {
        $base = strtolower((string) preg_replace('/[^A-Za-z0-9_.\-]/', '', $wanted));
        $base = substr($base, 0, 50);
        if (strlen($base) < 2) {
            $base = 'openback_' . substr(hash('sha256', $sub), 0, 10);
        }
        $name = $base;
        for ($i = 2; UserHelper::getUserId($name) > 0; $i++) {
            $name = $i <= 50 ? $base . $i : 'openback_' . substr(hash('sha256', $sub . random_int(0, PHP_INT_MAX)), 0, 12);
        }
        return $name;
    }

    private function userById(int $id): ?User
    {
        $user = Factory::getContainer()->get(UserFactoryInterface::class)->loadUserById($id);
        return $user->id ? $user : null;
    }

    private function userByEmail(string $email): ?User
    {
        $db    = $this->db;
        $query = $db->getQuery(true)
            ->select($db->quoteName('id'))
            ->from($db->quoteName('#__users'))
            ->where('LOWER(' . $db->quoteName('email') . ') = ' . $db->quote(strtolower($email)));
        $id = (int) $db->setQuery($query, 0, 1)->loadResult();
        return $id > 0 ? $this->userById($id) : null;
    }

    /** @return array<string, string> */
    private function profile(int $userId): array
    {
        $db    = $this->db;
        $query = $db->getQuery(true)
            ->select([$db->quoteName('profile_key'), $db->quoteName('profile_value')])
            ->from($db->quoteName('#__user_profiles'))
            ->where($db->quoteName('user_id') . ' = ' . (int) $userId)
            ->where($db->quoteName('profile_key') . ' LIKE ' . $db->quote('openback.%'));
        $out = [];
        foreach ($db->setQuery($query)->loadObjectList() as $row) {
            $out[(string) $row->profile_key] = (string) $row->profile_value;
        }
        return $out;
    }
}
