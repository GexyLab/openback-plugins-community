<?php

declare(strict_types=1);

// Bundled copy of openback-app-auth-php 1.0.0 (MIT), namespace prefixed for this plugin.

namespace OpenBackAppAuthWp\Sdk;

/** The user behind a verified access token (see {@see TokenVerifier::verify()}). */
final class AppUser
{
    /**
     * @param string[] $roles
     * @param string[] $permissions
     * @param array<string, mixed> $attributes
     * @param string[] $amr
     * @param array<string, mixed> $claims the raw claims of the token
     */
    public function __construct(
        public readonly string $id,
        public readonly ?string $poolId,
        public readonly string $clientId,
        public readonly ?string $email,
        public readonly bool $emailVerified,
        public readonly bool $anonymous,
        public readonly ?string $orgId,
        public readonly array $roles,
        public readonly array $permissions,
        public readonly array $attributes,
        public readonly ?string $sessionId,
        public readonly array $amr,
        public readonly array $claims,
    ) {
    }

    /** @param array<string, mixed> $claims verified claims of an access token */
    public static function fromClaims(array $claims, string $clientId): self
    {
        $strings = static fn ($v): array => is_array($v) ? array_values(array_filter($v, 'is_string')) : [];
        $string = static fn ($v): ?string => is_string($v) && $v !== '' ? $v : null;
        return new self(
            (string) $claims['sub'],
            $string($claims['pool'] ?? null),
            $clientId,
            $string($claims['email'] ?? null),
            ($claims['email_verified'] ?? false) === true,
            ($claims['anon'] ?? false) === true,
            $string($claims['org_id'] ?? null),
            $strings($claims['roles'] ?? []),
            $strings($claims['permissions'] ?? []),
            is_array($claims['attr'] ?? null) ? $claims['attr'] : [],
            $string($claims['sid'] ?? null),
            $strings($claims['amr'] ?? []),
            $claims,
        );
    }

    public function hasRole(string $role): bool
    {
        return in_array($role, $this->roles, true);
    }

    /** True when the permissions contain $permission or "*" (all). */
    public function hasPermission(string $permission): bool
    {
        return in_array('*', $this->permissions, true) || in_array($permission, $this->permissions, true);
    }
}
