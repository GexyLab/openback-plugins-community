<?php

declare(strict_types=1);

namespace OpenBack\AppAuth;

/** The answer of a sign-up or sign-in: the Client keeps the tokens only when the status is Ok. */
final class Outcome
{
    /**
     * @param array<string, mixed>|null $user the PoolUser (status Ok)
     * @param array<string, mixed>|null $org the active organization (B2B pools)
     * @param array<string, mixed> $raw the whole answer (tokens included: never log it)
     */
    public function __construct(
        public readonly OutcomeStatus $status,
        public readonly string $rawStatus,
        public readonly ?array $user,
        public readonly ?array $org,
        public readonly ?string $mfaToken,
        public readonly ?string $changeToken,
        public readonly array $raw,
    ) {
    }

    /** @param array<string, mixed> $data */
    public static function fromResponse(array $data): self
    {
        $raw = is_string($data['status'] ?? null) ? $data['status'] : 'unknown';
        return new self(
            OutcomeStatus::tryFrom($raw) ?? OutcomeStatus::Unknown,
            $raw,
            is_array($data['user'] ?? null) ? $data['user'] : null,
            is_array($data['org'] ?? null) ? $data['org'] : null,
            is_string($data['mfa_token'] ?? null) ? $data['mfa_token'] : null,
            is_string($data['change_token'] ?? null) ? $data['change_token'] : null,
            $data,
        );
    }

    public function isOk(): bool
    {
        return $this->status === OutcomeStatus::Ok;
    }
}
