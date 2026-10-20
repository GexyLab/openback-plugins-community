<?php

declare(strict_types=1);

// Bundled copy of openback-app-auth-php 1.0.0 (MIT), namespace prefixed for this extension.

namespace OpenBackAppAuthJoomla\Sdk;

\defined('_JEXEC') or die;

/**
 * Every error of the SDK: an error answer of the pool, a refused token, a network failure.
 *
 * - {@see $status}: the HTTP status of the answer (0 for a network error or a local check);
 * - {@see $errorCode}: the pool's error code (`invalid_credentials`, `token_expired`, `invalid_grant`...), else `http_<status>`;
 *   it is not called `code` because PHP's Exception::getCode() is an integer (it holds the status here);
 * - {@see $detail}: the decoded `detail` of the answer (an array with `problems` for `weak_password`, a string, a list...).
 */
class AppAuthException extends \RuntimeException
{
    public readonly int $status;
    public readonly string $errorCode;
    public readonly mixed $detail;

    public function __construct(int $status, string $errorCode, string $message = '', mixed $detail = null, ?\Throwable $previous = null)
    {
        parent::__construct($message !== '' ? $message : $errorCode, $status, $previous);
        $this->status = $status;
        $this->errorCode = $errorCode;
        $this->detail = $detail;
    }

    public function getStatus(): int
    {
        return $this->status;
    }

    public function getErrorCode(): string
    {
        return $this->errorCode;
    }

    public function getDetail(): mixed
    {
        return $this->detail;
    }

    /** True when the error means the local session is dead (a refused token or refresh token). */
    public function endsSession(): bool
    {
        return $this->errorCode === 'invalid_refresh_token'
            || ($this->status === 401 && str_starts_with($this->errorCode, 'token_'));
    }

    /**
     * An error answer of the JSON API: `{"detail": {"code", "message"}}`, `{"detail": "text"}`, `{"detail": [...]}`
     * (validation), or an OAuth error `{"error", "error_description"}`.
     *
     * @param array<mixed>|null $data
     */
    public static function fromResponse(int $status, ?array $data, string $fallbackMessage = ''): self
    {
        $detail = $data['detail'] ?? null;
        $code = null;
        $message = null;
        if (is_array($detail) && !array_is_list($detail)) {
            $code = isset($detail['code']) && is_string($detail['code']) ? $detail['code'] : null;
            $message = isset($detail['message']) && is_string($detail['message']) ? $detail['message'] : null;
        } elseif (is_string($detail)) {
            $message = $detail;
        } elseif (is_array($detail) && $detail !== [] && is_array($detail[0] ?? null) && isset($detail[0]['msg']) && is_string($detail[0]['msg'])) {
            $message = $detail[0]['msg'];
        }
        if ($code === null && isset($data['error']) && is_string($data['error'])) {
            $code = $data['error'];
            $message = isset($data['error_description']) && is_string($data['error_description']) ? $data['error_description'] : $message;
            $detail = $detail ?? $data;
        }
        $code = $code ?? ('http_' . $status);
        return new self($status, $code, $message ?? ($fallbackMessage !== '' ? $fallbackMessage : $code), $detail);
    }
}
