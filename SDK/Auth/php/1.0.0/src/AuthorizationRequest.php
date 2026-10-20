<?php

declare(strict_types=1);

namespace OpenBack\AppAuth;

/** The address of the hosted sign-in page to redirect the browser to, and the transaction to keep for the callback. */
final class AuthorizationRequest
{
    public function __construct(public readonly string $url, public readonly AuthTransaction $transaction)
    {
    }

    public function state(): string
    {
        return $this->transaction->state;
    }

    public function nonce(): string
    {
        return $this->transaction->nonce;
    }

    public function codeVerifier(): string
    {
        return $this->transaction->codeVerifier;
    }

    public function redirectUri(): string
    {
        return $this->transaction->redirectUri;
    }
}
