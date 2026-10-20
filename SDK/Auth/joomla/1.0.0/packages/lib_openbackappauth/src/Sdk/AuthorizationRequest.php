<?php

declare(strict_types=1);

// Bundled copy of openback-app-auth-php 1.0.0 (MIT), namespace prefixed for this extension.

namespace OpenBackAppAuthJoomla\Sdk;

\defined('_JEXEC') or die;

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
