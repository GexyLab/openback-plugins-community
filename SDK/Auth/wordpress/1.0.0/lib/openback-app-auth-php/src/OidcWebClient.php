<?php

declare(strict_types=1);

// Bundled copy of openback-app-auth-php 1.0.0 (MIT), namespace prefixed for this plugin.

namespace OpenBackAppAuthWp\Sdk;

use OpenBackAppAuthWp\Sdk\Http\Transport;
use OpenBackAppAuthWp\Sdk\Internal\OidcProtocol;

/**
 * Sign-in through the pool's hosted page for a `web` app (a confidential client with its own server): authorization
 * code + PKCE S256, client authentication `client_secret_basic` (default) or `client_secret_post`.
 *
 *     $oidc = new OidcWebClient($issuer, 'uapp_...', $secret, 'https://shop.example.com/auth/callback');
 *     $req = $oidc->authorizationUrl();                  // keep $req->transaction server-side (session)
 *     $_SESSION['ob_tx'] = $req->transaction->toArray();
 *     header('Location: ' . $req->url);
 *     // ... on the callback:
 *     $tokens = $oidc->handleCallback($_GET, $_SESSION['ob_tx']);   // TokenSet, ID token verified
 */
final class OidcWebClient
{
    private readonly OidcProtocol $protocol;
    private readonly TokenVerifier $verifier;
    private readonly string $redirectUri;
    private readonly string $scope;

    /**
     * @param array{
     *   authMethod?: 'client_secret_basic'|'client_secret_post', scope?: string, verifier?: TokenVerifier,
     *   transport?: \OpenBackAppAuthWp\Sdk\Http\HttpTransport, httpClient?: object, requestFactory?: object, streamFactory?: object,
     *   cache?: mixed, leeway?: int, clock?: callable(): int
     * } $options
     */
    public function __construct(string $issuer, string $clientId, string $clientSecret, string $redirectUri, array $options = [])
    {
        $issuer = rtrim(trim($issuer), '/');
        if ($clientId === '' || $clientSecret === '' || $redirectUri === '') {
            throw new \InvalidArgumentException('OidcWebClient: clientId, clientSecret and redirectUri are required');
        }
        $transport = Transport::fromOptions($options);
        $this->protocol = new OidcProtocol($transport, $issuer, $clientId, $clientSecret,
            (string) ($options['authMethod'] ?? 'client_secret_basic'));
        $verifierOptions = array_intersect_key($options, array_flip(['cache', 'leeway', 'clock', 'cacheTtl', 'jwksUri']));
        $this->verifier = $options['verifier'] ?? new TokenVerifier($issuer, $clientId, ['transport' => $transport] + $verifierOptions);
        $this->redirectUri = $redirectUri;
        $this->scope = (string) ($options['scope'] ?? OidcProtocol::DEFAULT_SCOPE);
    }

    /**
     * The hosted page's address and the transaction to keep server-side until the callback.
     *
     * @param array{provider?: string, orgId?: string, prompt?: 'none'|'login', screenHint?: 'signup', loginHint?: string,
     *              maxAge?: int, scope?: string, uiLocales?: string, redirectUri?: string} $options
     */
    public function authorizationUrl(array $options = []): AuthorizationRequest
    {
        $tx = AuthTransaction::create((string) ($options['redirectUri'] ?? $this->redirectUri));
        $options['scope'] = $options['scope'] ?? $this->scope;
        return new AuthorizationRequest($this->protocol->authorizeUrl($tx, $options), $tx);
    }

    /**
     * Checks the callback (error, state in constant time, iss), exchanges the code and verifies the ID token (signature,
     * issuer, audience, expiry, nonce, at_hash). Delete the stored transaction afterwards, whatever the result.
     *
     * @param array<string, mixed> $params the callback's query parameters ($_GET or $request->getQueryParams())
     * @param AuthTransaction|array<string, mixed> $transaction
     */
    public function handleCallback(array $params, AuthTransaction|array $transaction): TokenSet
    {
        $tx = $transaction instanceof AuthTransaction ? $transaction : AuthTransaction::fromArray($transaction);
        return $this->protocol->exchange($params, $tx, $this->verifier);
    }

    /** New tokens for a refresh token. The refresh token ROTATES: store the new one, never reuse the old one. */
    public function refresh(string $refreshToken, ?string $orgId = null): TokenSet
    {
        return $this->protocol->refresh($refreshToken, $orgId);
    }

    /** Revokes a refresh token (RFC 7009) and its whole family. */
    public function revoke(string $refreshToken): void
    {
        $this->protocol->revoke($refreshToken);
    }

    /** @return array<string, mixed> the OIDC userinfo of an access token */
    public function userinfo(string $accessToken): array
    {
        return $this->protocol->userinfo($accessToken);
    }

    /** The pool's end-session address (single logout). $postLogoutRedirectUri must be registered on the app. */
    public function logoutUrl(?string $idTokenHint = null, ?string $postLogoutRedirectUri = null, ?string $state = null): string
    {
        return $this->protocol->logoutUrl($idTokenHint, $postLogoutRedirectUri, $state);
    }

    public function verifier(): TokenVerifier
    {
        return $this->verifier;
    }

    public function issuer(): string
    {
        return $this->protocol->issuer;
    }

    public function clientId(): string
    {
        return $this->protocol->clientId;
    }
}
