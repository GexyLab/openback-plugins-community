<?php

declare(strict_types=1);

// Bundled copy of openback-app-auth-php 1.0.0 (MIT), namespace prefixed for this extension.

namespace OpenBackAppAuthJoomla\Sdk\Internal;

\defined('_JEXEC') or die;

use OpenBackAppAuthJoomla\Sdk\AppAuthException;
use OpenBackAppAuthJoomla\Sdk\AuthTransaction;
use OpenBackAppAuthJoomla\Sdk\Http\HttpTransport;
use OpenBackAppAuthJoomla\Sdk\TokenSet;
use OpenBackAppAuthJoomla\Sdk\TokenVerifier;

/**
 * @internal The OIDC requests shared by Client and OidcWebClient: authorize URL, code exchange (state, iss, nonce,
 * at_hash checks), refresh, revocation, userinfo and end-session URL.
 */
final class OidcProtocol
{
    public const DEFAULT_SCOPE = 'openid profile email';

    public function __construct(
        private readonly HttpTransport $transport,
        public readonly string $issuer,
        public readonly string $clientId,
        private readonly ?string $clientSecret = null,
        private readonly string $authMethod = 'client_secret_basic',
    ) {
        if (!in_array($authMethod, ['client_secret_basic', 'client_secret_post'], true)) {
            throw new \InvalidArgumentException('authMethod must be client_secret_basic or client_secret_post');
        }
    }

    /**
     * @param array{provider?: string, orgId?: string, prompt?: string, screenHint?: string, loginHint?: string,
     *              maxAge?: int, scope?: string, uiLocales?: string} $options
     */
    public function authorizeUrl(AuthTransaction $tx, array $options = []): string
    {
        $scope = trim((string) ($options['scope'] ?? self::DEFAULT_SCOPE));
        if (!in_array('openid', preg_split('/\s+/', $scope) ?: [], true)) {
            $scope = trim('openid ' . $scope);
        }
        $params = [
            'response_type' => 'code',
            'client_id' => $this->clientId,
            'redirect_uri' => $tx->redirectUri,
            'scope' => $scope,
            'state' => $tx->state,
            'nonce' => $tx->nonce,
            'code_challenge' => $tx->codeChallenge(),
            'code_challenge_method' => 'S256',
        ];
        $extras = ['provider' => 'provider', 'orgId' => 'org_id', 'prompt' => 'prompt', 'screenHint' => 'screen_hint',
            'loginHint' => 'login_hint', 'maxAge' => 'max_age', 'uiLocales' => 'ui_locales'];
        foreach ($extras as $option => $param) {
            if (isset($options[$option]) && $options[$option] !== '') {
                $params[$param] = (string) $options[$option];
            }
        }
        return $this->issuer . '/authorize?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * The callback's parameters (the query of the redirect) -> verified tokens.
     *
     * @param array<string, mixed> $params
     */
    public function exchange(array $params, AuthTransaction $tx, TokenVerifier $verifier): TokenSet
    {
        $get = static fn (string $name): ?string => isset($params[$name]) && is_string($params[$name]) && $params[$name] !== '' ? $params[$name] : null;
        $state = $get('state');
        if ($state === null || !hash_equals($tx->state, $state)) {
            throw new AppAuthException(400, 'invalid_state', 'Sign-in state mismatch');
        }
        $error = $get('error');
        if ($error !== null) {
            $code = substr((string) preg_replace('/[^A-Za-z0-9_.-]/', '', $error), 0, 64);
            $description = $get('error_description');
            throw new AppAuthException(400, $code !== '' ? $code : 'access_denied',
                $description !== null ? substr($description, 0, 300) : ($code !== '' ? $code : 'access_denied'));
        }
        $iss = $get('iss');
        if ($iss !== null && $iss !== $this->issuer) {
            throw new AppAuthException(400, 'invalid_issuer', 'Unexpected issuer');
        }
        $code = $get('code');
        if ($code === null) {
            throw new AppAuthException(400, 'invalid_request', 'No authorization code');
        }
        $data = $this->tokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $tx->redirectUri,
            'code_verifier' => $tx->codeVerifier,
        ]);
        $idToken = is_string($data['id_token'] ?? null) ? $data['id_token'] : null;
        if ($idToken === null) {
            throw new AppAuthException(502, 'missing_id_token', 'The token endpoint answered without an ID token');
        }
        $claims = $verifier->verifyIdToken($idToken, $tx->nonce);
        if (is_string($claims['at_hash'] ?? null) && is_string($data['access_token'] ?? null)) {
            $digest = hash('sha256', $data['access_token'], true);
            if (!hash_equals(Base64Url::encode(substr($digest, 0, 16)), $claims['at_hash'])) {
                throw new AppAuthException(400, 'invalid_at_hash', 'The access token does not match the ID token');
            }
        }
        return TokenSet::fromResponse($data, $claims);
    }

    public function refresh(string $refreshToken, ?string $orgId = null): TokenSet
    {
        $form = ['grant_type' => 'refresh_token', 'refresh_token' => $refreshToken];
        if ($orgId !== null && $orgId !== '') {
            $form['org_id'] = $orgId;
        }
        return TokenSet::fromResponse($this->tokenRequest($form));
    }

    public function revoke(string $refreshToken): void
    {
        $response = $this->transport->send('POST', $this->issuer . '/revoke', $this->formHeaders(),
            http_build_query($this->withClientAuth(['token' => $refreshToken, 'token_type_hint' => 'refresh_token']), '', '&'));
        if (!$response->ok()) {
            throw AppAuthException::fromResponse($response->status, $response->json());
        }
    }

    /** @return array<string, mixed> */
    public function userinfo(string $accessToken): array
    {
        $response = $this->transport->send('GET', $this->issuer . '/userinfo', [
            'Authorization' => 'Bearer ' . $accessToken,
            'Accept' => 'application/json',
        ]);
        $data = $response->json();
        if (!$response->ok() || !is_array($data)) {
            throw AppAuthException::fromResponse($response->status, $data);
        }
        return $data;
    }

    public function logoutUrl(?string $idTokenHint = null, ?string $postLogoutRedirectUri = null, ?string $state = null): string
    {
        $params = ['client_id' => $this->clientId];
        if ($idTokenHint !== null && $idTokenHint !== '') {
            $params['id_token_hint'] = $idTokenHint;
        }
        if ($postLogoutRedirectUri !== null && $postLogoutRedirectUri !== '') {
            $params['post_logout_redirect_uri'] = $postLogoutRedirectUri;
        }
        if ($state !== null && $state !== '') {
            $params['state'] = $state;
        }
        return $this->issuer . '/logout?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * POST <issuer>/token, form-encoded, with the client's authentication.
     *
     * @param array<string, string> $form
     * @return array<string, mixed>
     */
    public function tokenRequest(array $form): array
    {
        $response = $this->transport->send('POST', $this->issuer . '/token', $this->formHeaders(),
            http_build_query($this->withClientAuth($form), '', '&'));
        $data = $response->json();
        if (!$response->ok() || !is_array($data)) {
            throw AppAuthException::fromResponse($response->status, $data);
        }
        return $data;
    }

    /** @return array<string, string> */
    private function formHeaders(): array
    {
        $headers = ['Content-Type' => 'application/x-www-form-urlencoded', 'Accept' => 'application/json'];
        if ($this->clientSecret !== null && $this->clientSecret !== '' && $this->authMethod === 'client_secret_basic') {
            $headers['Authorization'] = 'Basic ' . base64_encode(rawurlencode($this->clientId) . ':' . rawurlencode($this->clientSecret));
        }
        return $headers;
    }

    /**
     * @param array<string, string> $form
     * @return array<string, string>
     */
    private function withClientAuth(array $form): array
    {
        $form['client_id'] = $this->clientId;
        if ($this->clientSecret !== null && $this->clientSecret !== '' && $this->authMethod === 'client_secret_post') {
            $form['client_secret'] = $this->clientSecret;
        }
        return $form;
    }
}
