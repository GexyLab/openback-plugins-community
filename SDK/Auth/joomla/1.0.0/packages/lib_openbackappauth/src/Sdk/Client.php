<?php

declare(strict_types=1);

// Bundled copy of openback-app-auth-php 1.0.0 (MIT), namespace prefixed for this extension.

namespace OpenBackAppAuthJoomla\Sdk;

\defined('_JEXEC') or die;

use OpenBackAppAuthJoomla\Sdk\Http\HttpResponse;
use OpenBackAppAuthJoomla\Sdk\Http\HttpTransport;
use OpenBackAppAuthJoomla\Sdk\Http\Transport;
use OpenBackAppAuthJoomla\Sdk\Internal\Jwt;
use OpenBackAppAuthJoomla\Sdk\Internal\OidcProtocol;
use OpenBackAppAuthJoomla\Sdk\Lock\InProcessLock;
use OpenBackAppAuthJoomla\Sdk\Lock\RefreshLock;
use OpenBackAppAuthJoomla\Sdk\Storage\MemoryStorage;
use OpenBackAppAuthJoomla\Sdk\Storage\Storage;
use Psr\Http\Message\RequestInterface;

/**
 * The client of a user pool's JSON API (`<issuer>/api/v1`) and of its hosted sign-in page, for PHP code that signs
 * users in itself: a CLI tool, a desktop/worker process, a server acting for a user (the session kept in the PHP session
 * with {@see Storage\SessionStorage}), or a `backend` app.
 *
 *     $auth = new Client('https://api.example.com/gateway/shop/auth/main', 'uapp_...');
 *     $res = $auth->signInWithPassword('ada@example.com', $password);
 *     if ($res->status === OutcomeStatus::MfaRequired) { $res = $auth->verifyMfa($res->mfaToken, $code); }
 *     $token = $auth->getAccessToken();             // renewed one minute before it expires
 *
 * The session (`{accessToken, refreshToken, idToken, expiresAt (epoch ms), user, org}`) is kept in the storage under
 * `openback.auth.<clientId>`. Refresh tokens rotate: refreshes are serialized ({@see RefreshLock}) and never retried
 * automatically.
 */
final class Client
{
    private const API = '/api/v1';
    private const SKEW_MS = 60_000;

    private readonly string $issuer;
    private readonly string $clientId;
    private readonly string $key;
    private readonly Storage $storage;
    private readonly HttpTransport $transport;
    private readonly RefreshLock $lock;
    private readonly OidcProtocol $protocol;
    private readonly ?string $redirectUri;
    /** @var array<string, mixed> */
    private readonly array $verifierOptions;
    private ?TokenVerifier $verifier;
    /** @var callable(): int */
    private $clock;
    /** @var array<string, mixed> */
    private array $state;
    /** @var array<int, callable> */
    private array $listeners = [];
    private int $nextListener = 0;

    /**
     * @param array{
     *   redirectUri?: string, storage?: Storage, storageKey?: string, clientSecret?: string,
     *   authMethod?: 'client_secret_basic'|'client_secret_post', lock?: RefreshLock, verifier?: TokenVerifier,
     *   transport?: HttpTransport, httpClient?: object, requestFactory?: object, streamFactory?: object,
     *   cache?: mixed, clock?: callable(): int
     * } $options `clientSecret` only for `web` / `backend` apps (server-side code, never shipped to a browser or device)
     */
    public function __construct(string $issuer, string $clientId, array $options = [])
    {
        $issuer = rtrim(trim($issuer), '/');
        if ($issuer === '' || $clientId === '') {
            throw new \InvalidArgumentException('Client: issuer and clientId are required');
        }
        $this->issuer = $issuer;
        $this->clientId = $clientId;
        $this->key = (string) ($options['storageKey'] ?? 'openback.auth.' . $clientId);
        $this->storage = $options['storage'] ?? new MemoryStorage();
        $this->transport = Transport::fromOptions($options);
        $this->lock = $options['lock'] ?? new InProcessLock();
        $this->redirectUri = isset($options['redirectUri']) ? (string) $options['redirectUri'] : null;
        $this->protocol = new OidcProtocol($this->transport, $issuer, $clientId,
            isset($options['clientSecret']) ? (string) $options['clientSecret'] : null,
            (string) ($options['authMethod'] ?? 'client_secret_basic'));
        $this->verifier = $options['verifier'] ?? null;
        $this->verifierOptions = array_intersect_key($options, array_flip(['cache', 'clock']));
        $this->clock = $options['clock'] ?? static fn (): int => time();
        $this->state = $this->load();
    }

    public function issuer(): string
    {
        return $this->issuer;
    }

    public function clientId(): string
    {
        return $this->clientId;
    }

    // --- state -----------------------------------------------------------------------------------------------------

    /** @return array<string, mixed>|null the signed-in PoolUser */
    public function currentUser(): ?array
    {
        return is_array($this->state['user'] ?? null) ? $this->state['user'] : null;
    }

    /** @return array<string, mixed>|null the active organization (B2B pools) */
    public function currentOrg(): ?array
    {
        return is_array($this->state['org'] ?? null) ? $this->state['org'] : null;
    }

    /** @return array<string, mixed>|null the claims of the current access token, decoded WITHOUT verification */
    public function accessTokenClaims(): ?array
    {
        return Jwt::unverifiedClaims($this->state['accessToken'] ?? null);
    }

    public function isSignedIn(): bool
    {
        return is_string($this->state['refreshToken'] ?? null) && $this->state['refreshToken'] !== '';
    }

    /** The ID token of the last hosted sign-in (for the logout's id_token_hint), if any. */
    public function idToken(): ?string
    {
        return is_string($this->state['idToken'] ?? null) ? $this->state['idToken'] : null;
    }

    /**
     * Calls $listener(?array $user, ?array $org) now and at every change (sign-in, refresh, sign-out).
     *
     * @return \Closure(): void unsubscribes
     */
    public function onAuthStateChanged(callable $listener): \Closure
    {
        $id = $this->nextListener++;
        $this->listeners[$id] = $listener;
        $this->notify($listener);
        return function () use ($id): void {
            unset($this->listeners[$id]);
        };
    }

    // --- tokens ----------------------------------------------------------------------------------------------------

    /** The access token, renewed when it expires within 60 seconds. */
    public function getAccessToken(): string
    {
        if ($this->fresh($this->state)) {
            return (string) $this->state['accessToken'];
        }
        return $this->refresh();
    }

    /**
     * New tokens now (optionally for another organization). One refresh at a time ({@see RefreshLock}); a failure
     * is thrown, never retried (the next call tries again with the stored token). A refused refresh token ends the
     * local session.
     */
    public function refresh(?string $orgId = null): string
    {
        if (!$this->isSignedIn()) {
            throw new AppAuthException(401, 'not_signed_in', 'Not signed in');
        }
        return $this->lock->synchronized($this->key . '.refresh', function () use ($orgId): string {
            $latest = $this->load();               // another process may have renewed it already
            if ($orgId === null && ($latest['refreshToken'] ?? null) !== null
                && $latest['refreshToken'] !== ($this->state['refreshToken'] ?? null) && $this->fresh($latest)) {
                $this->state = $latest;
                return (string) $latest['accessToken'];
            }
            $refreshToken = $latest['refreshToken'] ?? $this->state['refreshToken'] ?? null;
            if (!is_string($refreshToken) || $refreshToken === '') {
                $this->save(null);
                throw new AppAuthException(401, 'not_signed_in', 'Not signed in');
            }
            try {
                $data = $this->call('POST', '/token/refresh', ['refresh_token' => $refreshToken, 'org_id' => $orgId]);
            } catch (AppAuthException $e) {
                if ($e->status === 401) {
                    $this->save(null);
                }
                throw $e;
            }
            $this->keep($data);
            return (string) $this->state['accessToken'];
        });
    }

    /**
     * An HTTP request to YOUR API with `Authorization: Bearer <access token>`.
     *
     * @param array<string, string> $headers
     */
    public function fetch(string $method, string $url, array $headers = [], ?string $body = null): HttpResponse
    {
        $headers['Authorization'] = 'Bearer ' . $this->getAccessToken();
        return $this->transport->send($method, $url, $headers, $body);
    }

    /** A PSR-7 request with `Authorization: Bearer <access token>` added (for your own PSR-18 client). */
    public function authorizeRequest(RequestInterface $request): RequestInterface
    {
        return $request->withHeader('Authorization', 'Bearer ' . $this->getAccessToken());
    }

    // --- configuration, sign-up and sign-in ------------------------------------------------------------------------

    /** @return array<string, mixed> the pool's public configuration (methods, providers, password policy, branding) */
    public function config(): array
    {
        return $this->call('GET', '/config');
    }

    public function signUp(string $email, string $password, ?string $displayName = null, ?string $locale = null, ?string $orgId = null): Outcome
    {
        return $this->outcome($this->call('POST', '/signup', ['email' => $email, 'password' => $password,
            'display_name' => $displayName ?? '', 'locale' => $locale, 'org_id' => $orgId]));
    }

    public function signInWithPassword(string $email, string $password, ?string $orgId = null): Outcome
    {
        return $this->outcome($this->call('POST', '/signin/password', ['email' => $email, 'password' => $password, 'org_id' => $orgId]));
    }

    /** @return array<string, mixed> always `{status: "sent"}` */
    public function sendEmailCode(string $email): array
    {
        return $this->call('POST', '/signin/email-code', ['email' => $email]);
    }

    /** With the emailed code (and the email), or with the link's token. */
    public function signInWithEmailCode(?string $email = null, ?string $code = null, ?string $token = null, ?string $orgId = null): Outcome
    {
        return $this->outcome($this->call('POST', '/signin/email-code/verify', ['email' => $email, 'code' => $code,
            'token' => $token, 'org_id' => $orgId]));
    }

    public function signInAnonymously(): Outcome
    {
        return $this->outcome($this->call('POST', '/signin/anonymous', []));
    }

    public function verifyMfa(string $mfaToken, string $code): Outcome
    {
        return $this->outcome($this->call('POST', '/signin/mfa', ['mfa_token' => $mfaToken, 'code' => $code]));
    }

    /** @return array<string, mixed> `{secret, otpauth_uri}`: during a sign-in with $mfaToken, else for the signed-in user */
    public function enrollMfa(?string $mfaToken = null): array
    {
        return $mfaToken !== null
            ? $this->call('POST', '/mfa/enroll', ['mfa_token' => $mfaToken])
            : $this->call('POST', '/mfa/enroll', [], true);
    }

    /**
     * Confirms the enrollment with a code of the authenticator app. With $mfaToken (during a sign-in) the answer is
     * also an outcome: the session is kept when its status is "ok". The answer holds `recovery_codes`: show them once.
     *
     * @return array<string, mixed>
     */
    public function confirmMfa(string $code, ?string $mfaToken = null): array
    {
        if ($mfaToken === null) {
            return $this->call('POST', '/mfa/enroll/confirm', ['code' => $code], true);
        }
        $data = $this->call('POST', '/mfa/enroll/confirm', ['mfa_token' => $mfaToken, 'code' => $code]);
        $this->outcome($data);
        return $data;
    }

    /** @return array<string, mixed> */
    public function disableMfa(string $code): array
    {
        return $this->call('POST', '/mfa/disable', ['code' => $code], true);
    }

    // --- passwords and emails --------------------------------------------------------------------------------------

    /** @return array<string, mixed> always `{status: "sent"}` */
    public function sendPasswordReset(string $email): array
    {
        return $this->call('POST', '/password/forgot', ['email' => $email]);
    }

    /** With the link's token, or with the email and the emailed code. @return array<string, mixed> */
    public function resetPassword(string $newPassword, ?string $token = null, ?string $email = null, ?string $code = null): array
    {
        return $this->call('POST', '/password/reset', ['token' => $token, 'email' => $email, 'code' => $code, 'new_password' => $newPassword]);
    }

    /** Continues a `password_change_required` outcome. @return array<string, mixed> */
    public function changeForcedPassword(string $changeToken, string $newPassword): array
    {
        return $this->call('POST', '/password/reset', ['change_token' => $changeToken, 'new_password' => $newPassword]);
    }

    /** With the link's token, or with the email and the code. @return array<string, mixed> */
    public function verifyEmail(?string $token = null, ?string $email = null, ?string $code = null): array
    {
        return $this->call('POST', '/email/verify', ['token' => $token, 'email' => $email, 'code' => $code]);
    }

    /** @return array<string, mixed> */
    public function resendVerification(): array
    {
        return $this->call('POST', '/email/verify/send', [], true);
    }

    // --- the signed-in user ----------------------------------------------------------------------------------------

    /** @return array<string, mixed> the PoolUser with org_id, roles, providers, has_password */
    public function me(): array
    {
        $user = $this->call('GET', '/me', null, true);
        $this->rememberUser($user);
        return $user;
    }

    /** @return array<string, mixed> the updated PoolUser */
    public function updateProfile(?string $displayName = null, ?string $photoUrl = null, ?string $locale = null): array
    {
        $user = $this->call('PATCH', '/me', ['display_name' => $displayName, 'photo_url' => $photoUrl, 'locale' => $locale], true);
        $this->rememberUser($user);
        return $user;
    }

    /** Every session of the user ends: the local one is cleared too. @return array<string, mixed> */
    public function changePassword(string $newPassword, ?string $currentPassword = null): array
    {
        $out = $this->call('POST', '/me/password', ['current_password' => $currentPassword, 'new_password' => $newPassword], true);
        $this->save(null);
        return $out;
    }

    /** @return array<string, mixed> `{status: "verification_sent"}` */
    public function changeEmail(string $newEmail): array
    {
        return $this->call('POST', '/me/email', ['new_email' => $newEmail], true);
    }

    /** @return array<string, mixed> `{status: "email_changed", user}` */
    public function confirmEmailChange(?string $code = null, ?string $token = null): array
    {
        $out = $this->call('POST', '/me/email/confirm', ['code' => $code, 'token' => $token], true);
        if (is_array($out['user'] ?? null)) {
            $this->rememberUser($out['user']);
        }
        return $out;
    }

    /** A guest account becomes a real one (same id). @return array<string, mixed> `{status: "upgraded", user}` */
    public function upgradeAnonymous(string $email, string $password): array
    {
        $out = $this->call('POST', '/me/upgrade', ['email' => $email, 'password' => $password], true);
        if (is_array($out['user'] ?? null)) {
            $this->rememberUser($out['user']);
        }
        return $out;
    }

    /** Deletes the account (the password is required when it has one); the local session is cleared. @return array<string, mixed> */
    public function deleteAccount(?string $password = null): array
    {
        $out = $this->call('DELETE', '/me', ['password' => $password], true);
        $this->save(null);
        return $out;
    }

    /** Signs out on the server (best effort) and always locally. $everywhere ends every session of the user. */
    public function signOut(bool $everywhere = false): void
    {
        $access = $this->state['accessToken'] ?? null;
        $refresh = $this->state['refreshToken'] ?? null;
        try {
            if (is_string($access) && $access !== '') {
                $this->call('POST', '/signout', ['refresh_token' => $refresh, 'everywhere' => $everywhere], true, $access);
            } elseif (is_string($refresh) && $refresh !== '') {
                $this->call('POST', '/signout', ['refresh_token' => $refresh]);
            }
        } catch (AppAuthException) {
            // signed out locally anyway
        }
        $this->save(null);
    }

    // --- organizations (B2B pools) ---------------------------------------------------------------------------------

    /** @return array<string, mixed> `{orgs: [{id, name, roles, disabled}], active}` (B2C pools: empty) */
    public function organizations(): array
    {
        return $this->call('GET', '/orgs', null, true);
    }

    /** @return array<string, mixed> `{id, name, roles: ["owner"]}` */
    public function createOrganization(string $name): array
    {
        return $this->call('POST', '/orgs', ['name' => $name], true);
    }

    /** New tokens for another organization of the user. @return array<string, mixed>|null the new active organization */
    public function switchOrganization(string $orgId): ?array
    {
        return $this->lock->synchronized($this->key . '.refresh', function () use ($orgId): ?array {
            $latest = $this->load();
            $refreshToken = $latest['refreshToken'] ?? $this->state['refreshToken'] ?? null;
            try {
                $data = $this->call('POST', '/orgs/switch', ['org_id' => $orgId, 'refresh_token' => $refreshToken], true);
            } catch (AppAuthException $e) {
                if ($e->errorCode === 'invalid_refresh_token') {
                    $this->save(null);
                }
                throw $e;
            }
            $this->keep($data);
            return $this->currentOrg();
        });
    }

    /** @return array<string, mixed> `{items, total?, roles}` */
    public function members(string $orgId, string $q = '', int $skip = 0, int $limit = 50): array
    {
        $query = http_build_query(['q' => $q, 'skip' => $skip, 'limit' => $limit], '', '&', PHP_QUERY_RFC3986);
        return $this->call('GET', '/orgs/' . rawurlencode($orgId) . '/members?' . $query, null, true);
    }

    /**
     * @param string[] $roles
     * @return array<string, mixed> the new member (may include a temporary password)
     */
    public function addMember(string $orgId, string $email, ?string $displayName = null, ?string $password = null, array $roles = []): array
    {
        return $this->call('POST', '/orgs/' . rawurlencode($orgId) . '/members',
            ['email' => $email, 'display_name' => $displayName ?? '', 'password' => $password, 'roles' => array_values($roles)], true);
    }

    /**
     * @param string[] $roles
     * @return array<string, mixed>
     */
    public function setMemberRoles(string $orgId, string $userId, array $roles): array
    {
        return $this->call('PATCH', '/orgs/' . rawurlencode($orgId) . '/members/' . rawurlencode($userId), ['roles' => array_values($roles)], true);
    }

    /** @return array<string, mixed> */
    public function removeMember(string $orgId, string $userId): array
    {
        return $this->call('DELETE', '/orgs/' . rawurlencode($orgId) . '/members/' . rawurlencode($userId), null, true);
    }

    // --- hosted sign-in page (OIDC) --------------------------------------------------------------------------------

    /**
     * The hosted page's address; state, nonce and PKCE verifier are kept in the storage until
     * {@see handleRedirectCallback()}. Redirect the user's browser (or open a system browser) to `$request->url`.
     *
     * @param array{provider?: string, orgId?: string, prompt?: 'none'|'login', screenHint?: 'signup', loginHint?: string,
     *              maxAge?: int, scope?: string, uiLocales?: string, redirectUri?: string} $options
     */
    public function buildAuthorizationRequest(array $options = []): AuthorizationRequest
    {
        $redirectUri = (string) ($options['redirectUri'] ?? $this->redirectUri ?? '');
        if ($redirectUri === '') {
            throw new \InvalidArgumentException('buildAuthorizationRequest: redirectUri is required (option of the Client or of the call)');
        }
        $tx = AuthTransaction::create($redirectUri);
        $this->storage->set($this->key . '.pkce', (string) json_encode($tx->toArray()));
        return new AuthorizationRequest($this->protocol->authorizeUrl($tx, $options), $tx);
    }

    /**
     * Completes a hosted sign-in on the redirect address: checks error, state and iss, exchanges the code (PKCE),
     * verifies the ID token and its nonce, keeps the session and loads the user. Null when $urlOrParams carries no
     * callback.
     *
     * @param string|array<string, mixed> $urlOrParams the full callback URL, or its query parameters ($_GET)
     * @return array<string, mixed>|null the PoolUser
     */
    public function handleRedirectCallback(string|array $urlOrParams): ?array
    {
        $params = $urlOrParams;
        if (is_string($urlOrParams)) {
            $params = [];
            parse_str((string) parse_url($urlOrParams, PHP_URL_QUERY), $params);
        }
        if (!isset($params['code']) && !isset($params['error'])) {
            return null;
        }
        $pending = json_decode((string) $this->storage->get($this->key . '.pkce'), true);
        $this->storage->remove($this->key . '.pkce');
        if (!is_array($pending)) {
            throw new AppAuthException(400, 'invalid_state', 'No sign-in in progress');
        }
        $tokens = $this->protocol->exchange($params, AuthTransaction::fromArray($pending), $this->verifier());
        $this->keep($tokens->raw + ['user' => null]);
        try {
            return $this->me();
        } catch (AppAuthException) {
            return null;
        }
    }

    /** The pool's end-session address (with the ID token as hint when there is one). */
    public function buildLogoutUrl(?string $postLogoutRedirectUri = null, ?string $state = null): string
    {
        return $this->protocol->logoutUrl($this->idToken(), $postLogoutRedirectUri, $state);
    }

    /** Clears the local session and returns the end-session address to redirect the browser to. */
    public function signOutRedirect(?string $postLogoutRedirectUri = null, ?string $state = null): string
    {
        $url = $this->buildLogoutUrl($postLogoutRedirectUri, $state);
        $this->save(null);
        return $url;
    }

    // --- internals -------------------------------------------------------------------------------------------------

    private function verifier(): TokenVerifier
    {
        return $this->verifier ??= new TokenVerifier($this->issuer, $this->clientId, ['transport' => $this->transport] + $this->verifierOptions);
    }

    /**
     * @param array<string, mixed>|null $body null: no body; nulls inside are left out
     * @return array<string, mixed>
     */
    private function call(string $method, string $path, ?array $body = null, bool $auth = false, ?string $token = null): array
    {
        $headers = ['X-Client-Id' => $this->clientId, 'Accept' => 'application/json'];
        $payload = null;
        if ($body !== null) {
            $body = array_filter($body, static fn ($v) => $v !== null);
            $headers['Content-Type'] = 'application/json';
            $payload = $body === [] ? '{}' : (string) json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        }
        if ($auth) {
            $headers['Authorization'] = 'Bearer ' . ($token ?? $this->getAccessToken());
        }
        $response = $this->transport->send($method, $this->issuer . self::API . $path, $headers, $payload);
        $data = $response->json();
        if (!$response->ok()) {
            $error = AppAuthException::fromResponse($response->status, $data);
            if ($auth && $error->status === 401 && str_starts_with($error->errorCode, 'token_')) {
                $this->save(null);
            }
            throw $error;
        }
        return $data ?? [];
    }

    /** @param array<string, mixed> $data */
    private function outcome(array $data): Outcome
    {
        $outcome = Outcome::fromResponse($data);
        if ($outcome->isOk() && is_string($data['access_token'] ?? null)) {
            $this->keep($data);
        }
        return $outcome;
    }

    /** Keeps the tokens of an answer (sign-in, refresh, switch, code exchange). @param array<string, mixed> $data */
    private function keep(array $data): void
    {
        $this->save([
            'accessToken' => $data['access_token'],
            'refreshToken' => $data['refresh_token'] ?? $this->state['refreshToken'] ?? null,
            'idToken' => $data['id_token'] ?? $this->state['idToken'] ?? null,
            'expiresAt' => $this->nowMs() + (int) ($data['expires_in'] ?? 900) * 1000,
            'user' => array_key_exists('user', $data) ? $data['user'] : ($this->state['user'] ?? null),
            'org' => is_array($data['org'] ?? null) ? $data['org'] : null,
        ]);
    }

    /** @param array<string, mixed> $user */
    private function rememberUser(array $user): void
    {
        if ($this->isSignedIn()) {
            $this->save(['user' => $user] + $this->state);
        }
    }

    /** @param array<string, mixed>|null $next */
    private function save(?array $next): void
    {
        $this->state = $next ?? [];
        if ($next !== null && is_string($next['refreshToken'] ?? null) && $next['refreshToken'] !== '') {
            $this->storage->set($this->key, (string) json_encode($this->state, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        } else {
            $this->state = [];
            $this->storage->remove($this->key);
        }
        foreach ($this->listeners as $listener) {
            $this->notify($listener);
        }
    }

    private function notify(callable $listener): void
    {
        try {
            $listener($this->currentUser(), $this->currentOrg());
        } catch (\Throwable) {
            // a listener's error is its own
        }
    }

    /** @return array<string, mixed> */
    private function load(): array
    {
        $raw = $this->storage->get($this->key);
        if ($raw === null || $raw === '') {
            return [];
        }
        $data = json_decode($raw, true);
        return is_array($data) ? $data : [];
    }

    /** @param array<string, mixed> $state */
    private function fresh(array $state): bool
    {
        return is_string($state['accessToken'] ?? null) && is_numeric($state['expiresAt'] ?? null)
            && (int) $state['expiresAt'] - $this->nowMs() > self::SKEW_MS;
    }

    private function nowMs(): int
    {
        return ($this->clock)() * 1000;
    }
}
