<?php

declare(strict_types=1);

namespace OpenBack\AppAuth;

use OpenBack\AppAuth\Cache\ApcuJwksCache;
use OpenBack\AppAuth\Cache\JwksCache;
use OpenBack\AppAuth\Cache\MemoryJwksCache;
use OpenBack\AppAuth\Cache\Psr16JwksCache;
use OpenBack\AppAuth\Http\HttpTransport;
use OpenBack\AppAuth\Http\Transport;
use OpenBack\AppAuth\Internal\Ecdsa;
use OpenBack\AppAuth\Internal\Jwt;

/**
 * Verifies the pool's tokens locally with its public keys (JWKS), without calling OpenBack for each token.
 *
 * Only ES256 is accepted (never `none`, HS*, RS*: no algorithm confusion). Access tokens must have `typ` `at+jwt`,
 * the pool's exact issuer, an audience among the configured client IDs, and must not be expired (leeway 60 s).
 * Access tokens cannot be revoked before they expire: keep them short-lived (the pool's default is 15 minutes).
 *
 *     $verifier = new TokenVerifier('https://api.example.com/gateway/shop/auth/main', 'uapp_...');
 *     $user = $verifier->verify($bearerToken);     // AppUser, or AppAuthException (401 token_*)
 */
final class TokenVerifier
{
    private readonly string $issuer;
    /** @var string[] */
    private readonly array $clientIds;
    private readonly HttpTransport $transport;
    private readonly JwksCache $cache;
    private readonly string $jwksUri;
    private readonly int $cacheTtl;
    private readonly int $leeway;
    private readonly int $refetchInterval;
    /** @var callable(): int */
    private $clock;
    /** @var array<string, \OpenSSLAsymmetricKey> public keys by kid and key material */
    private array $keys = [];

    /**
     * @param string|string[] $clientIds the app(s) whose tokens are accepted (the `aud` claim)
     * @param array{
     *   transport?: HttpTransport, httpClient?: object, requestFactory?: object, streamFactory?: object,
     *   jwksUri?: string, cache?: JwksCache|\Psr\SimpleCache\CacheInterface, cacheTtl?: int, leeway?: int,
     *   refetchInterval?: int, clock?: callable(): int
     * } $options
     */
    public function __construct(string $issuer, string|array $clientIds, array $options = [])
    {
        $issuer = rtrim(trim($issuer), '/');
        if ($issuer === '' || !preg_match('#^https?://#i', $issuer)) {
            throw new \InvalidArgumentException('TokenVerifier: issuer must be an http(s) address');
        }
        $ids = array_values(array_filter(is_array($clientIds) ? $clientIds : [$clientIds], static fn ($v) => is_string($v) && $v !== ''));
        if ($ids === []) {
            throw new \InvalidArgumentException('TokenVerifier: at least one client ID is required');
        }
        $this->issuer = $issuer;
        $this->clientIds = $ids;
        $this->transport = Transport::fromOptions($options);
        $this->jwksUri = (string) ($options['jwksUri'] ?? $issuer . '/.well-known/jwks.json');
        $this->cacheTtl = max(1, (int) ($options['cacheTtl'] ?? 600));
        $this->leeway = max(0, (int) ($options['leeway'] ?? 60));
        $this->refetchInterval = max(0, (int) ($options['refetchInterval'] ?? 30));
        $this->clock = $options['clock'] ?? static fn (): int => time();
        $cache = $options['cache'] ?? null;
        if ($cache instanceof JwksCache) {
            $this->cache = $cache;
        } elseif ($cache !== null && interface_exists(\Psr\SimpleCache\CacheInterface::class) && $cache instanceof \Psr\SimpleCache\CacheInterface) {
            $this->cache = new Psr16JwksCache($cache);
        } elseif ($cache !== null) {
            throw new \InvalidArgumentException('TokenVerifier: option "cache" must be a JwksCache or a PSR-16 cache');
        } else {
            $this->cache = ApcuJwksCache::available() ? new ApcuJwksCache() : new MemoryJwksCache();
        }
    }

    public function issuer(): string
    {
        return $this->issuer;
    }

    /** @return string[] */
    public function clientIds(): array
    {
        return $this->clientIds;
    }

    /**
     * Verifies an access token (`typ: at+jwt`) and returns its user.
     *
     * @throws AppAuthException 401 `token_missing` | `token_invalid` | `token_expired` | `token_other_app`;
     *                          503 `jwks_unavailable` when the keys cannot be fetched
     */
    public function verify(?string $token): AppUser
    {
        $claims = $this->verifyToken($token, 'access');
        $clientId = (string) $claims['__client_id'];
        unset($claims['__client_id']);
        return AppUser::fromClaims($claims, $clientId);
    }

    /**
     * Verifies an ID token (`typ: JWT`, `aud` = the client ID) and, when given, its `nonce`. Returns its claims.
     *
     * @return array<string, mixed>
     * @throws AppAuthException 401 `token_*`, or 400 `invalid_nonce`
     */
    public function verifyIdToken(?string $idToken, ?string $nonce = null): array
    {
        $claims = $this->verifyToken($idToken, 'id');
        unset($claims['__client_id']);
        if ($nonce !== null && (!is_string($claims['nonce'] ?? null) || !hash_equals($nonce, $claims['nonce']))) {
            throw new AppAuthException(400, 'invalid_nonce', 'The ID token nonce does not match');
        }
        return $claims;
    }

    /** @return array<string, mixed> */
    private function verifyToken(?string $token, string $kind): array
    {
        if ($token === null || trim($token) === '') {
            throw new AppAuthException(401, 'token_missing', 'No token');
        }
        try {
            $jwt = Jwt::parse(trim($token));
        } catch (\InvalidArgumentException) {
            throw $this->invalid('malformed token');
        }
        $header = $jwt->header;
        if (($header['alg'] ?? null) !== 'ES256') {
            throw $this->invalid('unsupported algorithm');
        }
        if (array_key_exists('crit', $header)) {
            throw $this->invalid('unsupported critical header');
        }
        $typ = is_string($header['typ'] ?? null) ? strtolower($header['typ']) : null;
        if ($kind === 'access' && !in_array($typ, ['at+jwt', 'application/at+jwt'], true)) {
            throw $this->invalid('not an access token');
        }
        if ($kind === 'id' && $typ !== null && !in_array($typ, ['jwt', 'application/jwt'], true)) {
            throw $this->invalid('not an ID token');
        }
        $kid = $header['kid'] ?? null;
        if (!is_string($kid) || $kid === '' || strlen($kid) > 200) {
            throw $this->invalid('missing key id');
        }
        $publicKey = $this->publicKey($kid);
        try {
            $der = Ecdsa::joseToDer($jwt->signature);
        } catch (\InvalidArgumentException) {
            throw $this->invalid('bad signature');
        }
        if (openssl_verify($jwt->signingInput, $der, $publicKey, OPENSSL_ALGO_SHA256) !== 1) {
            while (openssl_error_string() !== false) {
                // drain OpenSSL's error queue
            }
            throw $this->invalid('bad signature');
        }
        return $this->checkClaims($jwt->claims);
    }

    /**
     * @param array<string, mixed> $claims
     * @return array<string, mixed>
     */
    private function checkClaims(array $claims): array
    {
        if (($claims['iss'] ?? null) !== $this->issuer) {
            throw $this->invalid('wrong issuer');
        }
        if (!is_string($claims['sub'] ?? null) || $claims['sub'] === '') {
            throw $this->invalid('no subject');
        }
        $aud = $claims['aud'] ?? null;
        $audiences = is_string($aud) ? [$aud] : (is_array($aud) ? array_values(array_filter($aud, 'is_string')) : []);
        $matched = null;
        foreach ($audiences as $candidate) {
            if (in_array($candidate, $this->clientIds, true)) {
                $matched = $candidate;
                break;
            }
        }
        if ($matched === null) {
            throw new AppAuthException(401, 'token_other_app', 'Token of another app');
        }
        $now = ($this->clock)();
        $exp = $claims['exp'] ?? null;
        if (!is_int($exp) && !is_float($exp)) {
            throw $this->invalid('no expiry');
        }
        if ($exp <= $now - $this->leeway) {
            throw new AppAuthException(401, 'token_expired', 'Token expired');
        }
        foreach (['nbf', 'iat'] as $name) {
            if (!array_key_exists($name, $claims)) {
                continue;
            }
            $value = $claims[$name];
            if ((!is_int($value) && !is_float($value)) || $value > $now + $this->leeway) {
                throw $this->invalid("token not valid yet ($name)");
            }
        }
        $claims['__client_id'] = $matched;
        return $claims;
    }

    private function publicKey(string $kid): \OpenSSLAsymmetricKey
    {
        $jwks = $this->jwks(false);
        if (!isset($jwks['keys'][$kid]) && ($this->clock)() - (int) ($jwks['fetchedAt'] ?? 0) >= $this->refetchInterval) {
            $jwks = $this->jwks(true);           // a new key (rotation): refetch, at most once per refetchInterval
        }
        $jwk = $jwks['keys'][$kid] ?? null;
        if (!is_array($jwk)) {
            throw $this->invalid('unknown key');
        }
        $id = $kid . '|' . ($jwk['x'] ?? '') . '|' . ($jwk['y'] ?? '');
        if (!isset($this->keys[$id])) {
            try {
                $key = @openssl_pkey_get_public(Ecdsa::jwkToPem($jwk));     // fails on a point not on the curve
            } catch (\InvalidArgumentException) {
                $key = false;
            }
            if ($key === false) {
                while (openssl_error_string() !== false) {
                    // drain OpenSSL's error queue
                }
                throw $this->invalid('unusable key');
            }
            $this->keys[$id] = $key;
        }
        return $this->keys[$id];
    }

    /** @return array{keys: array<string, array<string, mixed>>, fetchedAt: int} */
    private function jwks(bool $force): array
    {
        $cacheKey = 'openback_app_auth_jwks_' . sha1($this->jwksUri);
        $cached = $this->cache->get($cacheKey);
        if (!$force && is_array($cached) && is_array($cached['keys'] ?? null)) {
            return $cached;
        }
        try {
            $response = $this->transport->send('GET', $this->jwksUri, ['Accept' => 'application/json']);
        } catch (AppAuthException $e) {
            if (is_array($cached) && is_array($cached['keys'] ?? null)) {
                return $cached;
            }
            throw new AppAuthException(503, 'jwks_unavailable', 'The pool\'s keys could not be fetched', null, $e);
        }
        $data = $response->ok() ? $response->json() : null;
        if (!is_array($data) || !is_array($data['keys'] ?? null)) {
            if (is_array($cached) && is_array($cached['keys'] ?? null)) {
                return $cached;
            }
            throw new AppAuthException(503, 'jwks_unavailable', 'The pool\'s keys could not be fetched (HTTP ' . $response->status . ')');
        }
        $keys = [];
        foreach ($data['keys'] as $jwk) {
            if (!is_array($jwk) || !is_string($jwk['kid'] ?? null)) {
                continue;
            }
            if (($jwk['kty'] ?? null) !== 'EC' || ($jwk['crv'] ?? null) !== 'P-256') {
                continue;
            }
            if (isset($jwk['alg']) && $jwk['alg'] !== 'ES256') {
                continue;
            }
            if (isset($jwk['use']) && $jwk['use'] !== 'sig') {
                continue;
            }
            $keys[$jwk['kid']] = ['kty' => 'EC', 'crv' => 'P-256', 'x' => $jwk['x'] ?? null, 'y' => $jwk['y'] ?? null];
        }
        $out = ['keys' => $keys, 'fetchedAt' => ($this->clock)()];
        $this->cache->set($cacheKey, $out, $this->cacheTtl);
        return $out;
    }

    private function invalid(string $reason): AppAuthException
    {
        return new AppAuthException(401, 'token_invalid', 'Invalid token: ' . $reason);
    }
}
