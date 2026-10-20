<?php

declare(strict_types=1);

namespace OpenBack\AppAuth\Tests;

use OpenBack\AppAuth\AppAuthException;
use OpenBack\AppAuth\Cache\MemoryJwksCache;
use OpenBack\AppAuth\Internal\Base64Url;
use OpenBack\AppAuth\TokenVerifier;
use OpenBack\AppAuth\Tests\Support\FakeTransport;
use OpenBack\AppAuth\Tests\Support\TestKeys;
use PHPUnit\Framework\TestCase;
use Psr\SimpleCache\CacheInterface;

final class TokenVerifierTest extends TestCase
{
    private const JWKS = TestKeys::ISSUER . '/.well-known/jwks.json';

    private TestKeys $keys;
    private FakeTransport $http;
    private int $now;

    protected function setUp(): void
    {
        MemoryJwksCache::clear();
        $this->keys = new TestKeys('k1');
        $this->http = (new FakeTransport())->json('GET', self::JWKS, 200, TestKeys::jwks([$this->keys]));
        $this->now = time();
    }

    private function verifier(array $options = []): TokenVerifier
    {
        return new TokenVerifier(TestKeys::ISSUER . '/', TestKeys::CLIENT, $options + [
            'transport' => $this->http, 'cache' => new MemoryJwksCache(), 'clock' => fn () => $this->now,
        ]);
    }

    private function assertRefused(string $token, string $code, ?TokenVerifier $verifier = null): void
    {
        try {
            ($verifier ?? $this->verifier())->verify($token);
            self::fail("token accepted, expected $code");
        } catch (AppAuthException $e) {
            self::assertSame($code, $e->errorCode);
            self::assertSame(401, $e->status);
        }
    }

    public function testVerifiesAnAccessToken(): void
    {
        $token = $this->keys->sign(TestKeys::accessClaims(['anon' => false, 'attr' => ['plan' => 'pro'], 'permissions' => ['orders.read']]));
        $user = $this->verifier()->verify($token);
        self::assertSame('usr_1', $user->id);
        self::assertSame('upool_1', $user->poolId);
        self::assertSame(TestKeys::CLIENT, $user->clientId);
        self::assertSame('ada@example.com', $user->email);
        self::assertTrue($user->emailVerified);
        self::assertFalse($user->anonymous);
        self::assertSame('org_1', $user->orgId);
        self::assertSame(['member'], $user->roles);
        self::assertSame(['plan' => 'pro'], $user->attributes);
        self::assertSame('sess_1', $user->sessionId);
        self::assertSame(['pwd'], $user->amr);
        self::assertTrue($user->hasRole('member'));
        self::assertFalse($user->hasRole('admin'));
        self::assertTrue($user->hasPermission('orders.read'));
        self::assertFalse($user->hasPermission('orders.write'));
        self::assertArrayNotHasKey('__client_id', $user->claims);
        self::assertSame('at_1', $user->claims['jti']);
    }

    public function testStarPermissionGrantsAll(): void
    {
        $user = $this->verifier()->verify($this->keys->sign(TestKeys::accessClaims(['permissions' => ['*']])));
        self::assertTrue($user->hasPermission('anything'));
    }

    public function testTypIsCaseInsensitiveAndAcceptsMediaType(): void
    {
        foreach (['AT+JWT', 'application/at+jwt'] as $typ) {
            self::assertSame('usr_1', $this->verifier()->verify($this->keys->sign(TestKeys::accessClaims(), ['typ' => $typ]))->id);
        }
    }

    public function testRejectsOtherAlgorithms(): void
    {
        $claims = Base64Url::encode((string) json_encode(TestKeys::accessClaims()));
        // alg none
        $none = Base64Url::encode('{"alg":"none","typ":"at+jwt","kid":"k1"}') . '.' . $claims . '.';
        $this->assertRefused($none, 'token_invalid');
        // HS256 with the public key as the HMAC secret (algorithm confusion)
        $header = Base64Url::encode('{"alg":"HS256","typ":"at+jwt","kid":"k1"}');
        $secret = json_encode($this->keys->jwk);
        $hs = $header . '.' . $claims . '.' . Base64Url::encode(hash_hmac('sha256', $header . '.' . $claims, (string) $secret, true));
        $this->assertRefused($hs, 'token_invalid');
        // RS256 / ES384 labels with a valid ES256 signature
        $this->assertRefused($this->keys->sign(TestKeys::accessClaims(), ['alg' => 'RS256']), 'token_invalid');
        $this->assertRefused($this->keys->sign(TestKeys::accessClaims(), ['alg' => 'ES384']), 'token_invalid');
    }

    public function testRejectsWrongTypIssuerAudienceAndSignature(): void
    {
        $this->assertRefused($this->keys->sign(TestKeys::accessClaims(), ['typ' => 'JWT']), 'token_invalid');
        $this->assertRefused($this->keys->sign(TestKeys::accessClaims(), ['crit' => ['exp']]), 'token_invalid');
        $this->assertRefused($this->keys->sign(TestKeys::accessClaims(['iss' => TestKeys::ISSUER . '/'])), 'token_invalid');
        $this->assertRefused($this->keys->sign(TestKeys::accessClaims(['iss' => 'https://evil.example.com'])), 'token_invalid');
        $this->assertRefused($this->keys->sign(TestKeys::accessClaims(['aud' => 'uapp_other'])), 'token_other_app');
        $this->assertRefused($this->keys->sign(TestKeys::accessClaims(['sub' => ''])), 'token_invalid');

        $token = $this->keys->sign(TestKeys::accessClaims());
        [$h, $p, $s] = explode('.', $token);
        $tampered = $h . '.' . Base64Url::encode((string) json_encode(TestKeys::accessClaims(['roles' => ['admin']]))) . '.' . $s;
        $this->assertRefused($tampered, 'token_invalid');
        $other = new TestKeys('k1');                       // same kid, another key
        $this->assertRefused($other->sign(TestKeys::accessClaims()), 'token_invalid');
        $this->assertRefused('not-a-token', 'token_invalid');
        $this->assertRefused('', 'token_missing');
        $this->assertRefused($h . '.' . $p . '.' . Base64Url::encode(str_repeat("\x00", 64)), 'token_invalid');
    }

    public function testExpiryNotBeforeAndLeeway(): void
    {
        $this->assertRefused($this->keys->sign(TestKeys::accessClaims(['exp' => $this->now - 61])), 'token_expired');
        self::assertSame('usr_1', $this->verifier()->verify($this->keys->sign(TestKeys::accessClaims(['exp' => $this->now - 30])))->id);
        $this->assertRefused($this->keys->sign(TestKeys::accessClaims(['exp' => $this->now - 30])), 'token_expired', $this->verifier(['leeway' => 0]));
        $this->assertRefused($this->keys->sign(TestKeys::accessClaims(['nbf' => $this->now + 120])), 'token_invalid');
        $this->assertRefused($this->keys->sign(TestKeys::accessClaims(['iat' => $this->now + 120])), 'token_invalid');
        $claims = TestKeys::accessClaims();
        unset($claims['exp']);
        $this->assertRefused($this->keys->sign($claims), 'token_invalid');
    }

    public function testSeveralClientIds(): void
    {
        $verifier = new TokenVerifier(TestKeys::ISSUER, ['uapp_web', TestKeys::CLIENT], ['transport' => $this->http, 'cache' => new MemoryJwksCache()]);
        $user = $verifier->verify($this->keys->sign(TestKeys::accessClaims(['aud' => 'uapp_web'])));
        self::assertSame('uapp_web', $user->clientId);
    }

    public function testJwksIsCachedAndRefetchedOnUnknownKidAtMostEvery30Seconds(): void
    {
        $verifier = $this->verifier();
        $token = $this->keys->sign(TestKeys::accessClaims());
        $verifier->verify($token);
        $verifier->verify($token);
        self::assertCount(1, $this->http->to('GET', self::JWKS));

        // Key rotation: a new kid appears, but the last fetch is too recent.
        $rotated = new TestKeys('k2');
        $this->http->json('GET', self::JWKS, 200, TestKeys::jwks([$rotated, $this->keys]));
        $this->assertRefused($rotated->sign(TestKeys::accessClaims()), 'token_invalid', $verifier);
        self::assertCount(1, $this->http->to('GET', self::JWKS));

        $this->now += 31;
        self::assertSame('usr_1', $verifier->verify($rotated->sign(TestKeys::accessClaims([], $this->now)))->id);
        self::assertCount(2, $this->http->to('GET', self::JWKS));

        // An unknown kid again right after: no new fetch.
        $this->assertRefused((new TestKeys('k3'))->sign(TestKeys::accessClaims([], $this->now)), 'token_invalid', $verifier);
        self::assertCount(2, $this->http->to('GET', self::JWKS));
    }

    public function testJwksKeysOfOtherTypesAreIgnored(): void
    {
        $rsa = ['kty' => 'RSA', 'kid' => 'k1', 'n' => 'AQAB', 'e' => 'AQAB'];
        $wrongUse = $this->keys->jwk + [];
        $wrongUse['use'] = 'enc';
        $this->http->json('GET', self::JWKS, 200, ['keys' => [$rsa, $wrongUse]]);
        $this->assertRefused($this->keys->sign(TestKeys::accessClaims()), 'token_invalid');
    }

    public function testJwksUnavailable(): void
    {
        $this->http->fail('GET', self::JWKS);
        try {
            $this->verifier()->verify($this->keys->sign(TestKeys::accessClaims()));
            self::fail('accepted');
        } catch (AppAuthException $e) {
            self::assertSame(503, $e->status);
            self::assertSame('jwks_unavailable', $e->errorCode);
        }
    }

    public function testPsr16CacheIsUsed(): void
    {
        $cache = new class implements CacheInterface {
            public array $data = [];
            public function get(string $key, mixed $default = null): mixed { return $this->data[$key] ?? $default; }
            public function set(string $key, mixed $value, \DateInterval|int|null $ttl = null): bool { $this->data[$key] = $value; return true; }
            public function delete(string $key): bool { unset($this->data[$key]); return true; }
            public function clear(): bool { $this->data = []; return true; }
            public function getMultiple(iterable $keys, mixed $default = null): iterable { return []; }
            public function setMultiple(iterable $values, \DateInterval|int|null $ttl = null): bool { return true; }
            public function deleteMultiple(iterable $keys): bool { return true; }
            public function has(string $key): bool { return isset($this->data[$key]); }
        };
        $token = $this->keys->sign(TestKeys::accessClaims());
        $this->verifier(['cache' => $cache])->verify($token);
        $this->verifier(['cache' => $cache])->verify($token);     // a new verifier (another request) uses the cache
        self::assertCount(1, $this->http->to('GET', self::JWKS));
        $key = array_key_first($cache->data);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_]+$/', (string) $key, 'PSR-16 legal key');
    }

    public function testIdTokens(): void
    {
        $verifier = $this->verifier();
        $claims = $verifier->verifyIdToken($this->keys->idToken('n-123'), 'n-123');
        self::assertSame('Ada', $claims['name']);
        try {
            $verifier->verifyIdToken($this->keys->idToken('n-123'), 'other');
            self::fail('nonce mismatch accepted');
        } catch (AppAuthException $e) {
            self::assertSame('invalid_nonce', $e->errorCode);
        }
        // An access token is not an ID token, and the other way round.
        $this->expectException(AppAuthException::class);
        $verifier->verifyIdToken($this->keys->sign(TestKeys::accessClaims()));
    }

    public function testIdTokenIsNotAnAccessToken(): void
    {
        $this->assertRefused($this->keys->idToken('n'), 'token_invalid');
    }
}
