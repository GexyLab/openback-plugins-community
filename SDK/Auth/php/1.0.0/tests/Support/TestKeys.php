<?php

declare(strict_types=1);

namespace OpenBack\AppAuth\Tests\Support;

use OpenBack\AppAuth\Internal\Base64Url;
use OpenBack\AppAuth\Internal\Ecdsa;

/** An ES256 (P-256) key pair generated with openssl_pkey_new, its JWK, and signed test tokens. */
final class TestKeys
{
    public const ISSUER = 'https://api.example.com/gateway/shop/auth/main';
    public const CLIENT = 'uapp_test0000000000000000';

    public readonly \OpenSSLAsymmetricKey $private;
    /** @var array<string, string> */
    public readonly array $jwk;

    public function __construct(public readonly string $kid = 'k1')
    {
        $options = ['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC];
        $key = openssl_pkey_new($options);
        if ($key === false) {
            // Some Windows builds have no default openssl.cnf: a minimal one is enough for key generation.
            while (openssl_error_string() !== false) {
            }
            $config = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'openback-app-auth-test-openssl.cnf';
            file_put_contents($config, "[req]\ndefault_bits = 2048\n");
            $key = openssl_pkey_new($options + ['config' => $config]);
        }
        if ($key === false) {
            throw new \RuntimeException('openssl_pkey_new failed: ' . openssl_error_string());
        }
        $this->private = $key;
        $details = openssl_pkey_get_details($key);
        $this->jwk = [
            'kty' => 'EC', 'crv' => 'P-256', 'kid' => $kid, 'alg' => 'ES256', 'use' => 'sig',
            'x' => Base64Url::encode(str_pad($details['ec']['x'], 32, "\x00", STR_PAD_LEFT)),
            'y' => Base64Url::encode(str_pad($details['ec']['y'], 32, "\x00", STR_PAD_LEFT)),
        ];
    }

    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $header
     */
    public function sign(array $claims, array $header = []): string
    {
        $header = $header + ['alg' => 'ES256', 'typ' => 'at+jwt', 'kid' => $this->kid];
        $input = Base64Url::encode((string) json_encode($header)) . '.' . Base64Url::encode((string) json_encode($claims));
        if (!openssl_sign($input, $der, $this->private, OPENSSL_ALGO_SHA256)) {
            throw new \RuntimeException('openssl_sign failed');
        }
        return $input . '.' . Base64Url::encode(Ecdsa::derToJose($der));
    }

    /** @param array<string, mixed> $overrides */
    public static function accessClaims(array $overrides = [], ?int $now = null): array
    {
        $now ??= time();
        return array_merge([
            'iss' => self::ISSUER, 'sub' => 'usr_1', 'aud' => self::CLIENT, 'azp' => self::CLIENT,
            'exp' => $now + 900, 'iat' => $now, 'jti' => 'at_1', 'sid' => 'sess_1', 'pool' => 'upool_1', 'sv' => 1,
            'org_id' => 'org_1', 'roles' => ['member'], 'permissions' => ['orders.read'], 'email' => 'ada@example.com',
            'email_verified' => true, 'amr' => ['pwd'], 'scope' => 'openid profile email',
        ], $overrides);
    }

    /** @param array<string, mixed> $overrides */
    public function idToken(string $nonce, ?string $accessToken = null, array $overrides = []): string
    {
        $now = time();
        $claims = array_merge([
            'iss' => self::ISSUER, 'sub' => 'usr_1', 'aud' => self::CLIENT, 'azp' => self::CLIENT, 'exp' => $now + 3600,
            'iat' => $now, 'auth_time' => $now, 'sid' => 'sess_1', 'pool' => 'upool_1', 'email' => 'ada@example.com',
            'email_verified' => true, 'name' => 'Ada', 'org_id' => 'org_1', 'roles' => ['member'], 'amr' => ['pwd'], 'nonce' => $nonce,
        ], $overrides);
        if ($accessToken !== null && !array_key_exists('at_hash', $overrides)) {
            $claims['at_hash'] = Base64Url::encode(substr(hash('sha256', $accessToken, true), 0, 16));
        }
        return $this->sign($claims, ['typ' => 'JWT']);
    }

    /** @param TestKeys[] $keys */
    public static function jwks(array $keys): array
    {
        return ['keys' => array_map(static fn (TestKeys $k) => $k->jwk, $keys)];
    }
}
