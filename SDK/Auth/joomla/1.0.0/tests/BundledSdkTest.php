<?php

declare(strict_types=1);

use OpenBackAppAuthJoomla\Sdk\AppAuthException;
use OpenBackAppAuthJoomla\Sdk\Cache\MemoryJwksCache;
use OpenBackAppAuthJoomla\Sdk\Http\HttpResponse;
use OpenBackAppAuthJoomla\Sdk\Http\HttpTransport;
use OpenBackAppAuthJoomla\Sdk\Internal\Base64Url;
use OpenBackAppAuthJoomla\Sdk\Internal\Ecdsa;
use OpenBackAppAuthJoomla\Sdk\OidcWebClient;
use OpenBackAppAuthJoomla\Sdk\TokenVerifier;
use PHPUnit\Framework\TestCase;

/** The bundled, namespace-prefixed SDK of the library verifies ES256 tokens and builds the authorize URL. */
final class BundledSdkTest extends TestCase
{
    private const ISSUER   = 'https://api.example.com/gateway/site/auth/main';
    private const CLIENT   = 'uapp_joomla';
    private const CALLBACK = 'https://site.example.com/index.php?option=com_ajax&group=system&plugin=openbackappauth&format=raw&task=callback';

    private static function key(): OpenSSLAsymmetricKey
    {
        $options = ['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC];
        $key = openssl_pkey_new($options);
        if ($key === false) {
            while (openssl_error_string() !== false) {
            }
            $config = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'openback-app-auth-test-openssl.cnf';
            file_put_contents($config, "[req]\ndefault_bits = 2048\n");
            $key = openssl_pkey_new($options + ['config' => $config]);
        }
        self::assertNotFalse($key);
        return $key;
    }

    private static function sign(OpenSSLAsymmetricKey $key, array $claims, array $header): string
    {
        $input = Base64Url::encode((string) json_encode($header)) . '.' . Base64Url::encode((string) json_encode($claims));
        openssl_sign($input, $der, $key, OPENSSL_ALGO_SHA256);
        return $input . '.' . Base64Url::encode(Ecdsa::derToJose($der));
    }

    public function testVerification(): void
    {
        $key = self::key();
        $details = openssl_pkey_get_details($key);
        $jwk = ['kty' => 'EC', 'crv' => 'P-256', 'kid' => 'k1', 'alg' => 'ES256', 'use' => 'sig',
            'x' => Base64Url::encode(str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT)),
            'y' => Base64Url::encode(str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT))];
        $http = new class ($jwk) implements HttpTransport {
            public function __construct(private array $jwk)
            {
            }

            public function send(string $method, string $url, array $headers = [], ?string $body = null): HttpResponse
            {
                return new HttpResponse(200, [], (string) json_encode(['keys' => [$this->jwk]]));
            }
        };
        MemoryJwksCache::clear();
        $verifier = new TokenVerifier(self::ISSUER, [self::CLIENT, 'uapp_mobile'], ['transport' => $http, 'cache' => new MemoryJwksCache()]);
        $now = time();
        $claims = ['iss' => self::ISSUER, 'sub' => 'usr_1', 'aud' => 'uapp_mobile', 'exp' => $now + 60, 'iat' => $now, 'pool' => 'upool_1', 'anon' => true];
        $user = $verifier->verify(self::sign($key, $claims, ['alg' => 'ES256', 'typ' => 'at+jwt', 'kid' => 'k1']));
        self::assertSame('uapp_mobile', $user->clientId);
        self::assertTrue($user->anonymous);

        $this->expectException(AppAuthException::class);
        $verifier->verify(self::sign($key, ['exp' => $now - 3600] + $claims, ['alg' => 'ES256', 'typ' => 'at+jwt', 'kid' => 'k1']));
    }

    public function testAuthorizeUrlCarriesTheComAjaxCallback(): void
    {
        $http = new class implements HttpTransport {
            public function send(string $method, string $url, array $headers = [], ?string $body = null): HttpResponse
            {
                return new HttpResponse(500);
            }
        };
        $oidc = new OidcWebClient(self::ISSUER, self::CLIENT, 'secret', self::CALLBACK, ['transport' => $http]);
        $request = $oidc->authorizationUrl(['uiLocales' => 'it', 'provider' => 'uprov_g']);
        parse_str((string) parse_url($request->url, PHP_URL_QUERY), $q);
        self::assertSame(self::CALLBACK, $q['redirect_uri']);
        self::assertSame('uprov_g', $q['provider']);
        // The pool appends code/state/iss with "&" to a redirect URI that already has a query: still the same route.
        self::assertStringContainsString('task=callback', self::CALLBACK . '&code=x&state=y');
    }
}
