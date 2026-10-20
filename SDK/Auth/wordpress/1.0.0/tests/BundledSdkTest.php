<?php

declare(strict_types=1);

use OpenBackAppAuthWp\Sdk\AppAuthException;
use OpenBackAppAuthWp\Sdk\Cache\MemoryJwksCache;
use OpenBackAppAuthWp\Sdk\Http\HttpResponse;
use OpenBackAppAuthWp\Sdk\Http\HttpTransport;
use OpenBackAppAuthWp\Sdk\Internal\Base64Url;
use OpenBackAppAuthWp\Sdk\Internal\Ecdsa;
use OpenBackAppAuthWp\Sdk\OidcWebClient;
use OpenBackAppAuthWp\Sdk\TokenVerifier;
use PHPUnit\Framework\TestCase;

/** The bundled, namespace-prefixed SDK loads through the plugin's autoloader and verifies ES256 tokens. */
final class BundledSdkTest extends TestCase
{
	private const ISSUER = 'https://api.example.com/gateway/site/auth/main';
	private const CLIENT = 'uapp_wp';

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

	public function testPrefixedClassesAndVerification(): void
	{
		self::assertFalse(class_exists('OpenBack\\AppAuth\\TokenVerifier', false), 'the unprefixed namespace is not used');
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
		$verifier = new TokenVerifier(self::ISSUER, self::CLIENT, ['transport' => $http, 'cache' => new MemoryJwksCache()]);
		$now = time();
		$claims = ['iss' => self::ISSUER, 'sub' => 'usr_1', 'aud' => self::CLIENT, 'exp' => $now + 60, 'iat' => $now, 'pool' => 'upool_1', 'roles' => ['member']];
		$user = $verifier->verify(self::sign($key, $claims, ['alg' => 'ES256', 'typ' => 'at+jwt', 'kid' => 'k1']));
		self::assertSame('usr_1', $user->id);
		self::assertSame('upool_1', $user->poolId);

		$id = $verifier->verifyIdToken(self::sign($key, $claims + ['nonce' => 'n1'], ['alg' => 'ES256', 'typ' => 'JWT', 'kid' => 'k1']), 'n1');
		self::assertSame('usr_1', $id['sub']);

		$this->expectException(AppAuthException::class);
		$verifier->verify(self::sign($key, ['aud' => 'uapp_other'] + $claims, ['alg' => 'ES256', 'typ' => 'at+jwt', 'kid' => 'k1']));
	}

	public function testOidcClientUsesTheRegisteredRedirectUri(): void
	{
		$http = new class implements HttpTransport {
			public function send(string $method, string $url, array $headers = [], ?string $body = null): HttpResponse
			{
				return new HttpResponse(500);
			}
		};
		$oidc = new OidcWebClient(self::ISSUER, self::CLIENT, 'secret', 'https://site.example.com/wp-json/openback-app-auth/v1/callback', ['transport' => $http]);
		$request = $oidc->authorizationUrl(['scope' => 'openid profile email', 'uiLocales' => 'it']);
		parse_str((string) parse_url($request->url, PHP_URL_QUERY), $q);
		self::assertSame('https://site.example.com/wp-json/openback-app-auth/v1/callback', $q['redirect_uri']);
		self::assertSame('S256', $q['code_challenge_method']);
		self::assertSame('it', $q['ui_locales']);
		$tx = $request->transaction->toArray() + ['redirect_to' => '/x', 'link_user' => 0];   // as the plugin stores it
		self::assertSame($request->state(), $tx['state']);
	}
}
