<?php

declare(strict_types=1);

namespace OpenBack\AppAuth\Tests;

use OpenBack\AppAuth\AppAuthException;
use OpenBack\AppAuth\AuthTransaction;
use OpenBack\AppAuth\Cache\MemoryJwksCache;
use OpenBack\AppAuth\Http\HttpResponse;
use OpenBack\AppAuth\Internal\Base64Url;
use OpenBack\AppAuth\OidcWebClient;
use OpenBack\AppAuth\Tests\Support\FakeTransport;
use OpenBack\AppAuth\Tests\Support\TestKeys;
use PHPUnit\Framework\TestCase;

final class OidcWebClientTest extends TestCase
{
    private const REDIRECT = 'https://shop.example.com/auth/callback';
    private const SECRET = 'sec:ret/with+chars';

    private TestKeys $keys;
    private FakeTransport $http;
    /** @var array<string, mixed>|null */
    private ?array $tokenAnswer = null;

    protected function setUp(): void
    {
        MemoryJwksCache::clear();
        $this->keys = new TestKeys();
        $this->http = (new FakeTransport())
            ->json('GET', TestKeys::ISSUER . '/.well-known/jwks.json', 200, TestKeys::jwks([$this->keys]))
            ->on('POST', TestKeys::ISSUER . '/token', fn () => new HttpResponse(200, [], (string) json_encode($this->tokenAnswer)));
    }

    private function client(array $options = []): OidcWebClient
    {
        return new OidcWebClient(TestKeys::ISSUER, TestKeys::CLIENT, self::SECRET, self::REDIRECT, $options + ['transport' => $this->http]);
    }

    private function answerFor(AuthTransaction $tx, array $idOverrides = []): void
    {
        $access = $this->keys->sign(TestKeys::accessClaims());
        $this->tokenAnswer = ['access_token' => $access, 'token_type' => 'Bearer', 'expires_in' => 900, 'scope' => 'openid profile email',
            'refresh_token' => 'obur_abc', 'refresh_expires_in' => 1209600, 'id_token' => $this->keys->idToken($tx->nonce, $access, $idOverrides)];
    }

    public function testAuthorizationUrl(): void
    {
        $req = $this->client()->authorizationUrl(['provider' => 'uprov_1', 'orgId' => 'org_9', 'prompt' => 'login', 'screenHint' => 'signup',
            'loginHint' => 'ada@example.com', 'maxAge' => 300, 'uiLocales' => 'it']);
        self::assertStringStartsWith(TestKeys::ISSUER . '/authorize?', $req->url);
        parse_str((string) parse_url($req->url, PHP_URL_QUERY), $q);
        self::assertSame('code', $q['response_type']);
        self::assertSame(TestKeys::CLIENT, $q['client_id']);
        self::assertSame(self::REDIRECT, $q['redirect_uri']);
        self::assertSame('openid profile email', $q['scope']);
        self::assertSame('S256', $q['code_challenge_method']);
        self::assertSame(Base64Url::encode(hash('sha256', $req->codeVerifier(), true)), $q['code_challenge']);
        self::assertSame($req->state(), $q['state']);
        self::assertSame($req->nonce(), $q['nonce']);
        self::assertSame(['uprov_1', 'org_9', 'login', 'signup', 'ada@example.com', '300', 'it'],
            [$q['provider'], $q['org_id'], $q['prompt'], $q['screen_hint'], $q['login_hint'], $q['max_age'], $q['ui_locales']]);
        self::assertGreaterThanOrEqual(43, strlen($req->codeVerifier()));
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $req->codeVerifier());
        self::assertNotSame($req->state(), $this->client()->authorizationUrl()->state());
    }

    public function testScopeAlwaysHasOpenid(): void
    {
        $req = $this->client(['scope' => 'profile email offline_access'])->authorizationUrl();
        parse_str((string) parse_url($req->url, PHP_URL_QUERY), $q);
        self::assertSame('openid profile email offline_access', $q['scope']);
    }

    public function testHandleCallbackWithBasicAuth(): void
    {
        $client = $this->client();
        $req = $client->authorizationUrl();
        $this->answerFor($req->transaction);
        $stored = $req->transaction->toArray();          // as kept in a session
        $tokens = $client->handleCallback(['code' => 'c-1', 'state' => $req->state(), 'iss' => TestKeys::ISSUER], $stored);
        self::assertSame('obur_abc', $tokens->refreshToken);
        self::assertSame('usr_1', $tokens->idTokenClaims['sub']);
        self::assertSame(900, $tokens->expiresIn);

        $call = $this->http->to('POST', TestKeys::ISSUER . '/token')[0];
        self::assertSame('Basic ' . base64_encode(rawurlencode(TestKeys::CLIENT) . ':' . rawurlencode(self::SECRET)), $call['headers']['Authorization']);
        parse_str((string) $call['body'], $form);
        self::assertSame(['grant_type' => 'authorization_code', 'code' => 'c-1', 'redirect_uri' => self::REDIRECT,
            'code_verifier' => $req->codeVerifier(), 'client_id' => TestKeys::CLIENT], $form);
        self::assertArrayNotHasKey('client_secret', $form);
    }

    public function testClientSecretPost(): void
    {
        $client = $this->client(['authMethod' => 'client_secret_post']);
        $req = $client->authorizationUrl();
        $this->answerFor($req->transaction);
        $client->handleCallback(['code' => 'c-1', 'state' => $req->state()], $req->transaction);
        $call = $this->http->to('POST', TestKeys::ISSUER . '/token')[0];
        self::assertArrayNotHasKey('Authorization', $call['headers']);
        parse_str((string) $call['body'], $form);
        self::assertSame(self::SECRET, $form['client_secret']);
    }

    /** @return iterable<string, array{0: array<string, string>, 1: string, 2?: array<string, mixed>}> */
    public static function badCallbacks(): iterable
    {
        yield 'state mismatch' => [['code' => 'c', 'state' => 'other'], 'invalid_state'];
        yield 'no state' => [['code' => 'c'], 'invalid_state'];
        yield 'issuer mismatch' => [['code' => 'c', 'state' => '{state}', 'iss' => 'https://evil.example.com'], 'invalid_issuer'];
        yield 'error' => [['error' => 'access_denied', 'error_description' => 'no', 'state' => '{state}'], 'access_denied'];
        yield 'login required' => [['error' => 'login_required', 'state' => '{state}'], 'login_required'];
        yield 'no code' => [['state' => '{state}'], 'invalid_request'];
        yield 'nonce mismatch' => [['code' => 'c', 'state' => '{state}'], 'invalid_nonce', ['nonce' => 'wrong']];
        yield 'at_hash mismatch' => [['code' => 'c', 'state' => '{state}'], 'invalid_at_hash', ['at_hash' => 'AAAAAAAAAAAAAAAAAAAAAA']];
        yield 'id token of another app' => [['code' => 'c', 'state' => '{state}'], 'token_other_app', ['aud' => 'uapp_other']];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('badCallbacks')]
    public function testHandleCallbackRefuses(array $params, string $code, array $idOverrides = []): void
    {
        $client = $this->client();
        $req = $client->authorizationUrl();
        $this->answerFor($req->transaction, $idOverrides);
        $params = array_map(static fn ($v) => $v === '{state}' ? $req->state() : $v, $params);
        try {
            $client->handleCallback($params, $req->transaction);
            self::fail('callback accepted');
        } catch (AppAuthException $e) {
            self::assertSame($code, $e->errorCode);
        }
    }

    public function testTokenEndpointErrors(): void
    {
        $this->http->json('POST', TestKeys::ISSUER . '/token', 400, ['error' => 'invalid_grant', 'error_description' => 'invalid or expired code']);
        $client = $this->client();
        $req = $client->authorizationUrl();
        try {
            $client->handleCallback(['code' => 'c', 'state' => $req->state()], $req->transaction);
            self::fail('accepted');
        } catch (AppAuthException $e) {
            self::assertSame(400, $e->status);
            self::assertSame('invalid_grant', $e->errorCode);
            self::assertSame('invalid or expired code', $e->getMessage());
        }
    }

    public function testRefreshRevokeUserinfoAndLogout(): void
    {
        $this->tokenAnswer = ['access_token' => 'at2', 'token_type' => 'Bearer', 'expires_in' => 600, 'refresh_token' => 'obur_new',
            'org' => ['id' => 'org_2', 'name' => 'B']];
        $client = $this->client();
        $tokens = $client->refresh('obur_old', 'org_2');
        self::assertSame('obur_new', $tokens->refreshToken);
        self::assertSame('org_2', $tokens->org['id']);
        self::assertNull($tokens->idTokenClaims);
        parse_str((string) $this->http->last()['body'], $form);
        self::assertSame(['grant_type' => 'refresh_token', 'refresh_token' => 'obur_old', 'org_id' => 'org_2', 'client_id' => TestKeys::CLIENT], $form);

        $this->http->on('POST', TestKeys::ISSUER . '/revoke', static fn () => new HttpResponse(200));
        $client->revoke('obur_new');
        parse_str((string) $this->http->last()['body'], $form);
        self::assertSame('obur_new', $form['token']);
        self::assertStringStartsWith('Basic ', $this->http->last()['headers']['Authorization']);

        $this->http->json('GET', TestKeys::ISSUER . '/userinfo', 200, ['sub' => 'usr_1', 'email' => 'ada@example.com']);
        self::assertSame('usr_1', $client->userinfo('at2')['sub']);
        self::assertSame('Bearer at2', $this->http->last()['headers']['Authorization']);

        $url = $client->logoutUrl('id.tok.en', 'https://shop.example.com/', 'xyz');
        parse_str((string) parse_url($url, PHP_URL_QUERY), $q);
        self::assertStringStartsWith(TestKeys::ISSUER . '/logout?', $url);
        self::assertSame(['client_id' => TestKeys::CLIENT, 'id_token_hint' => 'id.tok.en', 'post_logout_redirect_uri' => 'https://shop.example.com/', 'state' => 'xyz'], $q);
    }
}
