<?php

declare(strict_types=1);

namespace OpenBack\AppAuth\Tests;

use OpenBack\AppAuth\AppAuthException;
use OpenBack\AppAuth\Cache\MemoryJwksCache;
use OpenBack\AppAuth\Client;
use OpenBack\AppAuth\Http\HttpResponse;
use OpenBack\AppAuth\Lock\RefreshLock;
use OpenBack\AppAuth\OutcomeStatus;
use OpenBack\AppAuth\Storage\MemoryStorage;
use OpenBack\AppAuth\Tests\Support\FakeTransport;
use OpenBack\AppAuth\Tests\Support\TestKeys;
use PHPUnit\Framework\TestCase;

final class ClientTest extends TestCase
{
    private const API = TestKeys::ISSUER . '/api/v1';
    private const KEY = 'openback.auth.' . TestKeys::CLIENT;

    private FakeTransport $http;
    private MemoryStorage $storage;
    private int $now;

    protected function setUp(): void
    {
        MemoryJwksCache::clear();
        $this->http = new FakeTransport();
        $this->storage = new MemoryStorage();
        $this->now = 1_800_000_000;
    }

    private function client(array $options = []): Client
    {
        return new Client(TestKeys::ISSUER . '/', TestKeys::CLIENT, $options + [
            'transport' => $this->http, 'storage' => $this->storage, 'clock' => fn () => $this->now,
        ]);
    }

    private static function ok(string $access = 'at1', string $refresh = 'obur_1'): array
    {
        return ['status' => 'ok', 'access_token' => $access, 'refresh_token' => $refresh, 'expires_in' => 900,
            'user' => ['id' => 'usr_1', 'email' => 'ada@example.com'], 'org' => null];
    }

    private function signedIn(): Client
    {
        $this->http->json('POST', self::API . '/signin/password', 200, self::ok());
        $client = $this->client();
        $client->signInWithPassword('ada@example.com', 'pw');
        return $client;
    }

    public function testSignInWithPasswordKeepsTheSession(): void
    {
        $client = $this->signedIn();
        $call = $this->http->last();
        self::assertSame(TestKeys::CLIENT, $call['headers']['X-Client-Id']);
        self::assertSame('application/json', $call['headers']['Content-Type']);
        self::assertArrayNotHasKey('Origin', $call['headers']);
        self::assertSame(['email' => 'ada@example.com', 'password' => 'pw'], json_decode((string) $call['body'], true));

        self::assertTrue($client->isSignedIn());
        self::assertSame('usr_1', $client->currentUser()['id']);
        $stored = json_decode((string) $this->storage->get(self::KEY), true);
        self::assertSame(['accessToken', 'refreshToken', 'idToken', 'expiresAt', 'user', 'org'], array_keys($stored));
        self::assertSame(($this->now + 900) * 1000, $stored['expiresAt']);
        self::assertSame('at1', $client->getAccessToken());
        self::assertCount(1, $this->http->requests, 'fresh token: no refresh');

        // A new Client on the same storage resumes the session.
        self::assertSame('usr_1', $this->client()->currentUser()['id']);
    }

    public function testMfaBranch(): void
    {
        $this->http->json('POST', self::API . '/signin/password', 200, ['status' => 'mfa_required', 'mfa_token' => 'mfa_1']);
        $this->http->json('POST', self::API . '/signin/mfa', 200, self::ok());
        $client = $this->client();
        $res = $client->signInWithPassword('ada@example.com', 'pw');
        self::assertSame(OutcomeStatus::MfaRequired, $res->status);
        self::assertSame('mfa_1', $res->mfaToken);
        self::assertFalse($client->isSignedIn());
        $res = $client->verifyMfa($res->mfaToken, '123456');
        self::assertTrue($res->isOk());
        self::assertTrue($client->isSignedIn());
        self::assertSame(['mfa_token' => 'mfa_1', 'code' => '123456'], json_decode((string) $this->http->last()['body'], true));
    }

    public function testOtherOutcomesDoNotSignIn(): void
    {
        $this->http->json('POST', self::API . '/signup', 200, ['status' => 'verification_required', 'email' => 'ada@example.com']);
        $this->http->json('POST', self::API . '/signin/email-code/verify', 200, ['status' => 'password_change_required', 'change_token' => 'chg_1']);
        $this->http->json('POST', self::API . '/signin/anonymous', 200, ['status' => 'something_new']);
        $client = $this->client();
        self::assertSame(OutcomeStatus::VerificationRequired, $client->signUp('ada@example.com', 'pw', 'Ada')->status);
        self::assertSame('chg_1', $client->signInWithEmailCode('ada@example.com', '123456')->changeToken);
        $unknown = $client->signInAnonymously();
        self::assertSame(OutcomeStatus::Unknown, $unknown->status);
        self::assertSame('something_new', $unknown->rawStatus);
        self::assertSame('{}', $this->http->last()['body']);
        self::assertFalse($client->isSignedIn());
    }

    public function testRefreshRotatesAndStoresTheNewRefreshToken(): void
    {
        $client = $this->signedIn();
        $this->http->json('POST', self::API . '/token/refresh', 200, ['access_token' => 'at2', 'refresh_token' => 'obur_2', 'expires_in' => 900]);
        $this->now += 900 - 59;                       // expires within 60 s
        self::assertSame('at2', $client->getAccessToken());
        self::assertSame(['refresh_token' => 'obur_1'], json_decode((string) $this->http->last()['body'], true));
        $stored = json_decode((string) $this->storage->get(self::KEY), true);
        self::assertSame('obur_2', $stored['refreshToken']);
        self::assertSame('usr_1', $stored['user']['id'], 'user kept across refresh');
        self::assertSame('at2', $client->getAccessToken());
        self::assertCount(1, $this->http->to('POST', self::API . '/token/refresh'));
    }

    public function testRefreshUsesTheTokenAnotherProcessAlreadyRenewed(): void
    {
        $client = $this->signedIn();
        // Another process refreshed meanwhile and stored new tokens.
        $other = json_decode((string) $this->storage->get(self::KEY), true);
        $other['accessToken'] = 'at-other';
        $other['refreshToken'] = 'obur_other';
        $other['expiresAt'] = ($this->now + 2000) * 1000;
        $this->storage->set(self::KEY, (string) json_encode($other));
        $this->now += 900;
        self::assertSame('at-other', $client->getAccessToken());
        self::assertCount(0, $this->http->to('POST', self::API . '/token/refresh'));
    }

    public function testRefreshRunsInsideTheLock(): void
    {
        $lock = new class implements RefreshLock {
            public array $names = [];
            public function synchronized(string $name, callable $critical): mixed { $this->names[] = $name; return $critical(); }
        };
        $this->http->json('POST', self::API . '/signin/password', 200, self::ok());
        $client = $this->client(['lock' => $lock]);
        $client->signInWithPassword('a@example.com', 'pw');
        $this->http->json('POST', self::API . '/token/refresh', 200, ['access_token' => 'at2', 'refresh_token' => 'obur_2', 'expires_in' => 900]);
        $client->refresh();
        self::assertSame([self::KEY . '.refresh'], $lock->names);
    }

    public function testRefusedRefreshEndsTheSessionAndNotifies(): void
    {
        $client = $this->signedIn();
        $events = [];
        $unsubscribe = $client->onAuthStateChanged(static function (?array $user, ?array $org) use (&$events) {
            $events[] = $user['id'] ?? null;
        });
        self::assertSame(['usr_1'], $events, 'called immediately');
        $this->http->json('POST', self::API . '/token/refresh', 401, ['detail' => ['code' => 'invalid_refresh_token', 'message' => 'Session expired']]);
        try {
            $client->refresh();
            self::fail('refresh accepted');
        } catch (AppAuthException $e) {
            self::assertSame('invalid_refresh_token', $e->errorCode);
            self::assertTrue($e->endsSession());
        }
        self::assertFalse($client->isSignedIn());
        self::assertNull($this->storage->get(self::KEY));
        self::assertSame(['usr_1', null], $events);
        $unsubscribe();
        $this->signedIn();
        self::assertSame(['usr_1', null], $events, 'unsubscribed');
    }

    public function testNetworkErrorOnRefreshIsNotRetriedAndKeepsTheSession(): void
    {
        $client = $this->signedIn();
        $this->http->fail('POST', self::API . '/token/refresh');
        try {
            $client->refresh();
            self::fail('no error');
        } catch (AppAuthException $e) {
            self::assertSame('network_error', $e->errorCode);
        }
        self::assertCount(1, $this->http->to('POST', self::API . '/token/refresh'));
        self::assertTrue($client->isSignedIn());
    }

    public function testTokenErrorOnASignedInCallClearsTheSession(): void
    {
        $client = $this->signedIn();
        $this->http->json('GET', self::API . '/me', 401, ['detail' => ['code' => 'token_revoked', 'message' => 'Sign-in required']]);
        try {
            $client->me();
            self::fail('accepted');
        } catch (AppAuthException $e) {
            self::assertSame('token_revoked', $e->errorCode);
        }
        self::assertFalse($client->isSignedIn());
        self::assertSame('Bearer at1', $this->http->last()['headers']['Authorization']);
    }

    private static function error(callable $call): AppAuthException
    {
        try {
            $call();
        } catch (AppAuthException $e) {
            return $e;
        }
        self::fail('no AppAuthException');
    }

    public function testErrorMapping(): void
    {
        $client = $this->client();
        $this->http->json('POST', self::API . '/signup', 422, ['detail' => ['code' => 'weak_password', 'message' => 'Weak', 'problems' => ['length']]]);
        $e = self::error(fn () => $client->signUp('a@example.com', 'x'));
        self::assertSame([422, 'weak_password', 'Weak', ['length']], [$e->status, $e->errorCode, $e->getMessage(), $e->detail['problems']]);

        $this->http->json('POST', self::API . '/signup', 422, ['detail' => [['loc' => ['body', 'email'], 'msg' => 'value is not a valid email']]]);
        $e = self::error(fn () => $client->signUp('bad', 'x'));
        self::assertSame(['http_422', 'value is not a valid email'], [$e->errorCode, $e->getMessage()]);

        $this->http->json('GET', self::API . '/config', 404, ['detail' => 'Pool not found']);
        $e = self::error(fn () => $client->config());
        self::assertSame(['http_404', 'Pool not found', 404], [$e->errorCode, $e->getMessage(), $e->getCode()]);

        $this->http->on('GET', self::API . '/config', static fn () => new HttpResponse(502, [], '<html>bad gateway</html>'));
        self::assertSame('http_502', self::error(fn () => $client->config())->errorCode);

        $this->http->json('POST', self::API . '/signin/password', 429, ['detail' => ['code' => 'too_many_requests', 'message' => 'Slow down']]);
        $e = self::error(fn () => $client->signInWithPassword('a@example.com', 'x'));
        self::assertSame([429, 'too_many_requests'], [$e->status, $e->errorCode]);
        self::assertFalse($e->endsSession());
    }

    public function testSignOutAlwaysClearsLocally(): void
    {
        $client = $this->signedIn();
        $this->http->fail('POST', self::API . '/signout');
        $client->signOut(true);
        self::assertFalse($client->isSignedIn());
        $call = $this->http->last();
        self::assertSame(['refresh_token' => 'obur_1', 'everywhere' => true], json_decode((string) $call['body'], true));
        self::assertSame('Bearer at1', $call['headers']['Authorization']);
    }

    public function testChangePasswordAndDeleteAccountClear(): void
    {
        $client = $this->signedIn();
        $this->http->json('POST', self::API . '/me/password', 200, ['status' => 'password_changed']);
        $client->changePassword('new-password', 'old');
        self::assertFalse($client->isSignedIn());
        $client = $this->signedIn();
        $this->http->json('DELETE', self::API . '/me', 200, ['status' => 'deleted']);
        $client->deleteAccount('pw');
        self::assertFalse($client->isSignedIn());
        self::assertSame(['password' => 'pw'], json_decode((string) $this->http->last()['body'], true));
    }

    public function testOrganizations(): void
    {
        $client = $this->signedIn();
        $this->http->json('POST', self::API . '/orgs/switch', 200, ['access_token' => 'at-b', 'refresh_token' => 'obur_b', 'expires_in' => 900,
            'org' => ['id' => 'org_b', 'name' => 'B', 'roles' => ['admin'], 'choices' => 2]]);
        self::assertSame('org_b', $client->switchOrganization('org_b')['id']);
        self::assertSame(['org_id' => 'org_b', 'refresh_token' => 'obur_1'], json_decode((string) $this->http->last()['body'], true));
        self::assertSame('obur_b', json_decode((string) $this->storage->get(self::KEY), true)['refreshToken']);

        $this->http->json('GET', self::API . '/orgs/org%2Fx/members', 200, ['items' => [], 'roles' => []]);
        $client->members('org/x', 'ada smith', 10, 20);
        self::assertSame(self::API . '/orgs/org%2Fx/members?q=ada%20smith&skip=10&limit=20', $this->http->last()['url']);
        self::assertSame('Bearer at-b', $this->http->last()['headers']['Authorization']);
    }

    public function testHostedSignInRoundTrip(): void
    {
        $keys = new TestKeys();
        $this->http->json('GET', TestKeys::ISSUER . '/.well-known/jwks.json', 200, TestKeys::jwks([$keys]));
        $client = $this->client(['redirectUri' => 'com.example.app:/callback', 'clock' => static fn () => time()]);
        $req = $client->buildAuthorizationRequest(['provider' => 'uprov_g']);
        self::assertNotNull($this->storage->get(self::KEY . '.pkce'));
        $access = $keys->sign(TestKeys::accessClaims());
        $this->http->json('POST', TestKeys::ISSUER . '/token', 200, ['access_token' => $access, 'token_type' => 'Bearer', 'expires_in' => 900,
            'refresh_token' => 'obur_h', 'id_token' => $keys->idToken($req->nonce(), $access)]);
        $this->http->json('GET', self::API . '/me', 200, ['id' => 'usr_1', 'email' => 'ada@example.com']);

        $url = 'com.example.app:/callback?code=abc&state=' . rawurlencode($req->state()) . '&iss=' . rawurlencode(TestKeys::ISSUER);
        $user = $client->handleRedirectCallback($url);
        self::assertSame('usr_1', $user['id']);
        self::assertTrue($client->isSignedIn());
        self::assertNull($this->storage->get(self::KEY . '.pkce'), 'transaction used once');
        parse_str((string) $this->http->to('POST', TestKeys::ISSUER . '/token')[0]['body'], $form);
        self::assertSame($req->codeVerifier(), $form['code_verifier']);
        self::assertArrayNotHasKey('Authorization', $this->http->to('POST', TestKeys::ISSUER . '/token')[0]['headers'], 'public client');

        $logout = $client->signOutRedirect('com.example.app:/signed-out');
        parse_str((string) parse_url($logout, PHP_URL_QUERY), $q);
        self::assertSame($client->isSignedIn(), false);
        self::assertSame(TestKeys::CLIENT, $q['client_id']);
        self::assertSame('com.example.app:/signed-out', $q['post_logout_redirect_uri']);
        self::assertArrayHasKey('id_token_hint', $q);

        // A replayed callback has no transaction any more.
        $this->expectException(AppAuthException::class);
        $client->handleRedirectCallback($url);
    }

    public function testHandleRedirectCallbackWithoutParamsIsNull(): void
    {
        self::assertNull($this->client()->handleRedirectCallback('https://shop.example.com/'));
    }

    public function testFetchAddsTheBearer(): void
    {
        $client = $this->signedIn();
        $this->http->json('GET', 'https://api.example.com/gateway/shop/orders', 200, []);
        $client->fetch('GET', 'https://api.example.com/gateway/shop/orders', ['Accept' => 'application/json']);
        self::assertSame('Bearer at1', $this->http->last()['headers']['Authorization']);
    }

    public function testNotSignedIn(): void
    {
        $e = self::error(fn () => $this->client()->getAccessToken());
        self::assertSame([401, 'not_signed_in'], [$e->status, $e->errorCode]);
    }
}
