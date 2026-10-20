<?php

declare(strict_types=1);

namespace OpenBack\AppAuth\Tests;

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use OpenBack\AppAuth\AppUser;
use OpenBack\AppAuth\Cache\MemoryJwksCache;
use OpenBack\AppAuth\Middleware\RequireAppUser;
use OpenBack\AppAuth\TokenVerifier;
use OpenBack\AppAuth\Tests\Support\FakeTransport;
use OpenBack\AppAuth\Tests\Support\TestKeys;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class RequireAppUserTest extends TestCase
{
    private TestKeys $keys;
    private TokenVerifier $verifier;
    private ?AppUser $seen = null;

    protected function setUp(): void
    {
        MemoryJwksCache::clear();
        $this->keys = new TestKeys();
        $http = (new FakeTransport())->json('GET', TestKeys::ISSUER . '/.well-known/jwks.json', 200, TestKeys::jwks([$this->keys]));
        $this->verifier = new TokenVerifier(TestKeys::ISSUER, TestKeys::CLIENT, ['transport' => $http, 'cache' => new MemoryJwksCache()]);
    }

    private function call(?string $authorization, array $options = []): ResponseInterface
    {
        $factory = new Psr17Factory();
        $middleware = new RequireAppUser($this->verifier, $factory, $factory, $options);
        $request = new ServerRequest('GET', 'https://api.example.com/orders');
        if ($authorization !== null) {
            $request = $request->withHeader('Authorization', $authorization);
        }
        $handler = new class ($this) implements RequestHandlerInterface {
            public function __construct(private readonly RequireAppUserTest $test)
            {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->test->saw($request->getAttribute(AppUser::class));
                return new Response(200, [], 'ok');
            }
        };
        return $middleware->process($request, $handler);
    }

    public function saw(?AppUser $user): void
    {
        $this->seen = $user;
    }

    private function token(array $overrides = []): string
    {
        return 'Bearer ' . $this->keys->sign(TestKeys::accessClaims($overrides));
    }

    public function testAttachesTheUser(): void
    {
        $response = $this->call($this->token());
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('usr_1', $this->seen?->id);
    }

    public function testMissingOrInvalidTokenIs401(): void
    {
        foreach ([null, 'Basic abc', 'Bearer ', 'Bearer not.a.token', $this->token(['exp' => time() - 3600])] as $header) {
            $response = $this->call($header);
            self::assertSame(401, $response->getStatusCode());
            self::assertSame('Bearer error="invalid_token"', $response->getHeaderLine('WWW-Authenticate'));
            self::assertSame(['error' => 'invalid_token'], json_decode((string) $response->getBody(), true));
        }
        self::assertNull($this->seen);
    }

    public function testOptionsAre403(): void
    {
        $forbidden = static fn (ResponseInterface $r) => $r->getStatusCode() === 403
            && json_decode((string) $r->getBody(), true) === ['error' => 'insufficient_scope'];
        self::assertTrue($forbidden($this->call($this->token(['anon' => true]))));
        self::assertSame(200, $this->call($this->token(['anon' => true]), ['allowAnonymous' => true])->getStatusCode());
        self::assertTrue($forbidden($this->call($this->token(['email_verified' => false]), ['requireVerifiedEmail' => true])));
        // roles: any of them
        self::assertSame(200, $this->call($this->token(['roles' => ['member']]), ['requireRoles' => ['admin', 'member']])->getStatusCode());
        self::assertTrue($forbidden($this->call($this->token(['roles' => ['member']]), ['requireRoles' => ['admin']])));
        // permissions: all of them, "*" grants all
        self::assertTrue($forbidden($this->call($this->token(['permissions' => ['a']]), ['requirePermissions' => ['a', 'b']])));
        self::assertSame(200, $this->call($this->token(['permissions' => ['a', 'b']]), ['requirePermissions' => ['a', 'b']])->getStatusCode());
        self::assertSame(200, $this->call($this->token(['permissions' => ['*']]), ['requirePermissions' => ['a', 'b']])->getStatusCode());
    }
}
