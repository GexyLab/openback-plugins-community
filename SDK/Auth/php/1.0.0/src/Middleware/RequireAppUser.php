<?php

declare(strict_types=1);

namespace OpenBack\AppAuth\Middleware;

use OpenBack\AppAuth\AppAuthException;
use OpenBack\AppAuth\AppUser;
use OpenBack\AppAuth\TokenVerifier;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * PSR-15 middleware (needs psr/http-server-middleware): verifies `Authorization: Bearer <access token>` and attaches
 * the {@see AppUser} as the request attribute `AppUser::class` (or the `attribute` option).
 *
 * - missing / invalid / expired token: 401, `WWW-Authenticate: Bearer error="invalid_token"`, `{"error": "invalid_token"}`
 * - an option not met: 403 `{"error": "insufficient_scope"}`
 * - the pool's keys cannot be fetched: 503 `{"error": "temporarily_unavailable"}`
 *
 * Options: `requireRoles` (any of them), `requirePermissions` (all of them; "*" grants all), `requireVerifiedEmail`
 * (default false), `allowAnonymous` (default false: guest tokens `anon: true` are refused), `attribute`.
 */
final class RequireAppUser implements MiddlewareInterface
{
    /** @var string[] */
    private readonly array $requireRoles;
    /** @var string[] */
    private readonly array $requirePermissions;
    private readonly bool $requireVerifiedEmail;
    private readonly bool $allowAnonymous;
    private readonly string $attribute;

    /**
     * @param array{requireRoles?: string[], requirePermissions?: string[], requireVerifiedEmail?: bool,
     *              allowAnonymous?: bool, attribute?: string} $options
     */
    public function __construct(
        private readonly TokenVerifier $verifier,
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly StreamFactoryInterface $streamFactory,
        array $options = [],
    ) {
        $this->requireRoles = array_values(array_filter((array) ($options['requireRoles'] ?? []), 'is_string'));
        $this->requirePermissions = array_values(array_filter((array) ($options['requirePermissions'] ?? []), 'is_string'));
        $this->requireVerifiedEmail = (bool) ($options['requireVerifiedEmail'] ?? false);
        $this->allowAnonymous = (bool) ($options['allowAnonymous'] ?? false);
        $this->attribute = (string) ($options['attribute'] ?? AppUser::class);
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $token = self::bearer($request->getHeaderLine('Authorization'));
        if ($token === null) {
            return $this->unauthorized();
        }
        try {
            $user = $this->verifier->verify($token);
        } catch (AppAuthException $e) {
            if ($e->status === 503) {
                return $this->json(503, ['error' => 'temporarily_unavailable']);
            }
            return $this->unauthorized();
        }
        if (!$this->allowed($user)) {
            return $this->json(403, ['error' => 'insufficient_scope']);
        }
        return $handler->handle($request->withAttribute($this->attribute, $user));
    }

    /** Whether the user meets the options (also usable on its own). */
    public function allowed(AppUser $user): bool
    {
        if ($user->anonymous && !$this->allowAnonymous) {
            return false;
        }
        if ($this->requireVerifiedEmail && !$user->emailVerified) {
            return false;
        }
        if ($this->requireRoles !== [] && array_intersect($this->requireRoles, $user->roles) === []) {
            return false;
        }
        foreach ($this->requirePermissions as $permission) {
            if (!$user->hasPermission($permission)) {
                return false;
            }
        }
        return true;
    }

    /** The token of an `Authorization: Bearer <token>` header, or null. */
    public static function bearer(string $header): ?string
    {
        if (!preg_match('/^\s*Bearer\s+([A-Za-z0-9\-_.~+\/]+=*)\s*$/i', $header, $m)) {
            return null;
        }
        return $m[1];
    }

    private function unauthorized(): ResponseInterface
    {
        return $this->json(401, ['error' => 'invalid_token'])->withHeader('WWW-Authenticate', 'Bearer error="invalid_token"');
    }

    /** @param array<string, string> $body */
    private function json(int $status, array $body): ResponseInterface
    {
        return $this->responseFactory->createResponse($status)
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Cache-Control', 'no-store')
            ->withBody($this->streamFactory->createStream((string) json_encode($body)));
    }
}
