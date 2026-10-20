<?php

// The PSR-15 middleware in a Slim 4 app (composer require slim/slim nyholm/psr7 psr/http-server-middleware).

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Nyholm\Psr7\Factory\Psr17Factory;
use OpenBack\AppAuth\AppUser;
use OpenBack\AppAuth\Middleware\RequireAppUser;
use OpenBack\AppAuth\TokenVerifier;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Factory\AppFactory;

$verifier = new TokenVerifier('https://api.example.com/gateway/shop/auth/main', 'uapp_...', [
    // 'cache' => $psr16Cache,   // share the pool's keys between requests (APCu is used by default when enabled)
]);
$psr17 = new Psr17Factory();

$app = AppFactory::create();

$app->get('/orders', function (ServerRequestInterface $request, ResponseInterface $response): ResponseInterface {
    /** @var AppUser $user */
    $user = $request->getAttribute(AppUser::class);
    $response->getBody()->write(json_encode(['user' => $user->id, 'roles' => $user->roles]));
    return $response->withHeader('Content-Type', 'application/json');
})->add(new RequireAppUser($verifier, $psr17, $psr17, ['requirePermissions' => ['orders.read']]));

$app->delete('/orders/{id}', function (ServerRequestInterface $request, ResponseInterface $response): ResponseInterface {
    return $response->withStatus(204);
})->add(new RequireAppUser($verifier, $psr17, $psr17, ['requireRoles' => ['admin'], 'requireVerifiedEmail' => true]));

$app->run();
