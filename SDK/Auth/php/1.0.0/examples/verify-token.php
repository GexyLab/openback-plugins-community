<?php

// A plain PHP API endpoint protected by the pool's access tokens (no framework).
//   curl -H "Authorization: Bearer <access token>" https://your-api.example.com/orders.php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use OpenBack\AppAuth\AppAuthException;
use OpenBack\AppAuth\Middleware\RequireAppUser;
use OpenBack\AppAuth\TokenVerifier;

$verifier = new TokenVerifier(
    getenv('OPENBACK_ISSUER') ?: 'https://api.example.com/gateway/shop/auth/main',
    getenv('OPENBACK_CLIENT_ID') ?: 'uapp_...',   // the app(s) whose tokens this API accepts
);

header('Content-Type: application/json');
$token = RequireAppUser::bearer($_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
try {
    $user = $verifier->verify($token);
} catch (AppAuthException $e) {
    http_response_code($e->status === 503 ? 503 : 401);
    if ($e->status !== 503) {
        header('WWW-Authenticate: Bearer error="invalid_token"');
    }
    echo json_encode(['error' => $e->status === 503 ? 'temporarily_unavailable' : 'invalid_token']);
    exit;
}
if ($user->anonymous || !$user->hasPermission('orders.read')) {
    http_response_code(403);
    echo json_encode(['error' => 'insufficient_scope']);
    exit;
}
echo json_encode(['user' => $user->id, 'org' => $user->orgId, 'orders' => []]);
