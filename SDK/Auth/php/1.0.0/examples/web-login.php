<?php

// Sign-in with the pool's hosted page for a `web` app (server-rendered PHP site).
// Register in the pool's Apps tab: kind "web", redirect URI https://shop.example.com/web-login.php?step=callback,
// post-logout redirect URI https://shop.example.com/. Keep the client secret out of the code (environment, vault).
//   /web-login.php?step=login     -> hosted page
//   /web-login.php?step=callback  -> back here, signed in
//   /web-login.php?step=logout    -> single logout

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use OpenBack\AppAuth\AppAuthException;
use OpenBack\AppAuth\OidcWebClient;

session_start(['cookie_httponly' => true, 'cookie_secure' => true, 'cookie_samesite' => 'Lax']);

$oidc = new OidcWebClient(
    'https://api.example.com/gateway/shop/auth/main',
    getenv('OPENBACK_CLIENT_ID') ?: 'uapp_...',
    getenv('OPENBACK_CLIENT_SECRET') ?: '',
    'https://shop.example.com/web-login.php?step=callback',
);

switch ($_GET['step'] ?? '') {
    case 'login':
        $request = $oidc->authorizationUrl(['uiLocales' => 'en']);
        $_SESSION['openback_tx'] = $request->transaction->toArray();     // server-side, never in a plain cookie
        header('Location: ' . $request->url, true, 302);
        exit;

    case 'callback':
        $tx = $_SESSION['openback_tx'] ?? [];
        unset($_SESSION['openback_tx']);                                  // one use
        try {
            $tokens = $oidc->handleCallback($_GET, $tx);
        } catch (AppAuthException $e) {
            http_response_code(400);
            echo 'Sign-in failed: ' . htmlspecialchars($e->errorCode, ENT_QUOTES);
            exit;
        }
        session_regenerate_id(true);
        $_SESSION['user'] = ['sub' => $tokens->idTokenClaims['sub'], 'email' => $tokens->idTokenClaims['email'] ?? null,
            'name' => $tokens->idTokenClaims['name'] ?? null, 'roles' => $tokens->idTokenClaims['roles'] ?? []];
        $_SESSION['id_token'] = $tokens->idToken;
        // Keep $tokens->refreshToken only if you call APIs later, and store each rotated one: refresh tokens rotate.
        if ($tokens->refreshToken !== null) {
            try {
                $oidc->revoke($tokens->refreshToken);                     // not needed here: revoke it
            } catch (AppAuthException) {
            }
        }
        header('Location: /', true, 302);
        exit;

    case 'logout':
        $idToken = $_SESSION['id_token'] ?? null;
        $_SESSION = [];
        session_destroy();
        header('Location: ' . $oidc->logoutUrl($idToken, 'https://shop.example.com/'), true, 302);
        exit;
}

echo isset($_SESSION['user'])
    ? 'Hello ' . htmlspecialchars((string) ($_SESSION['user']['name'] ?? $_SESSION['user']['email']), ENT_QUOTES) . ' <a href="?step=logout">Sign out</a>'
    : '<a href="?step=login">Sign in</a>';
