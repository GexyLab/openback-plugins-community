<?php

// A command-line tool signing a user in with email + password (and the second factor), then calling an API.
//   php examples/cli-sign-in.php ada@example.com

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use OpenBack\AppAuth\AppAuthException;
use OpenBack\AppAuth\Client;
use OpenBack\AppAuth\OutcomeStatus;

$auth = new Client('https://api.example.com/gateway/shop/auth/main', 'uapp_...');   // kind "native" or "backend"
$auth->onAuthStateChanged(static function (?array $user): void {
    fwrite(STDERR, $user ? "signed in as {$user['id']}\n" : "signed out\n");
});

$email = $argv[1] ?? '';
$password = (string) readline('Password: ');
try {
    $res = $auth->signInWithPassword($email, $password);
    if ($res->status === OutcomeStatus::MfaRequired) {
        $res = $auth->verifyMfa((string) $res->mfaToken, (string) readline('Authenticator code: '));
    }
    if ($res->status === OutcomeStatus::PasswordChangeRequired) {
        $auth->changeForcedPassword((string) $res->changeToken, (string) readline('New password: '));
        exit("Password changed: sign in again.\n");
    }
    if (!$res->isOk()) {
        exit("Not signed in: {$res->rawStatus}\n");
    }
    $response = $auth->fetch('GET', 'https://api.example.com/gateway/shop/orders', ['Accept' => 'application/json']);
    echo $response->status, ' ', $response->body, "\n";
    $auth->signOut();
} catch (AppAuthException $e) {
    exit("Error {$e->status} {$e->errorCode}: {$e->getMessage()}\n");
}
