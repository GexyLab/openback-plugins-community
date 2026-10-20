<?php

/**
 * API Authentication - OpenBack App Auth (disabled after install; enable it to use it): the Joomla Web Services API
 * (/api/index.php) accepts `Authorization: Bearer <pool access token>` and runs the request as the Joomla user linked
 * to the token's user. The token is verified locally (ES256 with the pool's keys, `typ: at+jwt`, issuer, audience among
 * this app's and the extra client IDs, expiry); guest tokens are refused. Tokens that are not JWTs (Joomla API tokens)
 * are left to the other plugins. The user still needs the "Web Services Login" permission (core.login.api).
 *
 * @copyright  (C) 2026 GexyLab and the OpenBack contributors
 * @license    GPL-2.0-or-later
 */

declare(strict_types=1);

namespace GexyLab\Plugin\ApiAuthentication\OpenBackAppAuth\Extension;

\defined('_JEXEC') or die;

use Joomla\CMS\Authentication\Authentication;
use Joomla\CMS\Factory;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\Database\DatabaseInterface;
use Joomla\Event\EventInterface;
use Joomla\Event\SubscriberInterface;
use OpenBackAppAuthJoomla\Integration\Settings;
use OpenBackAppAuthJoomla\Integration\UserLinker;
use OpenBackAppAuthJoomla\Sdk\AppAuthException;

final class OpenBackAppAuth extends CMSPlugin implements SubscriberInterface
{
    public static function getSubscribedEvents(): array
    {
        return ['onUserAuthenticate' => 'onUserAuthenticate'];
    }

    /**
     * @param array<string, mixed>|EventInterface $credentials
     * @param array<string, mixed>                $options
     * @param object|null                         $response  AuthenticationResponse
     */
    public function onUserAuthenticate($credentials, $options = [], $response = null): void
    {
        if ($credentials instanceof EventInterface) {
            $event = $credentials;
            if (method_exists($event, 'getAuthenticationResponse')) {
                $response = $event->getAuthenticationResponse();
            } else {
                $args     = array_values($event->getArguments());
                $response = $args[2] ?? null;
            }
        }
        if (!is_object($response) || !class_exists(Settings::class)) {
            return;
        }
        $token = $this->bearerJwt();
        if ($token === null) {
            return;
        }
        $settings = Settings::load();
        if (!$settings->configured()) {
            return;
        }
        $response->type = 'OpenBackAppAuth';
        // A JWT is never a Joomla API token: hide it from the core token plugin, whose Joomla 4 version fails with an
        // error 500 on a JWT instead of refusing it (a non-Bearer value makes it skip the header).
        $server = Factory::getApplication()->getInput()->server;
        $server->set('HTTP_AUTHORIZATION', 'OpenBackAppAuth checked');
        $server->set('REDIRECT_HTTP_AUTHORIZATION', 'OpenBackAppAuth checked');
        try {
            $appUser = $settings->verifier(Settings::extraClientIds($this->params))->verify($token);
        } catch (AppAuthException) {
            $response->status        = Authentication::STATUS_FAILURE;
            $response->error_message = 'invalid_token';
            return;
        }
        if ($appUser->anonymous) {
            $response->status        = Authentication::STATUS_FAILURE;
            $response->error_message = 'invalid_token';
            return;
        }
        $user = (new UserLinker($settings, Factory::getContainer()->get(DatabaseInterface::class)))->findLinked($appUser->id, $appUser->poolId);
        if ($user === null || (int) $user->block === 1) {
            $response->status        = Authentication::STATUS_FAILURE;
            $response->error_message = 'no_linked_user';
            return;
        }
        $response->status        = Authentication::STATUS_SUCCESS;
        $response->username      = $user->username;
        $response->email         = $user->email;
        $response->fullname      = $user->name;
        $response->error_message = '';
    }

    /** A bearer token shaped like a JWT, from the Authorization header (also when the server renames it). */
    private function bearerJwt(): ?string
    {
        $server = Factory::getApplication()->getInput()->server;
        $header = (string) $server->get('HTTP_AUTHORIZATION', '', 'RAW');
        if ($header === '') {
            $header = (string) $server->get('REDIRECT_HTTP_AUTHORIZATION', '', 'RAW');
        }
        if (!preg_match('/^\s*Bearer\s+([A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)\s*$/i', $header, $m)) {
            return null;
        }
        return $m[1];
    }
}
