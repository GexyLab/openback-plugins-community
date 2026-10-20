<?php

/**
 * Authentication - OpenBack App Auth: completes a sign-in that the system plugin has verified.
 *
 * It answers only when the login options carry a VerifiedLogin object (created by the system plugin after checking an
 * OpenBack ID token; a request can never supply it) for the same username. Password sign-ins are left to the other
 * authentication plugins.
 *
 * Joomla 4 calls onUserAuthenticate($credentials, $options, $response) directly; Joomla 5 dispatches an
 * AuthenticationEvent: both are handled.
 *
 * @copyright  (C) 2026 GexyLab and the OpenBack contributors
 * @license    GPL-2.0-or-later
 */

declare(strict_types=1);

namespace GexyLab\Plugin\Authentication\OpenBackAppAuth\Extension;

\defined('_JEXEC') or die;

use Joomla\CMS\Authentication\Authentication;
use Joomla\CMS\Factory;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\CMS\User\UserFactoryInterface;
use Joomla\Event\EventInterface;
use Joomla\Event\SubscriberInterface;
use OpenBackAppAuthJoomla\Integration\VerifiedLogin;

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
                $credentials = $event->getCredentials();
                $options     = $event->getOptions();
                $response    = $event->getAuthenticationResponse();
            } else {
                $args        = array_values($event->getArguments());
                $credentials = $args[0] ?? [];
                $options     = $args[1] ?? [];
                $response    = $args[2] ?? null;
            }
        }
        if (!is_object($response) || !is_array($options) || !is_array($credentials)) {
            return;
        }
        $login = $options[VerifiedLogin::OPTION] ?? null;
        if (!$login instanceof VerifiedLogin || $login->username !== ($credentials['username'] ?? null) || !$login->consume()) {
            return;
        }
        $user = Factory::getContainer()->get(UserFactoryInterface::class)->loadUserById($login->userId);
        if (!$user->id || $user->username !== $login->username) {
            return;
        }
        if ((int) $user->block === 1 || ($user->activation !== '' && $user->activation !== '0' && $user->activation !== null)) {
            $response->status        = Authentication::STATUS_FAILURE;
            $response->error_message = 'blocked';
            return;
        }
        $response->status        = Authentication::STATUS_SUCCESS;
        $response->type          = 'OpenBackAppAuth';
        $response->username      = $user->username;
        $response->email         = $user->email;
        $response->fullname      = $user->name;
        $response->error_message = '';
    }
}
