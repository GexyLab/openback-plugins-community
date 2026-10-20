<?php

/**
 * System - OpenBack App Auth: the sign-in routes (com_ajax), account linking and single logout.
 *
 *   index.php?option=com_ajax&group=system&plugin=openbackappauth&format=raw&task=login[&return=<base64>]
 *   index.php?option=com_ajax&group=system&plugin=openbackappauth&format=raw&task=callback   (the redirect URI)
 *   index.php?option=com_ajax&group=system&plugin=openbackappauth&format=raw&task=link&<token>=1
 *
 * @copyright  (C) 2026 GexyLab and the OpenBack contributors
 * @license    GPL-2.0-or-later
 */

declare(strict_types=1);

namespace GexyLab\Plugin\System\OpenBackAppAuth\Extension;

\defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\CMS\Router\Route;
use Joomla\CMS\Session\Session;
use Joomla\CMS\Uri\Uri;
use Joomla\Database\DatabaseInterface;
use Joomla\Event\EventInterface;
use Joomla\Event\Priority;
use Joomla\Event\SubscriberInterface;
use OpenBackAppAuthJoomla\Integration\PendingSignIns;
use OpenBackAppAuthJoomla\Integration\Settings;
use OpenBackAppAuthJoomla\Integration\UserLinker;
use OpenBackAppAuthJoomla\Integration\VerifiedLogin;
use OpenBackAppAuthJoomla\Sdk\AppAuthException;

final class OpenBackAppAuth extends CMSPlugin implements SubscriberInterface
{
    public const ID_TOKEN_KEY = 'openbackappauth.id_token';

    /** The error codes with a message (anything else is "sign_in_failed"). */
    private const ERRORS = [
        'invalid_state', 'cancelled', 'sign_in_failed', 'not_configured', 'email_exists', 'email_not_verified', 'no_account',
        'no_email', 'admin_link_refused', 'already_linked', 'registration_failed', 'login_refused', 'unavailable', 'library_missing',
    ];

    protected $autoloadLanguage = true;

    private ?string $logoutIdToken = null;

    public static function getSubscribedEvents(): array
    {
        return [
            'onAjaxOpenbackappauth' => 'onAjax',
            'onUserLogout'          => ['onUserLogout', Priority::HIGH],
            'onUserAfterLogout'     => 'onUserAfterLogout',
            'onUserAfterDelete'     => 'onUserAfterDelete',
        ];
    }

    /** com_ajax: the sign-in routes. Every branch ends with a redirect. */
    public function onAjax(EventInterface $event): void
    {
        $app = Factory::getApplication();
        if (!$app->isClient('site')) {
            return;
        }
        if (!class_exists(Settings::class)) {
            $this->fail('library_missing', '');
        }
        $task = (string) $app->getInput()->getCmd('task', 'login');
        match ($task) {
            'callback' => $this->callback(),
            'link'     => $this->start(true),
            default    => $this->start(false),
        };
    }

    private function start(bool $link): never
    {
        $app      = Factory::getApplication();
        $settings = Settings::load();
        $return   = $this->returnUrl();
        $linkUser = 0;
        if ($link) {
            $identity = $app->getIdentity();
            if (!Session::checkToken('get') || $identity === null || $identity->guest) {
                $this->fail('invalid_state', $return);
            }
            $linkUser = (int) $identity->id;
        }
        if (!$settings->configured()) {
            $this->fail('not_configured', $return);
        }
        $options = ['scope' => $settings->scopes(), 'uiLocales' => Settings::uiLocale()];
        if ($settings->provider() !== '') {
            $options['provider'] = $settings->provider();
        }
        $request = $settings->oidc()->authorizationUrl($options);
        $session = $app->getSession();
        $session->set(PendingSignIns::SESSION_KEY, PendingSignIns::add(
            (array) $session->get(PendingSignIns::SESSION_KEY, []),
            $request->transaction->toArray() + ['return' => $return, 'link_user' => $linkUser],
            time()
        ));
        $app->setHeader('Cache-Control', 'no-store', true);
        $app->redirect($request->url);
        exit;
    }

    private function callback(): never
    {
        $app   = Factory::getApplication();
        $input = $app->getInput();
        $params = [];
        foreach (['code', 'state', 'iss', 'error', 'error_description'] as $name) {
            $value = $input->get($name, '', 'RAW');
            if (is_string($value) && $value !== '' && strlen($value) <= 4096) {
                $params[$name] = $value;
            }
        }
        $session = $app->getSession();
        [$tx, $left] = PendingSignIns::take((array) $session->get(PendingSignIns::SESSION_KEY, []), $params['state'] ?? null, time());
        $session->set(PendingSignIns::SESSION_KEY, $left);
        if ($tx === null) {
            $this->fail('invalid_state', '');
        }
        $return   = is_string($tx['return'] ?? null) && Uri::isInternal($tx['return']) ? $tx['return'] : Uri::root();
        $linkUser = (int) ($tx['link_user'] ?? 0);
        $settings = Settings::load();
        if (!$settings->configured()) {
            $this->fail('not_configured', $return);
        }
        $oidc = $settings->oidc();
        try {
            $tokens = $oidc->handleCallback($params, $tx);
        } catch (AppAuthException $e) {
            $code = in_array($e->errorCode, ['access_denied', 'login_required', 'consent_required', 'interaction_required'], true) ? 'cancelled'
                : (in_array($e->errorCode, ['network_error', 'jwks_unavailable'], true) ? 'unavailable' : 'sign_in_failed');
            $this->fail($code, $return);
        }
        // Joomla keeps its own session: the refresh token is not needed, revoke it (best effort).
        if ($tokens->refreshToken !== null) {
            try {
                $oidc->revoke($tokens->refreshToken);
            } catch (AppAuthException) {
                // not fatal
            }
        }
        $claims = (array) $tokens->idTokenClaims;
        $linker = new UserLinker($settings, Factory::getContainer()->get(DatabaseInterface::class));

        if ($linkUser > 0) {
            $identity = $app->getIdentity();
            $other    = $linker->findLinked((string) $claims['sub'], is_string($claims['pool'] ?? null) ? $claims['pool'] : null);
            $mine     = $linker->linkedSub($linkUser);
            if ($identity === null || (int) $identity->id !== $linkUser || ($other !== null && (int) $other->id !== $linkUser)
                || ($mine !== null && $mine !== $claims['sub'])) {
                $this->fail('already_linked', $return);
            }
            $linker->link($linkUser, $claims);
            $app->enqueueMessage(Text::_('PLG_SYSTEM_OPENBACKAPPAUTH_LINKED'), 'message');
            $app->redirect($return);
            exit;
        }

        $user = $linker->resolve($claims);
        if (is_string($user)) {
            $this->fail($user, $return);
        }
        $result = $app->login(
            ['username' => $user->username, 'password' => ''],
            [
                VerifiedLogin::OPTION => new VerifiedLogin((int) $user->id, (string) $user->username),
                'remember'            => false,
                'silent'              => true,
                'action'              => 'core.login.site',
            ]
        );
        if ($result !== true) {
            $this->fail('login_refused', $return);
        }
        // Kept for the single logout's id_token_hint (after login: the session was renewed).
        $app->getSession()->set(self::ID_TOKEN_KEY, (string) $tokens->idToken);
        $app->redirect($return);
        exit;
    }

    /** Captures the ID token before the session ends (runs early: high priority). */
    public function onUserLogout(EventInterface $event): void
    {
        $app = Factory::getApplication();
        if (!$app->isClient('site') || !class_exists(Settings::class) || !Settings::load()->singleLogout()) {
            return;
        }
        $token = $app->getSession()->get(self::ID_TOKEN_KEY);
        $this->logoutIdToken = is_string($token) && $token !== '' ? $token : null;
    }

    /** Single logout: to the pool's end-session address, which returns to the registered post-logout URI. */
    public function onUserAfterLogout(EventInterface $event): void
    {
        if ($this->logoutIdToken === null) {
            return;
        }
        $settings = Settings::load();
        $token    = $this->logoutIdToken;
        $this->logoutIdToken = null;
        if (!$settings->configured()) {
            return;
        }
        Factory::getApplication()->redirect($settings->oidc()->logoutUrl($token, $settings->postLogoutRedirect()));
    }

    /** Removes the link of a deleted user. */
    public function onUserAfterDelete(EventInterface $event): void
    {
        $user = method_exists($event, 'getUser') ? $event->getUser() : ($event->getArgument(0) ?? $event->getArgument('subject'));
        $id   = (int) (is_array($user) ? ($user['id'] ?? 0) : (is_object($user) ? ($user->id ?? 0) : 0));
        if ($id > 0 && class_exists(UserLinker::class)) {
            (new UserLinker(Settings::load(), Factory::getContainer()->get(DatabaseInterface::class)))->unlink($id);
        }
    }

    /** The validated return address (base64 in `return`), an address of this site. */
    private function returnUrl(): string
    {
        $raw = (string) Factory::getApplication()->getInput()->get('return', '', 'BASE64');
        $url = $raw !== '' ? (string) base64_decode($raw, true) : '';
        return $url !== '' && Uri::isInternal($url) ? $url : Uri::root();
    }

    private function fail(string $code, string $return): never
    {
        $app  = Factory::getApplication();
        $code = in_array($code, self::ERRORS, true) ? $code : 'sign_in_failed';
        $app->enqueueMessage(Text::_('PLG_SYSTEM_OPENBACKAPPAUTH_ERR_' . strtoupper($code)), 'error');
        $target = $return !== '' && $return !== Uri::root() ? $return : Route::_('index.php?option=com_users&view=login', false);
        $app->redirect($target);
        exit;
    }
}
