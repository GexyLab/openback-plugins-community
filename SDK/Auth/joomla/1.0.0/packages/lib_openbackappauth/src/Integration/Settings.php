<?php

/**
 * The settings: the parameters of the system plugin "System - OpenBack App Auth" (shared by the other extensions of
 * the package), and the addresses of the sign-in routes.
 *
 * @copyright  (C) 2026 GexyLab and the OpenBack contributors
 * @license    GPL-2.0-or-later
 */

declare(strict_types=1);

namespace OpenBackAppAuthJoomla\Integration;

\defined('_JEXEC') or die;

use Joomla\CMS\Component\ComponentHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\CMS\Session\Session;
use Joomla\CMS\Uri\Uri;
use Joomla\Registry\Registry;
use OpenBackAppAuthJoomla\Sdk\OidcWebClient;
use OpenBackAppAuthJoomla\Sdk\TokenVerifier;

final class Settings
{
    /** The route of the system plugin (com_ajax), without the task. */
    public const ROUTE = 'index.php?option=com_ajax&group=system&plugin=openbackappauth&format=raw';

    public function __construct(private readonly Registry $params)
    {
    }

    /** The settings of the (enabled) system plugin. */
    public static function load(): self
    {
        $plugin = PluginHelper::getPlugin('system', 'openbackappauth');
        $params = is_object($plugin) && isset($plugin->params) ? (string) $plugin->params : '{}';
        return new self(new Registry($params));
    }

    public function issuer(): string
    {
        return rtrim(trim((string) $this->params->get('issuer', '')), '/');
    }

    public function clientId(): string
    {
        return trim((string) $this->params->get('client_id', ''));
    }

    public function clientSecret(): string
    {
        return trim((string) $this->params->get('client_secret', ''));
    }

    public function configured(): bool
    {
        return self::validIssuer($this->issuer()) && $this->clientId() !== '' && $this->clientSecret() !== '';
    }

    public function scopes(): string
    {
        $scopes = preg_split('/\s+/', trim((string) $this->params->get('scopes', 'openid profile email'))) ?: [];
        $scopes = array_values(array_filter($scopes, static fn (string $s): bool => (bool) preg_match('/^[A-Za-z0-9_.:\-]+$/', $s)));
        if (!in_array('openid', $scopes, true)) {
            array_unshift($scopes, 'openid');
        }
        return implode(' ', $scopes);
    }

    public function provider(): string
    {
        $provider = trim((string) $this->params->get('provider', ''));
        return preg_match('/^[A-Za-z0-9_\-]{1,64}$/', $provider) ? $provider : '';
    }

    public function buttonLabel(): string
    {
        return trim((string) $this->params->get('button_label', ''));
    }

    public function flag(string $name, bool $default): bool
    {
        return (bool) (int) $this->params->get($name, $default ? 1 : 0);
    }

    public function autoCreate(): bool
    {
        return $this->flag('auto_create', true);
    }

    public function requireVerifiedEmail(): bool
    {
        return $this->flag('require_verified_email', true);
    }

    public function linkByEmail(): bool
    {
        return $this->flag('link_by_email', false);
    }

    public function syncGroups(): bool
    {
        return $this->flag('sync_groups', false);
    }

    public function singleLogout(): bool
    {
        return $this->flag('single_logout', true);
    }

    /** @return list<array{0: string, 1: int}> */
    public function groupRules(): array
    {
        return GroupMapper::rules($this->params->get('group_map', []));
    }

    public function defaultGroup(): int
    {
        $group = (int) $this->params->get('default_group', 0);
        return $group > 0 ? $group : (int) ComponentHelper::getParams('com_users')->get('new_usertype', 2);
    }

    public function postLogoutRedirect(): string
    {
        $url = trim((string) $this->params->get('post_logout_redirect', ''));
        return $url !== '' ? $url : Uri::root();
    }

    /** @return string[] client IDs accepted by the API authentication plugin, besides this app's */
    public static function extraClientIds(Registry $params): array
    {
        return array_values(array_filter(
            preg_split('/[\s,]+/', (string) $params->get('client_ids', '')) ?: [],
            static fn (string $id): bool => (bool) preg_match('/^[A-Za-z0-9_\-]{1,64}$/', $id)
        ));
    }

    /** The redirect URI to register on the `web` app (exact match). */
    public static function redirectUri(): string
    {
        return Uri::root() . self::ROUTE . '&task=callback';
    }

    /** The address that starts a sign-in; $return is where to go afterwards (an address of this site). */
    public static function loginUrl(string $return = ''): string
    {
        $url = Uri::root() . self::ROUTE . '&task=login';
        return $return !== '' ? $url . '&return=' . rawurlencode(base64_encode($return)) : $url;
    }

    /** The address that links the signed-in user's account (carries the session's CSRF token). */
    public static function linkUrl(string $return = ''): string
    {
        $url = Uri::root() . self::ROUTE . '&task=link&' . Session::getFormToken() . '=1';
        return $return !== '' ? $url . '&return=' . rawurlencode(base64_encode($return)) : $url;
    }

    public static function validIssuer(string $issuer): bool
    {
        return (bool) preg_match('#^https://[^/\s]+(/\S*)?$#i', $issuer)
            || (bool) preg_match('#^http://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?(/\S*)?$#i', $issuer);
    }

    public function oidc(): OidcWebClient
    {
        return new OidcWebClient($this->issuer(), $this->clientId(), $this->clientSecret(), self::redirectUri(), [
            'transport' => new JoomlaHttpTransport(),
            'cache'     => new JoomlaJwksCache(),
            'scope'     => $this->scopes(),
        ]);
    }

    /** @param string[] $extraClientIds */
    public function verifier(array $extraClientIds = []): TokenVerifier
    {
        return new TokenVerifier($this->issuer(), array_values(array_unique(array_merge([$this->clientId()], $extraClientIds))), [
            'transport' => new JoomlaHttpTransport(),
            'cache'     => new JoomlaJwksCache(),
        ]);
    }

    /** The current language as the pool's ui_locales (it | en). */
    public static function uiLocale(): string
    {
        try {
            return str_starts_with((string) Factory::getApplication()->getLanguage()->getTag(), 'it') ? 'it' : 'en';
        } catch (\Throwable) {
            return 'en';
        }
    }
}
