<?php

/**
 * OpenBack App Auth - Login button module: the data of the layout.
 *
 * @copyright  (C) 2026 GexyLab and the OpenBack contributors
 * @license    GPL-2.0-or-later
 */

declare(strict_types=1);

namespace GexyLab\Module\OpenBackAppAuthLogin\Site\Dispatcher;

\defined('_JEXEC') or die;

use Joomla\CMS\Dispatcher\AbstractModuleDispatcher;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Uri\Uri;
use Joomla\Database\DatabaseInterface;
use OpenBackAppAuthJoomla\Integration\Settings;
use OpenBackAppAuthJoomla\Integration\UserLinker;

final class Dispatcher extends AbstractModuleDispatcher
{
    protected function getLayoutData(): array
    {
        $data   = parent::getLayoutData();
        $params = $data['params'];
        $user   = $this->getApplication()->getIdentity();

        $data['available'] = class_exists(Settings::class);
        $data['configured'] = false;
        $data['user']       = $user;
        $data['loginUrl']   = '';
        $data['linkUrl']    = '';
        $data['label']      = '';
        $data['return']     = $this->returnUrl((string) $params->get('return_url', ''));
        if (!$data['available']) {
            return $data;
        }
        $settings            = Settings::load();
        $data['configured']  = $settings->configured();
        $data['label']       = trim((string) $params->get('label', '')) !== '' ? trim((string) $params->get('label'))
            : ($settings->buttonLabel() !== '' ? $settings->buttonLabel() : Text::_('MOD_OPENBACKAPPAUTH_LOGIN_DEFAULT_LABEL'));
        $data['loginUrl']    = Settings::loginUrl($data['return']);
        if ($user !== null && !$user->guest && (int) $params->get('show_link', 1) === 1) {
            $linker = new UserLinker($settings, Factory::getContainer()->get(DatabaseInterface::class));
            if ($linker->linkedSub((int) $user->id) === null) {
                $data['linkUrl'] = Settings::linkUrl($data['return']);
            }
        }
        return $data;
    }

    /** Where to go after signing in: the module's setting (an address of this site) or the current page. */
    private function returnUrl(string $configured): string
    {
        if ($configured !== '' && Uri::isInternal($configured)) {
            return $configured;
        }
        return Uri::getInstance()->toString(['scheme', 'user', 'pass', 'host', 'port', 'path', 'query']);
    }
}
