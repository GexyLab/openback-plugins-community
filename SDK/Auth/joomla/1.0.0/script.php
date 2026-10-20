<?php

/**
 * Package installer script of OpenBack App Auth: checks PHP / Joomla, and on the first install enables the system and
 * authentication plugins (the API authentication plugin stays disabled until you enable it).
 *
 * @copyright  (C) 2026 GexyLab and the OpenBack contributors
 * @license    GPL-2.0-or-later
 */

\defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Installer\InstallerAdapter;
use Joomla\CMS\Language\Text;
use Joomla\Database\DatabaseInterface;

class Pkg_OpenbackappauthInstallerScript
{
    private const MIN_PHP    = '8.1.0';
    private const MIN_JOOMLA = '4.2.0';

    /**
     * @param string           $type
     * @param InstallerAdapter $parent
     */
    public function preflight($type, $parent): bool
    {
        if ($type === 'uninstall') {
            return true;
        }
        if (version_compare(PHP_VERSION, self::MIN_PHP, '<') || !extension_loaded('openssl')) {
            Factory::getApplication()->enqueueMessage(Text::_('PKG_OPENBACKAPPAUTH_ERR_PHP'), 'error');
            return false;
        }
        if (version_compare(JVERSION, self::MIN_JOOMLA, '<')) {
            Factory::getApplication()->enqueueMessage(Text::_('PKG_OPENBACKAPPAUTH_ERR_JOOMLA'), 'error');
            return false;
        }
        return true;
    }

    /**
     * Uninstall: removes the account links (#__user_profiles rows openback.*). Joomla accounts stay.
     *
     * @param InstallerAdapter $parent
     */
    public function uninstall($parent): bool
    {
        $db    = Factory::getContainer()->get(DatabaseInterface::class);
        $query = $db->getQuery(true)
            ->delete($db->quoteName('#__user_profiles'))
            ->where($db->quoteName('profile_key') . ' LIKE ' . $db->quote('openback.%'));
        $db->setQuery($query)->execute();
        return true;
    }

    /**
     * @param string           $type
     * @param InstallerAdapter $parent
     */
    public function postflight($type, $parent): void
    {
        if ($type !== 'install') {
            return;
        }
        $db    = Factory::getContainer()->get(DatabaseInterface::class);
        $query = $db->getQuery(true)
            ->update($db->quoteName('#__extensions'))
            ->set($db->quoteName('enabled') . ' = 1')
            ->where($db->quoteName('type') . ' = ' . $db->quote('plugin'))
            ->where($db->quoteName('element') . ' = ' . $db->quote('openbackappauth'))
            ->where($db->quoteName('folder') . ' IN (' . $db->quote('system') . ', ' . $db->quote('authentication') . ')');
        $db->setQuery($query)->execute();
    }
}
