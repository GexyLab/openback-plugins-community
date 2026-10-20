<?php

/**
 * @copyright  (C) 2026 GexyLab and the OpenBack contributors
 * @license    GPL-2.0-or-later
 */

\defined('_JEXEC') or die;

use GexyLab\Plugin\ApiAuthentication\OpenBackAppAuth\Extension\OpenBackAppAuth;
use Joomla\CMS\Extension\PluginInterface;
use Joomla\CMS\Factory;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\DI\Container;
use Joomla\DI\ServiceProviderInterface;
use Joomla\Event\DispatcherInterface;

return new class () implements ServiceProviderInterface {
    public function register(Container $container): void
    {
        if (!class_exists(\OpenBackAppAuthJoomla\Integration\Settings::class) && is_dir(JPATH_LIBRARIES . '/openbackappauth/src')) {
            \JLoader::registerNamespace('OpenBackAppAuthJoomla', JPATH_LIBRARIES . '/openbackappauth/src');
        }
        $container->set(
            PluginInterface::class,
            function (Container $container) {
                // A variable: Joomla 4's CMSPlugin takes the dispatcher by reference.
                $dispatcher = $container->get(DispatcherInterface::class);
                $plugin     = new OpenBackAppAuth(
                    $dispatcher,
                    (array) PluginHelper::getPlugin('api-authentication', 'openbackappauth')
                );
                $plugin->setApplication(Factory::getApplication());
                return $plugin;
            }
        );
    }
};
