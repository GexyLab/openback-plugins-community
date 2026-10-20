<?php

/**
 * @copyright  (C) 2026 GexyLab and the OpenBack contributors
 * @license    GPL-2.0-or-later
 */

\defined('_JEXEC') or die;

use GexyLab\Plugin\System\OpenBackAppAuth\Extension\OpenBackAppAuth;
use Joomla\CMS\Extension\PluginInterface;
use Joomla\CMS\Factory;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\DI\Container;
use Joomla\DI\ServiceProviderInterface;
use Joomla\Event\DispatcherInterface;

return new class () implements ServiceProviderInterface {
    public function register(Container $container): void
    {
        // The library's namespace, also when Joomla's autoload cache does not know it yet.
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
                    (array) PluginHelper::getPlugin('system', 'openbackappauth')
                );
                $plugin->setApplication(Factory::getApplication());
                return $plugin;
            }
        );
    }
};
