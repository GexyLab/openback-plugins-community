<?php

/**
 * @copyright  (C) 2026 GexyLab and the OpenBack contributors
 * @license    GPL-2.0-or-later
 */

\defined('_JEXEC') or die;

use Joomla\CMS\Extension\Service\Provider\Module;
use Joomla\CMS\Extension\Service\Provider\ModuleDispatcherFactory;
use Joomla\DI\Container;
use Joomla\DI\ServiceProviderInterface;

return new class () implements ServiceProviderInterface {
    public function register(Container $container): void
    {
        if (!class_exists(\OpenBackAppAuthJoomla\Integration\Settings::class) && is_dir(JPATH_LIBRARIES . '/openbackappauth/src')) {
            \JLoader::registerNamespace('OpenBackAppAuthJoomla', JPATH_LIBRARIES . '/openbackappauth/src');
        }
        $container->registerServiceProvider(new ModuleDispatcherFactory('\\GexyLab\\Module\\OpenBackAppAuthLogin'));
        $container->registerServiceProvider(new Module());
    }
};
