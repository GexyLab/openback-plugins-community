<?php
/**
 * Unit tests of the plugin's pure logic, without WordPress: role mapping, the server-side state store, and the bundled
 * (namespace-prefixed) SDK loaded through the plugin's own autoloader.
 *
 * @package openback-app-auth-wordpress
 */

declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';    // PHPUnit only

if (!defined('ABSPATH')) {
	define('ABSPATH', sys_get_temp_dir() . '/');       // lets includes/autoload.php load outside WordPress
}
require dirname(__DIR__) . '/includes/autoload.php';
