<?php
/**
 * Dependencies of the block's editor script (no build step).
 *
 * @package openback-app-auth-wordpress
 */

defined( 'ABSPATH' ) || exit;

return array(
	'dependencies' => array( 'wp-blocks', 'wp-element', 'wp-i18n', 'wp-block-editor', 'wp-components', 'wp-server-side-render' ),
	'version'      => '1.0.0',
);
