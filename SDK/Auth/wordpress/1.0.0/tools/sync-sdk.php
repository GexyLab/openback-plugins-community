<?php
/**
 * Copies the PHP SDK (openback-app-auth-php) into lib/openback-app-auth-php/ with its namespace PREFIXED
 * (OpenBack\AppAuth -> OpenBackAppAuthWp\Sdk), so that another plugin bundling another version of the SDK can never
 * clash with this copy. Development tool: not shipped in the plugin's zip.
 *
 *   php tools/sync-sdk.php [path/to/SDK/Auth/php/1.0.0]
 *
 * @package openback-app-auth-wordpress
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
	exit(1);
}

$root   = dirname(__DIR__);
$source = rtrim($argv[1] ?? $root . '/../../php/1.0.0', '/\\');
$target = $root . '/lib/openback-app-auth-php';
$prefix = 'OpenBackAppAuthWp\\Sdk';
// Not needed inside WordPress (PSR-15 stack): left out of the copy.
$skip = array( 'Middleware/RequireAppUser.php' );

if (!is_file($source . '/src/Client.php')) {
	fwrite(STDERR, "SDK not found in $source\n");
	exit(1);
}

function rrmdir(string $dir): void {
	if (!is_dir($dir)) {
		return;
	}
	foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST) as $item) {
		$item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
	}
	rmdir($dir);
}

rrmdir($target);
mkdir($target . '/src', 0777, true);

$count = 0;
$files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($source . '/src', FilesystemIterator::SKIP_DOTS));
foreach ($files as $file) {
	$relative = str_replace('\\', '/', substr($file->getPathname(), strlen($source . '/src/')));
	if ($file->getExtension() !== 'php' || in_array($relative, $skip, true)) {
		continue;
	}
	$code = file_get_contents($file->getPathname());
	$code = str_replace(array( 'OpenBack\\\\AppAuth', 'OpenBack\\AppAuth' ), array( str_replace('\\', '\\\\', $prefix), $prefix ), $code);
	$code = str_replace("declare(strict_types=1);\n", "declare(strict_types=1);\n\n// Bundled copy of openback-app-auth-php 1.0.0 (MIT), namespace prefixed for this plugin.\n", $code);
	$dest = $target . '/src/' . $relative;
	if (!is_dir(dirname($dest))) {
		mkdir(dirname($dest), 0777, true);
	}
	file_put_contents($dest, $code);
	$count++;
}
copy($source . '/LICENSE', $target . '/LICENSE');
file_put_contents($target . '/README.txt', <<<TXT
openback-app-auth-php 1.0.0 (MIT License, see LICENSE) -- bundled copy
https://github.com/GexyLab/openback-plugins-community/tree/main/SDK/Auth/php/1.0.0

The namespace OpenBack\\AppAuth is renamed {$prefix} so that it never clashes with another copy of the SDK
loaded by another plugin. Left out: Middleware/RequireAppUser.php (PSR-15). Regenerate with tools/sync-sdk.php;
do not edit these files by hand.

TXT);
echo "copied $count files to $target\n";
