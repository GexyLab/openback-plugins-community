<?php
/**
 * Builds dist/openback-app-auth-wordpress-1.0.0.zip (the installable plugin, folder openback-app-auth-wordpress/).
 *
 *   php build.php           # zip
 *   php build.php --sync    # copy the PHP SDK into lib/ again first (tools/sync-sdk.php)
 *
 * Needs ext-zip. Development files (tests, tools, composer, build scripts, README.md) are left out.
 *
 * @package openback-app-auth-wordpress
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
	exit(1);
}

const SLUG    = 'openback-app-auth-wordpress';
const VERSION = '1.0.0';

$root = __DIR__;
if (in_array('--sync', $argv, true)) {
	passthru(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($root . '/tools/sync-sdk.php'), $code);
	if ($code !== 0) {
		exit($code);
	}
}
if (!class_exists(ZipArchive::class)) {
	fwrite(STDERR, "ext-zip is required\n");
	exit(1);
}

$include = array('openback-app-auth-wordpress.php', 'uninstall.php', 'readme.txt', 'LICENSE', 'CHANGELOG.md', 'includes', 'lib', 'blocks', 'assets', 'languages');

// Every PHP file must lint before it is packed.
$php = array();
foreach ($include as $entry) {
	$path = $root . '/' . $entry;
	if (is_file($path) && str_ends_with($path, '.php')) {
		$php[] = $path;
	} elseif (is_dir($path)) {
		foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS)) as $file) {
			if ($file->getExtension() === 'php') {
				$php[] = $file->getPathname();
			}
		}
	}
}
foreach ($php as $file) {
	exec(escapeshellarg(PHP_BINARY) . ' -d log_errors=0 -l ' . escapeshellarg($file) . ' 2>&1', $out, $code);
	if ($code !== 0) {
		fwrite(STDERR, implode("\n", $out) . "\n");
		exit(1);
	}
}

@mkdir($root . '/dist', 0777, true);
$target = $root . '/dist/' . SLUG . '-' . VERSION . '.zip';
@unlink($target);
$zip = new ZipArchive();
if ($zip->open($target, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
	fwrite(STDERR, "cannot create $target\n");
	exit(1);
}
$count = 0;
foreach ($include as $entry) {
	$path = $root . '/' . $entry;
	if (is_file($path)) {
		$zip->addFile($path, SLUG . '/' . $entry);
		$count++;
	} elseif (is_dir($path)) {
		$zip->addEmptyDir(SLUG . '/' . $entry);
		$files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
		foreach ($files as $file) {
			$relative = SLUG . '/' . $entry . '/' . str_replace('\\', '/', substr($file->getPathname(), strlen($path) + 1));
			if ($file->isDir()) {
				$zip->addEmptyDir($relative);
			} else {
				$zip->addFile($file->getPathname(), $relative);
				$count++;
			}
		}
	}
}
$zip->close();
printf("%s (%d files, %d PHP files linted)\n", $target, $count, count($php));
