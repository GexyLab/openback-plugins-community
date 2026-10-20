<?php

/**
 * Copies the PHP SDK (openback-app-auth-php) into the library extension
 * (packages/lib_openbackappauth/src/Sdk/) with its namespace PREFIXED (OpenBack\AppAuth -> OpenBackAppAuthJoomla\Sdk),
 * so that another extension bundling another version of the SDK can never clash with this copy.
 * Development tool: not part of the installable package.
 *
 *   php tools/sync-sdk.php [path/to/SDK/Auth/php/1.0.0]
 *
 * @copyright  (C) 2026 GexyLab and the OpenBack contributors
 * @license    GPL-2.0-or-later
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    exit(1);
}

$root   = dirname(__DIR__);
$source = rtrim($argv[1] ?? $root . '/../../php/1.0.0', '/\\');
$target = $root . '/packages/lib_openbackappauth/src/Sdk';
$prefix = 'OpenBackAppAuthJoomla\\Sdk';
// Not needed inside Joomla (PSR-15 stack): left out of the copy.
$skip = ['Middleware/RequireAppUser.php'];

if (!is_file($source . '/src/Client.php')) {
    fwrite(STDERR, "SDK not found in $source\n");
    exit(1);
}

function rrmdir(string $dir): void
{
    if (!is_dir($dir)) {
        return;
    }
    $items = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($items as $item) {
        $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
    }
    rmdir($dir);
}

rrmdir($target);
mkdir($target, 0777, true);

$count = 0;
$files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($source . '/src', FilesystemIterator::SKIP_DOTS));
foreach ($files as $file) {
    $relative = str_replace('\\', '/', substr($file->getPathname(), strlen($source . '/src/')));
    if ($file->getExtension() !== 'php' || in_array($relative, $skip, true)) {
        continue;
    }
    $code = file_get_contents($file->getPathname());
    $code = str_replace(['OpenBack\\\\AppAuth', 'OpenBack\\AppAuth'], [str_replace('\\', '\\\\', $prefix), $prefix], $code);
    $code = str_replace(
        "declare(strict_types=1);\n",
        "declare(strict_types=1);\n\n// Bundled copy of openback-app-auth-php 1.0.0 (MIT), namespace prefixed for this extension.\n",
        $code
    );
    // Joomla's guard against direct access, right after the namespace declaration.
    $guard = "\n" . chr(92) . "defined('_JEXEC') or die;\n";
    $code  = (string) preg_replace_callback('/^namespace [^;]+;\n/m', static fn (array $m): string => $m[0] . $guard, $code, 1);
    $dest = $target . '/' . $relative;
    if (!is_dir(dirname($dest))) {
        mkdir(dirname($dest), 0777, true);
    }
    file_put_contents($dest, $code);
    $count++;
}
copy($source . '/LICENSE', $root . '/packages/lib_openbackappauth/LICENSE-SDK.txt');
echo "copied $count files to $target\n";
