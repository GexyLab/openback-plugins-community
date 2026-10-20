<?php

/**
 * Builds dist/openback-app-auth-joomla-1.0.0.zip: the Joomla package pkg_openbackappauth holding one zip per extension
 * (library, system / authentication / API authentication plugins, site module).
 *
 *   php build.php           # zip
 *   php build.php --sync    # copy the PHP SDK into the library again first (tools/sync-sdk.php)
 *
 * Needs ext-zip. Every PHP file is linted (php -l) before it is packed.
 *
 * @copyright  (C) 2026 GexyLab and the OpenBack contributors
 * @license    GPL-2.0-or-later
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    exit(1);
}

const FILE_NAME  = 'openback-app-auth-joomla-1.0.0.zip';
const EXTENSIONS = [
    'lib_openbackappauth',
    'plg_system_openbackappauth',
    'plg_authentication_openbackappauth',
    'plg_api-authentication_openbackappauth',
    'mod_openbackappauth_login',
];

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

/** @return list<SplFileInfo> */
function files_of(string $dir): array
{
    $out = [];
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)) as $file) {
        $out[] = $file;
    }
    usort($out, static fn (SplFileInfo $a, SplFileInfo $b): int => strcmp($a->getPathname(), $b->getPathname()));
    return $out;
}

function lint(string $file): void
{
    exec(escapeshellarg(PHP_BINARY) . ' -d log_errors=0 -l ' . escapeshellarg($file) . ' 2>&1', $out, $code);
    if ($code !== 0) {
        fwrite(STDERR, implode("\n", $out) . "\n");
        exit(1);
    }
}

function zip_dir(string $dir, string $target): int
{
    $zip = new ZipArchive();
    if ($zip->open($target, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
        fwrite(STDERR, "cannot create $target\n");
        exit(1);
    }
    $count = 0;
    foreach (files_of($dir) as $file) {
        $zip->addFile($file->getPathname(), str_replace('\\', '/', substr($file->getPathname(), strlen($dir) + 1)));
        $count++;
    }
    $zip->close();
    return $count;
}

$linted = 0;
foreach (array_merge([$root . '/script.php'], ...array_map(static fn (string $e): array => array_map(
    static fn (SplFileInfo $f): string => $f->getPathname(),
    array_filter(files_of($root . '/packages/' . $e), static fn (SplFileInfo $f): bool => $f->getExtension() === 'php')
), EXTENSIONS)) as $php) {
    lint($php);
    $linted++;
}
foreach (array_merge([$root . '/pkg_openbackappauth.xml'], ...array_map(static fn (string $e): array => array_map(
    static fn (SplFileInfo $f): string => $f->getPathname(),
    array_filter(files_of($root . '/packages/' . $e), static fn (SplFileInfo $f): bool => $f->getExtension() === 'xml')
), EXTENSIONS)) as $xml) {
    if (@simplexml_load_file($xml) === false) {
        fwrite(STDERR, "invalid XML: $xml\n");
        exit(1);
    }
}

$stage = $root . '/dist/.stage';
@mkdir($stage . '/packages', 0777, true);
foreach (EXTENSIONS as $extension) {
    $n = zip_dir($root . '/packages/' . $extension, $stage . '/packages/' . $extension . '.zip');
    printf("  %s.zip (%d files)\n", $extension, $n);
}

$target = $root . '/dist/' . FILE_NAME;
@unlink($target);
$zip = new ZipArchive();
if ($zip->open($target, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
    fwrite(STDERR, "cannot create $target\n");
    exit(1);
}
$zip->addFile($root . '/pkg_openbackappauth.xml', 'pkg_openbackappauth.xml');
$zip->addFile($root . '/script.php', 'script.php');
$zip->addFile($root . '/LICENSE', 'LICENSE');
foreach (files_of($root . '/language') as $file) {
    $zip->addFile($file->getPathname(), 'language/' . str_replace('\\', '/', substr($file->getPathname(), strlen($root . '/language') + 1)));
}
foreach (EXTENSIONS as $extension) {
    $zip->addFile($stage . '/packages/' . $extension . '.zip', 'packages/' . $extension . '.zip');
}
$zip->close();

foreach (EXTENSIONS as $extension) {
    unlink($stage . '/packages/' . $extension . '.zip');
}
rmdir($stage . '/packages');
rmdir($stage);
printf("%s (%d PHP files linted)\n", $target, $linted);
