<?php
/**
 * PHP 7.4 polyfills for the PHP 8 string helpers.
 *
 * DPXL Shield supports PHP 7.4 (the same floor WordPress itself sets) but is
 * written against str_contains() and friends, which arrived in PHP 8.0.
 *
 * WordPress core ships these same polyfills in wp-includes/compat.php — but the
 * WAF runs through auto_prepend_file, *before* WordPress exists, so core's copy
 * is not available on that path. This file is required directly by both entry
 * points (dpxl-shield.php and dpxl-shield-waf.php) so the functions are defined
 * in every context the plugin runs in, with or without WordPress and with or
 * without the Composer autoloader.
 *
 * Every definition is guarded, so on PHP 8+ — or when core defined them first —
 * this file is a no-op.
 *
 * @package DPXL\Shield
 */

declare(strict_types=1);

if (!function_exists('str_contains')) {
    /**
     * @param string $haystack
     * @param string $needle
     * @return bool
     */
    function str_contains($haystack, $needle) {
        // '' is a substring of every string, including '' — and strpos()
        // returns 0 (falsy) there, so the empty needle needs its own branch.
        return $needle === '' || strpos($haystack, $needle) !== false;
    }
}

if (!function_exists('str_starts_with')) {
    /**
     * @param string $haystack
     * @param string $needle
     * @return bool
     */
    function str_starts_with($haystack, $needle) {
        return $needle === '' || strncmp($haystack, $needle, strlen($needle)) === 0;
    }
}

if (!function_exists('str_ends_with')) {
    /**
     * @param string $haystack
     * @param string $needle
     * @return bool
     */
    function str_ends_with($haystack, $needle) {
        if ($needle === '') {
            return true;
        }

        $length = strlen($needle);

        return $length <= strlen($haystack)
            && substr_compare($haystack, $needle, -$length) === 0;
    }
}
