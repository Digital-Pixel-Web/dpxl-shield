<?php
/**
 * DPXL Shield — Early WAF Boot (Extended Protection)
 *
 * Referenced by auto_prepend_file in .htaccess / php.ini.
 * Runs before WordPress loads, blocking threats at the PHP runtime level.
 */

declare(strict_types=1);

// Only execute early boot when WordPress hasn't been loaded yet.
if (!defined('ABSPATH')) {
    // This constant persists for the whole PHP request. When WordPress later
    // loads the plugin normally, the admin UI can reliably detect that the
    // WAF was loaded through auto_prepend_file.
    if (!defined('DPXL_SHIELD_EXTENDED_ACTIVE')) {
        define('DPXL_SHIELD_EXTENDED_ACTIVE', true);
    }

    // Used by the Extended Protection installer to verify that auto_prepend_file
    // executed before WordPress. This header is harmless and avoids relying on
    // a database option that could say "active" without the loader actually running.
    if (!headers_sent()) {
        header('X-DPXL-Shield-Extended: active');
    }

    $dpxlPluginDir = __DIR__;

    // PHP 8 string helpers for the 7.4 floor. WordPress core's copy lives in
    // wp-includes/compat.php, which does not exist on this path — the WAF runs
    // before WordPress — so the plugin brings its own.
    require_once $dpxlPluginDir . '/src/Compat/php-polyfill.php';

    if (file_exists($dpxlPluginDir . '/vendor/autoload.php')) {
        require_once $dpxlPluginDir . '/vendor/autoload.php';
    } else {
        // Vendor not installed — skip early WAF, let WordPress boot normally.
        return;
    }

    \DPXL\Shield\Bootstrap\Loader::handleEarlyRequest();
}
