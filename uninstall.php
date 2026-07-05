<?php
declare(strict_types=1);

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

if (!defined('DPXL_SHIELD_PATH')) {
    define('DPXL_SHIELD_PATH', plugin_dir_path(__FILE__));
}

if (!defined('DPXL_SHIELD_FILE')) {
    define('DPXL_SHIELD_FILE', __FILE__);
}

if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require_once __DIR__ . '/vendor/autoload.php';
}

// Remove Extended Protection before deleting options/tables. This prevents the
// site from going down because auto_prepend_file still points to DPXL Shield.
(new \DPXL\Shield\Bootstrap\AutoPrepend())->cleanupForPluginRemoval();

\DPXL\Shield\Core\Database::dropAllTables();
\DPXL\Shield\Core\Options::deleteAll();
