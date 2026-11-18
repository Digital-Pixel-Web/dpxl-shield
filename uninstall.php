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

// The self-protection store: deleteAll() took its options; this removes its
// copy in the temp folder and the unprefixed copies 1.12.0 and earlier wrote.
\DPXL\Shield\SelfProtection\IntegrityStore::deleteLegacy();
wp_delete_file(\DPXL\Shield\SelfProtection\IntegrityStore::tempFilePath());

// Runtime files in the data folder (uploads/dpxl-shield), and the folder
// inside the plugin that 1.12.0 and earlier used. Repair backups in backups/
// stay: they may hold the only copy of an original file.
foreach ([\DPXL\Shield\Core\EarlyConfig::dataDir(), \DPXL\Shield\Core\EarlyConfig::legacyDataDir()] as $dpxlShieldDir) {
    if (!is_dir($dpxlShieldDir)) {
        continue;
    }

    $dpxlShieldKeep = is_dir($dpxlShieldDir . '/backups');

    foreach (array_merge((array) glob($dpxlShieldDir . '/*'), [$dpxlShieldDir . '/.htaccess']) as $dpxlShieldFile) {
        if (!is_string($dpxlShieldFile) || !is_file($dpxlShieldFile)) {
            continue;
        }

        // With backups left behind, the folder keeps its web lock.
        if ($dpxlShieldKeep && in_array(basename($dpxlShieldFile), ['.htaccess', 'index.php'], true)) {
            continue;
        }

        wp_delete_file($dpxlShieldFile);
    }

    if (!$dpxlShieldKeep) {
        require_once ABSPATH . 'wp-admin/includes/class-wp-filesystem-base.php';
        require_once ABSPATH . 'wp-admin/includes/class-wp-filesystem-direct.php';
        (new WP_Filesystem_Direct(null))->rmdir($dpxlShieldDir);
    }
}

// Per-user data: two-factor secrets (also half-finished setups) and backup
// codes, known login IPs and the breached-password flag. Leaving the TOTP
// secrets behind would keep a working second factor in the database of a site
// that no longer uses the plugin. Deleted by prefix so new keys are covered.
global $wpdb;

foreach (['dpxl_shield_', '_dpxl_shield_'] as $dpxlShieldPrefix) {
    $wpdb->query(
        $wpdb->prepare(
            "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE %s",
            $wpdb->esc_like($dpxlShieldPrefix) . '%'
        )
    );
}

wp_cache_flush();

// Transients (2FA tokens, lockouts, caches). They expire anyway; removing
// them now leaves the options table as it was before the plugin.

foreach (['_transient_dpxl', '_transient_timeout_dpxl', '_site_transient_dpxl', '_site_transient_timeout_dpxl'] as $dpxlShieldPrefix) {
    $wpdb->query(
        $wpdb->prepare(
            "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s",
            $wpdb->esc_like($dpxlShieldPrefix) . '%'
        )
    );
}

// The prepend file and .user.ini are left as harmless no-ops on purpose: PHP
// caches .user.ini for up to five minutes, and deleting the file it points to
// before then would take the site down.
