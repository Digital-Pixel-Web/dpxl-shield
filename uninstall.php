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

// The self-protection store keeps its copies under names without the
// dpxl_shield_ prefix, so deleteAll() never reached them.
delete_option('_site_check_timeout_shwp');
delete_option('_site_check_enc_key');
@unlink(WP_CONTENT_DIR . '/.shieldwp-integrity');
@unlink(sys_get_temp_dir() . '/shwp-' . md5(ABSPATH) . '.lock');

// Per-user data: two-factor secrets and backup codes, known login IPs and the
// breached-password flag. Leaving the TOTP secrets behind would keep a working
// second factor in the database of a site that no longer uses the plugin.
foreach (['dpxl_shield_totp_secret', '_dpxl_shield_totp_secret', 'dpxl_shield_totp_enabled',
          'dpxl_shield_backup_codes', 'dpxl_shield_known_ips', '_dpxl_shield_pwned_password'] as $dpxlShieldMetaKey) {
    delete_metadata('user', 0, $dpxlShieldMetaKey, '', true);
}

// Transients (2FA tokens, lockouts, caches). They expire anyway; removing
// them now leaves the options table as it was before the plugin.
global $wpdb;

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
// before then would take the site down. Repair backups in
// wp-content/dpxl-shield-backups are kept too: they may hold original files.
