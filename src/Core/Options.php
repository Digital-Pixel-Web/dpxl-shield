<?php
declare(strict_types=1);

namespace DPXL\Shield\Core;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

class Options {

    private const PREFIX = 'dpxl_shield_';

    private static array $defaults = [
        'firewall_enabled'             => true,
        'firewall_mode'                => 'basic',         // basic | extended
        'waf_rules_version'            => '',
        'rate_limit_login'             => 5,               // per minute
        'rate_limit_xmlrpc'            => 3,
        'rate_limit_rest'              => 60,
        'rate_limit_404'               => 20,
        'brute_force_enabled'          => true,
        'brute_force_threshold'        => 5,
        'brute_force_lockout_minutes'  => 60,
        'login_hide_errors'            => true,
        'xmlrpc_disabled'              => false,
        'two_factor_required_roles'    => ['administrator'],
        'scan_schedule'                => 'daily',
        'scan_time'                    => '03:00',
        'alert_email'                  => '',
        'alert_email_enabled'          => true,
        'alert_rate_limit_hours'       => 1,
        'alert_admin_login_enabled'    => true,
        'smtp_monitor_enabled'         => true,
        'smtp_failure_threshold'       => 2,
        'activity_report_pdf_enabled'  => true,
        'traffic_log_enabled'          => true,
        'traffic_log_retention_hours'  => 24,
        'audit_log_mode'               => 'significant_events',
        'country_block_mode'           => 'block',         // block | allow
        'honeypot_enabled'             => true,
        'php_execution_blocker'        => true,
        'self_protection_enabled'      => true,
        'threat_feed_enabled'          => true,
        'threat_feed_version'          => '',
        'geo_db_enabled'               => true,
        'geo_db_sha'                   => '',
        'geo_db_version'               => '',
        'spamhaus_dqs_key'             => '',
        'webhook_endpoints'            => [],
        'webhook_status'               => [],
    ];

    public static function setDefaults(): void {
        foreach (self::$defaults as $key => $value) {
            if (get_option(self::PREFIX . $key) === false) {
                add_option(self::PREFIX . $key, $value, '', false);
            }
        }

        if (empty(get_option(self::PREFIX . 'alert_email'))) {
            update_option(self::PREFIX . 'alert_email', get_option('admin_email'));
        }
    }

    /**
     * @param  mixed $fallback
     * @return mixed
     */
    public static function get(string $key, $fallback = null) {
        $value = get_option(self::PREFIX . $key, null);

        if ($value === null) {
            return $fallback ?? (self::$defaults[$key] ?? null);
        }

        return $value;
    }

    /** @param mixed $value */
    public static function set(string $key, $value): bool {
        return update_option(self::PREFIX . $key, $value);
    }

    public static function delete(string $key): bool {
        return delete_option(self::PREFIX . $key);
    }

    public static function deleteAll(): void {
        global $wpdb;

        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s",
                self::PREFIX . '%'
            )
        );
    }
}
