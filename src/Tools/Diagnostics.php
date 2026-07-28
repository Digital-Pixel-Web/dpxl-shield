<?php
declare(strict_types=1);

namespace DPXL\Shield\Tools;

/**
 * Collects environment diagnostic data for the admin panel.
 *
 * Each check returns:
 *   status  → ok | warning | error
 *   label   → human-readable name
 *   value   → current value/state
 *   note    → optional explanation
 */
class Diagnostics {

    /**
     * @return array<string, array{status: string, label: string, value: string, note: string}>
     */
    public function run(): array {
        return [
            'php_version'        => $this->checkPhpVersion(),
            'wp_version'         => $this->checkWpVersion(),
            'openssl'            => $this->checkExtension('openssl'),
            'mbstring'           => $this->checkExtension('mbstring'),
            'hash'               => $this->checkExtension('hash'),
            'json'               => $this->checkExtension('json'),
            'curl'               => $this->checkExtension('curl'),
            'apcu'               => $this->checkApcu(),
            'opcache'            => $this->checkOpcache(),
            'extended_mode'      => $this->checkExtendedMode(),
            'wp_config_perms'    => $this->checkFilePerms(ABSPATH . 'wp-config.php', '0400-0640'),
            'uploads_perms'      => $this->checkDirPerms(wp_upload_dir()['basedir'] ?? '', '0755'),
            'maxmind_db'         => $this->checkMaxMindDb(),
            'wp_cron'            => $this->checkWpCron(),
            'threat_feed'        => $this->checkThreatFeed(),
            'disk_space'         => $this->checkDiskSpace(),
            'mysql_version'      => $this->checkMysqlVersion(),
        ];
    }

    // ── Checks ─────────────────────────────────────────────────────────────

    /** @return array{status:string,label:string,value:string,note:string} */
    private function checkThreatFeed(): array {
        if (!get_option('dpxl_shield_threat_feed_enabled', true)) {
            return ['status' => 'warning', 'label' => 'Threat Feed', 'value' => 'Disabled', 'note' => ''];
        }

        $version    = (string) get_option('dpxl_shield_threat_feed_version', '');
        $lastStatus = (string) get_option('dpxl_shield_threat_feed_last_status', '');
        $lastRun    = (int) get_option('dpxl_shield_threat_feed_last_run', 0);

        if ($lastRun === 0) {
            $status = 'warning';
        } elseif (in_array($lastStatus, ['ok', 'no_change'], true)) {
            $status = 'ok';
        } elseif (in_array($lastStatus, ['sig_fail', 'hash_fail'], true)) {
            $status = 'error';
        } else {
            $status = 'warning';
        }

        $value = $version !== ''
            ? 'v' . $version . ($lastStatus !== '' ? ' (' . $lastStatus . ')' : '')
            : ($lastRun === 0 ? 'Never run' : '(' . ($lastStatus ?: 'pending') . ')');

        $notes = [
            'sig_fail'  => 'Feed failed signature/integrity verification and was NOT applied. Possible feed-channel tampering.',
            'hash_fail' => 'Feed failed signature/integrity verification and was NOT applied. Possible feed-channel tampering.',
            'net_fail'  => 'Could not reach the feed. Rules stay at the last good version.',
            'no_pubkey' => 'No feed public key or ext-sodium — feed cannot be verified.',
        ];

        $note = $notes[$lastStatus] ?? '';

        return ['status' => $status, 'label' => 'Threat Feed', 'value' => $value, 'note' => $note];
    }

    /** @return array{status:string,label:string,value:string,note:string} */
    private function checkPhpVersion(): array {
        $version = PHP_VERSION;
        $status  = version_compare($version, '8.1', '>=') ? 'ok' : 'error';

        return [
            'status' => $status,
            'label'  => 'PHP Version',
            'value'  => $version,
            'note'   => $status === 'error' ? 'PHP 8.1 or higher is required.' : '',
        ];
    }

    /** @return array{status:string,label:string,value:string,note:string} */
    private function checkWpVersion(): array {
        global $wp_version;
        $current = $wp_version ?? 'unknown';
        $status  = version_compare($current, '6.4', '>=') ? 'ok' : 'error';

        return [
            'status' => $status,
            'label'  => 'WordPress Version',
            'value'  => $current,
            'note'   => $status === 'error' ? 'WordPress 6.4 or higher is required.' : '',
        ];
    }

    /** @return array{status:string,label:string,value:string,note:string} */
    private function checkExtension(string $name): array {
        $loaded = extension_loaded($name);

        return [
            'status' => $loaded ? 'ok' : 'error',
            'label'  => "PHP Extension: {$name}",
            'value'  => $loaded ? 'Loaded' : 'Not loaded',
            'note'   => $loaded ? '' : "The {$name} extension is required by DPXL Shield.",
        ];
    }

    /** @return array{status:string,label:string,value:string,note:string} */
    private function checkApcu(): array {
        $loaded = extension_loaded('apcu') && function_exists('apcu_fetch');
        $enabled = $loaded && (bool) ini_get('apc.enabled');

        return [
            'status' => ($loaded && $enabled) ? 'ok' : 'warning',
            'label'  => 'APCu Cache',
            'value'  => ($loaded && $enabled) ? 'Available' : ($loaded ? 'Loaded but disabled' : 'Not available'),
            'note'   => (!$loaded || !$enabled) ? 'APCu is recommended for rate limiting performance.' : '',
        ];
    }

    /** @return array{status:string,label:string,value:string,note:string} */
    private function checkOpcache(): array {
        $loaded  = extension_loaded('Zend OPcache');
        $enabled = $loaded && (bool) ini_get('opcache.enable');

        return [
            'status' => ($loaded && $enabled) ? 'ok' : 'warning',
            'label'  => 'OPcache',
            'value'  => ($loaded && $enabled) ? 'Enabled' : 'Disabled/Not available',
            'note'   => (!$loaded || !$enabled) ? 'OPcache improves overall PHP performance.' : '',
        ];
    }

    /** @return array{status:string,label:string,value:string,note:string} */
    private function checkExtendedMode(): array {
        $active = defined('DPXL_SHIELD_EXTENDED_ACTIVE');

        return [
            'status' => $active ? 'ok' : 'warning',
            'label'  => 'Extended Protection (WAF)',
            'value'  => $active ? 'Active' : 'Inactive (Basic Mode)',
            'note'   => $active ? '' : 'Extended Protection intercepts requests before WordPress loads. Go to Firewall → Extended Protection to enable it.',
        ];
    }

    /** @return array{status:string,label:string,value:string,note:string} */
    private function checkFilePerms(string $path, string $expectedRange): array {
        if (!file_exists($path)) {
            return ['status' => 'warning', 'label' => 'File Permissions: ' . basename($path), 'value' => 'File not found', 'note' => ''];
        }

        $perms  = substr(sprintf('%o', fileperms($path)), -4);
        $oct    = octdec($perms);
        $status = ($oct <= octdec('0640')) ? 'ok' : 'warning';

        return [
            'status' => $status,
            'label'  => 'File Permissions: ' . basename($path),
            'value'  => $perms,
            'note'   => $status === 'warning' ? "Recommended: {$expectedRange}. Current permissions may be too permissive." : '',
        ];
    }

    /** @return array{status:string,label:string,value:string,note:string} */
    private function checkDirPerms(string $path, string $expected): array {
        if (!is_dir($path)) {
            return ['status' => 'warning', 'label'  => 'Directory: uploads', 'value'  => 'Not found', 'note' => ''];
        }

        $perms  = substr(sprintf('%o', fileperms($path)), -4);
        $oct    = octdec($perms);
        $status = ($oct <= octdec('0755')) ? 'ok' : 'warning';

        return [
            'status' => $status,
            'label'  => 'Directory: uploads',
            'value'  => $perms,
            'note'   => $status === 'warning' ? "Recommended: {$expected}." : '',
        ];
    }

    /** @return array{status:string,label:string,value:string,note:string} */
    private function checkMaxMindDb(): array {
        $path   = defined('DPXL_SHIELD_PATH') ? DPXL_SHIELD_PATH . 'data/GeoLite2-Country.mmdb' : '';
        $exists = $path && file_exists($path);

        $version    = (string) get_option('dpxl_shield_geo_db_version', '');
        $lastStatus = (string) get_option('dpxl_shield_geo_db_last_status', '');
        $lastRun    = (int) get_option('dpxl_shield_geo_db_last_run', 0);
        $enabled    = (bool) get_option('dpxl_shield_geo_db_enabled', true);

        // The DB is what actually makes country features work, so a missing file
        // is the headline regardless of how the last update run went.
        if (!$exists) {
            return [
                'status' => 'warning',
                'label'  => 'MaxMind GeoLite2 DB',
                'value'  => $enabled ? 'Not installed yet' : 'Not installed (auto-update off)',
                'note'   => $enabled
                    ? 'Country features stay idle until the database downloads. It installs itself on the daily update — or use "Check now" in All Options to fetch it immediately.'
                    : 'Auto-update is disabled, so the database will never download. Enable it in All Options → Firewall.',
            ];
        }

        // Stale is a real risk here: MaxMind requires redistributed copies to be
        // under 30 days old, and an old DB silently mislabels traffic.
        $ageDays = (int) floor((time() - (int) filemtime($path)) / DAY_IN_SECONDS);

        $verificationFailed = in_array($lastStatus, ['sig_fail', 'hash_fail'], true);
        $stale              = $ageDays > 30;

        if ($verificationFailed) {
            $status = 'error';
        } elseif ($stale || !$enabled || $lastRun === 0) {
            $status = 'warning';
        } else {
            $status = 'ok';
        }

        $value = 'Present (' . $this->humanSize((int) filesize($path)) . ')'
            . ($version !== '' ? ' · ' . $version : '')
            . ($lastStatus !== '' ? ' · ' . $lastStatus : '');

        if ($verificationFailed) {
            $note = 'The downloaded database failed signature/integrity verification and was NOT applied. Possible feed-channel tampering.';
        } elseif ($stale) {
            $note = "Database is {$ageDays} days old. MaxMind requires redistributed copies to stay under 30 days — check that the daily cron is running.";
        } elseif (!$enabled) {
            $note = 'Auto-update is disabled; this database will go stale. Enable it in All Options → Firewall.';
        } elseif ($lastStatus === 'net_fail') {
            $note = 'Could not reach the feed on the last run. The current database stays in use.';
        } elseif ($lastRun === 0) {
            $note = 'Auto-update has not run yet.';
        } else {
            $note = '';
        }

        return [
            'status' => $status,
            'label'  => 'MaxMind GeoLite2 DB',
            'value'  => $value,
            'note'   => $note,
        ];
    }

    /** @return array{status:string,label:string,value:string,note:string} */
    private function checkWpCron(): array {
        $lastRun = (int) get_option('dpxl_shield_last_cron_run', 0);
        $ago     = $lastRun ? (time() - $lastRun) : PHP_INT_MAX;
        $status  = $ago < 7200 ? 'ok' : ($lastRun === 0 ? 'warning' : 'error');
        $label   = $lastRun ? gmdate('Y-m-d H:i:s', $lastRun) . ' UTC' : 'Never';

        return [
            'status' => $status,
            'label'  => 'WP Cron',
            'value'  => $label,
            'note'   => $status === 'error' ? 'DPXL Shield cron has not run in >2 hours. Check WP-Cron configuration.' : '',
        ];
    }

    /** @return array{status:string,label:string,value:string,note:string} */
    private function checkDiskSpace(): array {
        $free   = (float) @disk_free_space(WP_CONTENT_DIR);
        $status = $free > 50 * 1024 * 1024 ? 'ok' : ($free > 10 * 1024 * 1024 ? 'warning' : 'error');

        return [
            'status' => $status,
            'label'  => 'Disk Space (wp-content)',
            'value'  => $this->humanSize((int) $free) . ' free',
            'note'   => $status !== 'ok' ? 'Low disk space may affect scan results and log storage.' : '',
        ];
    }

    /** @return array{status:string,label:string,value:string,note:string} */
    private function checkMysqlVersion(): array {
        global $wpdb;
        $version = $wpdb->get_var('SELECT VERSION()') ?? 'unknown';
        $status  = version_compare($version, '5.7', '>=') ? 'ok' : 'warning';

        return [
            'status' => $status,
            'label'  => 'MySQL / MariaDB Version',
            'value'  => $version,
            'note'   => $status === 'warning' ? 'MySQL 5.7+ or MariaDB 10.4+ recommended.' : '',
        ];
    }

    private function humanSize(int $bytes): string {
        if ($bytes >= 1073741824) {
            return round($bytes / 1073741824, 1) . ' GB';
        }

        if ($bytes >= 1048576) {
            return round($bytes / 1048576, 1) . ' MB';
        }

        return round($bytes / 1024, 1) . ' KB';
    }
}
