<?php
declare(strict_types=1);

namespace DPXL\Shield\Scanner;

use DPXL\Shield\Core\Options;
use DPXL\Shield\Core\Logger;

/**
 * Continuous per-request monitor for critical WordPress and plugin files.
 *
 * Different from MalwareScanner (periodic): this runs on every WordPress
 * request (init hook, priority 1) and checks only a small curated list
 * of files whose modification would indicate active compromise.
 */
class FileIntegrityMonitor {

    /**
     * Critical WordPress core files checked on every request.
     * Relative paths from ABSPATH.
     */
    private const CRITICAL_CORE_FILES = [
        'wp-config.php',
        'wp-includes/functions.php',
        'wp-includes/pluggable.php',
        'wp-includes/class-wp-hook.php',
        'wp-includes/load.php',
        'wp-admin/includes/plugin.php',
    ];

    private ChecksumVerifier $verifier;

    public function __construct() {
        $this->verifier = new ChecksumVerifier();
    }

    // ── Hook Registration ──────────────────────────────────────────────────

    public function registerHooks(): void {
        // Per-request integrity check — priority 1 = runs before almost everything.
        add_action('init', [$this, 'checkCriticalFiles'], 1);

        // Re-record baselines after WordPress or plugin updates.
        add_action('upgrader_process_complete', [$this, 'onUpgrade'], 10, 2);

        // Alert handler.
        add_action('dpxl_shield_integrity_violation', [$this, 'handleViolation'], 10, 2);
    }

    // ── Per-request Check ──────────────────────────────────────────────────

    /**
     * Runs on `init` (priority 1). Fast: only checks the small critical list.
     */
    public function checkCriticalFiles(): void {
        if (!Options::get('file_integrity_monitor_enabled', true)) {
            return;
        }

        foreach (self::CRITICAL_CORE_FILES as $relative) {
            $absolute = ABSPATH . $relative;

            if (!file_exists($absolute)) {
                continue;
            }

            $status = $this->verifier->verify($absolute);

            if ($status === false) {
                do_action('dpxl_shield_integrity_violation', $absolute, $relative);
            }
            // null means no baseline yet — silent until first baseline is recorded.
        }

    }

    // ── Violation Handler ──────────────────────────────────────────────────

    public function handleViolation(string $absolutePath, string $relativePath): void {
        // Alert at most once per hour per modified file to prevent flooding on every request.
        // The admin sees the alert once and can review; repeated alerts serve no purpose.
        $transientKey = 'dpxl_integrity_alerted_' . md5($absolutePath);

        if (get_transient($transientKey)) {
            return;
        }

        set_transient($transientKey, true, HOUR_IN_SECONDS);

        Logger::error("Integrity violation: {$absolutePath}");

        do_action('dpxl_shield_alert', [
            'level'       => 'critical',
            'event_type'  => 'file_modified',
            'description' => "Critical file modified: {$relativePath}",
            'context'     => [
                'file'      => $relativePath,
                'timestamp' => current_time('mysql', true),
            ],
        ]);
    }

    // ── Baseline Management ────────────────────────────────────────────────

    /**
     * Records the initial baseline — called during plugin activation.
     */
    public function recordInitialBaseline(): void {
        // Core critical files.
        foreach (self::CRITICAL_CORE_FILES as $relative) {
            $absolute = ABSPATH . $relative;

            if (file_exists($absolute)) {
                $this->verifier->record($absolute, 'core');
            }
        }

        // Plugin own files.
        $this->recordPluginBaseline();

        update_option('dpxl_shield_integrity_baseline_at', current_time('mysql', true));
    }

    public function recordPluginBaseline(): void {
        $this->verifier->recordDirectory(DPXL_SHIELD_PATH . 'src/', 'shieldwp');
        $this->verifier->record(DPXL_SHIELD_PATH . 'dpxl-shield.php', 'shieldwp');
        $this->verifier->record(DPXL_SHIELD_PATH . 'dpxl-shield-waf.php', 'shieldwp');
    }

    /**
     * Called after a WordPress core or plugin update — re-records baselines
     * so the monitor doesn't alert on legitimate update-induced changes.
     */
    public function onUpgrade(mixed $upgrader, array $hookExtra): void {
        $type = $hookExtra['type'] ?? '';

        if ($type === 'core') {
            // Invalidate WP.org checksum cache so next scan fetches the new version.
            WpOrgChecksumApi::invalidateCache();

            foreach (self::CRITICAL_CORE_FILES as $relative) {
                $absolute = ABSPATH . $relative;

                if (file_exists($absolute)) {
                    $this->verifier->record($absolute, 'core');
                }
            }
        }

        if ($type === 'plugin') {
            // Re-record our own plugin files if we were updated.
            $plugins = $hookExtra['plugins'] ?? [];

            if (in_array(DPXL_SHIELD_BASENAME, $plugins, true)) {
                $this->recordPluginBaseline();
            }
        }
    }
}
