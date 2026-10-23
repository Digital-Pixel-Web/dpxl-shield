<?php
declare(strict_types=1);

namespace DPXL\Shield\SelfProtection;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

use DPXL\Shield\Core\Logger;

/**
 * Detects unauthorised modifications to the plugin's own PHP files.
 *
 * On activation a SHA-256 baseline is captured and stored in the
 * IntegrityStore (3-location redundant + encrypted).
 *
 * On every request (plugins_loaded, priority -10) the checksums are
 * recomputed and compared against the stored baseline. Any mismatch
 * fires a CRITICAL alert and optionally auto-deactivates.
 */
class TamperDetector {

    /** Plugin-root files to include outside of src/. */
    private const ROOT_FILES = [
        'dpxl-shield.php',
        'dpxl-shield-waf.php',
        'uninstall.php',
    ];

    private IntegrityStore $store;

    public function __construct() {
        $this->store = new IntegrityStore();
    }

    // ── Public API ─────────────────────────────────────────────────────────

    /** Called once during plugin activation to capture the initial baseline. */
    public function recordBaseline(): void {
        $checksums = $this->computeChecksums();
        $this->store->save($checksums);
    }

    /**
     * Called on plugins_loaded (priority -10) on every request.
     * Also re-records the baseline when the plugin version changes (e.g. after
     * an update), preventing false-positive tamper alerts on legitimate upgrades.
     */
    public static function verifyIntegrity(): void {
        $instance = new self();

        // Auto-update baseline when the plugin version advances.
        $storedVersion  = (string) get_option('dpxl_shield_integrity_version', '');
        $currentVersion = defined('DPXL_SHIELD_VERSION') ? DPXL_SHIELD_VERSION : '';

        if (self::shouldRebaseline($storedVersion, $currentVersion)) {
            $instance->recordBaseline();
            update_option('dpxl_shield_integrity_version', $currentVersion, false);
            return; // Baseline just recorded — nothing to compare against yet.
        }

        $instance->runVerification();
    }

    /**
     * Whether the integrity baseline must be re-recorded rather than compared.
     *
     * True only when the plugin version actually advanced — this is the guard
     * that stopped the v1.0.14 false-positive tamper alerts after legitimate
     * updates. An empty current version (constant missing) never rebaselines.
     */
    public static function shouldRebaseline(string $storedVersion, string $currentVersion): bool {
        return $currentVersion !== '' && $storedVersion !== $currentVersion;
    }

    // ── Internal ───────────────────────────────────────────────────────────

    private function runVerification(): void {
        $baseline = $this->store->load();

        if ($baseline === null) {
            // No baseline yet — skip (happens before first activation completes).
            return;
        }

        $current    = $this->computeChecksums();
        $mismatches = self::diffChecksums($baseline, $current);

        if (empty($mismatches)) {
            return;
        }

        Logger::error('TamperDetector: plugin file modification detected — ' . implode(', ', $mismatches));

        do_action('dpxl_shield_alert', [
            'level'       => 'critical',
            'event_type'  => 'plugin_tampered',
            'description' => 'DPXL Shield plugin files were modified: ' . implode(', ', array_slice($mismatches, 0, 5)),
            'context'     => ['files' => $mismatches],
        ]);
    }

    /** @return array<string,string>  relative_path => sha256 */
    private function computeChecksums(): array {
        $base      = defined('DPXL_SHIELD_PATH') ? DPXL_SHIELD_PATH : dirname(__DIR__, 2) . '/';
        $checksums = [];

        // Root-level files.
        foreach (self::ROOT_FILES as $file) {
            $path = $base . $file;
            if (file_exists($path)) {
                $checksums[$file] = hash_file('sha256', $path);
            }
        }

        // All PHP files under src/.
        $srcDir = $base . 'src';
        if (!is_dir($srcDir)) {
            return $checksums;
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($srcDir, \FilesystemIterator::SKIP_DOTS)
        );

        foreach ($iterator as $fileInfo) {
            /** @var \SplFileInfo $fileInfo */
            if ($fileInfo->getExtension() !== 'php') {
                continue;
            }

            $absolute = $fileInfo->getRealPath();
            $relative = 'src/' . ltrim(str_replace($srcDir, '', $absolute), DIRECTORY_SEPARATOR);
            $relative = str_replace(DIRECTORY_SEPARATOR, '/', $relative);

            $checksums[$relative] = hash_file('sha256', $absolute);
        }

        ksort($checksums);

        return $checksums;
    }

    /**
     * Returns relative paths that are added, removed, or changed.
     *
     * @param array<string,string> $baseline
     * @param array<string,string> $current
     * @return string[]
     */
    public static function diffChecksums(array $baseline, array $current): array {
        $mismatches = [];

        foreach ($current as $path => $hash) {
            if (!isset($baseline[$path])) {
                $mismatches[] = "added:{$path}";
            } elseif (!hash_equals($baseline[$path], $hash)) {
                $mismatches[] = "modified:{$path}";
            }
        }

        foreach (array_keys($baseline) as $path) {
            if (!isset($current[$path])) {
                $mismatches[] = "deleted:{$path}";
            }
        }

        return $mismatches;
    }
}
