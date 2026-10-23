<?php
declare(strict_types=1);

namespace DPXL\Shield\Core;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

class Plugin {

    public static function activate(): void {
        Database::createTables();
        Options::setDefaults();

        // Record file integrity baseline for the scanner monitor.
        (new \DPXL\Shield\Scanner\FileIntegrityMonitor())->recordInitialBaseline();

        // Record self-protection tamper baseline.
        (new \DPXL\Shield\SelfProtection\TamperDetector())->recordBaseline();

        // Install PHP execution blocker in uploads directory.
        (new \DPXL\Shield\Hardening\PhpExecutionBlocker())->install();

        // Schedule cron jobs.
        \DPXL\Shield\Core\Cron::scheduleIfNeeded();

        // Config and blocklist snapshot for the pre-WordPress firewall.
        EarlyConfig::writeAll();

        flush_rewrite_rules();
    }

    public static function deactivate(): void {
        // Critical cleanup: remove Extended Protection rules before the plugin
        // can be deleted. The safe prepend loader is rewritten as a no-op so
        // the site stays online even if a host-level auto_prepend_file directive
        // still points to it.
        (new \DPXL\Shield\Bootstrap\AutoPrepend())->cleanupForPluginRemoval();

        // Remove PHP execution blocker from uploads directory.
        (new \DPXL\Shield\Hardening\PhpExecutionBlocker())->remove();

        \DPXL\Shield\Core\Cron::unschedule();
        flush_rewrite_rules();
    }
}
