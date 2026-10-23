<?php
declare(strict_types=1);

namespace DPXL\Shield\Core;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

use DPXL\Shield\Scanner\ScanOrchestrator;
use DPXL\Shield\Alerts\ActivityReport;
use DPXL\Shield\Scanner\ReputationChecker;
use DPXL\Shield\Threat\ThreatFeedUpdater;
use DPXL\Shield\Threat\GeoDbUpdater;

/**
 * WP-Cron schedule registration and hook handlers.
 */
class Cron {

    private const HOOK_FULL_SCAN        = 'dpxl_shield_full_scan';
    private const HOOK_INCREMENTAL_SCAN = 'dpxl_shield_incremental_scan';
    private const HOOK_CLEANUP          = 'dpxl_shield_cleanup';
    private const HOOK_ACTIVITY_REPORT  = 'dpxl_shield_activity_report';
    private const HOOK_REPUTATION_CHECK = 'dpxl_shield_reputation_check';
    private const HOOK_THREAT_FEED      = 'dpxl_shield_threat_feed_update';

    public static function register(): void {
        // Register custom intervals.
        add_filter('cron_schedules', [self::class, 'addIntervals']);

        // Attach handlers.
        add_action(self::HOOK_FULL_SCAN,        [self::class, 'runFullScan']);
        add_action(self::HOOK_INCREMENTAL_SCAN, [self::class, 'runIncrementalScan']);
        add_action(self::HOOK_CLEANUP,          [self::class, 'runCleanup']);
        add_action(self::HOOK_ACTIVITY_REPORT,  [self::class, 'runActivityReport']);
        add_action(self::HOOK_REPUTATION_CHECK, [self::class, 'runReputationCheck']);
        add_action(self::HOOK_THREAT_FEED,      [self::class, 'runThreatFeedUpdate']);

        // Schedule if not already scheduled.
        self::scheduleIfNeeded();
    }

    public static function addIntervals(array $schedules): array {
        // cron_schedules can run before `init`; translating then triggers the
        // "translation loaded too early" notice. English is fine until init.
        $translate = did_action('init') > 0;

        $schedules['dpxl_hourly_scan'] = [
            'interval' => HOUR_IN_SECONDS,
            'display'  => ($translate ? __('Every Hour (DPXL Shield incremental scan)', 'dpxl-shield') : 'Every Hour (DPXL Shield incremental scan)'),
        ];

        $schedules['dpxl_weekly'] = [
            'interval' => WEEK_IN_SECONDS,
            'display'  => ($translate ? __('Weekly (DPXL Shield activity report)', 'dpxl-shield') : 'Weekly (DPXL Shield activity report)'),
        ];

        $schedules['dpxl_monthly'] = [
            'interval' => 30 * DAY_IN_SECONDS,
            'display'  => ($translate ? __('Monthly (DPXL Shield activity report)', 'dpxl-shield') : 'Monthly (DPXL Shield activity report)'),
        ];

        return $schedules;
    }

    public static function scheduleIfNeeded(): void {
        $scanHour = (int) Options::get('scan_time_hour', 3);

        if (!wp_next_scheduled(self::HOOK_FULL_SCAN)) {
            // Schedule daily scan at the configured hour.
            $nextRun = mktime($scanHour, 0, 0) + (time() > mktime($scanHour, 0, 0) ? DAY_IN_SECONDS : 0);
            wp_schedule_event($nextRun, 'daily', self::HOOK_FULL_SCAN);
        }

        if (!wp_next_scheduled(self::HOOK_INCREMENTAL_SCAN)) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'dpxl_hourly_scan', self::HOOK_INCREMENTAL_SCAN);
        }

        if (!wp_next_scheduled(self::HOOK_CLEANUP)) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', self::HOOK_CLEANUP);
        }

        // Activity report — frequency based on option.
        $reportFreq = Options::get('activity_report_frequency', 'weekly');
        $recurrences = [
            'daily'   => 'daily',
            'monthly' => 'dpxl_monthly',
        ];

        $reportRecurrence = $recurrences[$reportFreq] ?? 'dpxl_weekly';

        if (!wp_next_scheduled(self::HOOK_ACTIVITY_REPORT)) {
            wp_schedule_event(time() + DAY_IN_SECONDS, $reportRecurrence, self::HOOK_ACTIVITY_REPORT);
        }

        // Reputation check — daily.
        if (!wp_next_scheduled(self::HOOK_REPUTATION_CHECK)) {
            wp_schedule_event(time() + 2 * HOUR_IN_SECONDS, 'daily', self::HOOK_REPUTATION_CHECK);
        }

        // Threat feed — daily, with a random offset so installations don't all
        // hit the CDN at the same minute (jitter).
        if (!wp_next_scheduled(self::HOOK_THREAT_FEED)) {
            $jitter = random_int(0, 6 * HOUR_IN_SECONDS);
            wp_schedule_event(time() + HOUR_IN_SECONDS + $jitter, 'daily', self::HOOK_THREAT_FEED);
        }
    }

    public static function unschedule(): void {
        foreach ([
            self::HOOK_FULL_SCAN, self::HOOK_INCREMENTAL_SCAN, self::HOOK_CLEANUP,
            self::HOOK_ACTIVITY_REPORT, self::HOOK_REPUTATION_CHECK, self::HOOK_THREAT_FEED,
        ] as $hook) {
            $timestamp = wp_next_scheduled($hook);

            if ($timestamp !== false) {
                wp_unschedule_event($timestamp, $hook);
            }
        }
    }

    // ── Cron Job Handlers ──────────────────────────────────────────────────

    public static function runFullScan(): void {
        Logger::debug('Cron: starting full malware scan.');
        (new ScanOrchestrator())->runFullScan();
    }

    public static function runIncrementalScan(): void {
        Logger::debug('Cron: starting incremental scan.');
        (new ScanOrchestrator())->runIncrementalScan();
    }

    public static function runActivityReport(): void {
        Logger::debug('Cron: sending activity report.');
        (new ActivityReport())->send();
        update_option('dpxl_shield_last_cron_run', time());
    }

    public static function runReputationCheck(): void {
        Logger::debug('Cron: running reputation check.');
        (new ReputationChecker())->run();
        update_option('dpxl_shield_last_cron_run', time());
    }

    public static function runThreatFeedUpdate(): void {
        Logger::debug('Cron: checking threat feed for updates.');
        $status = (new ThreatFeedUpdater())->run();
        Logger::debug('Cron: threat feed update status = ' . $status);

        // Same daily cadence keeps the GeoLite2 DB fresh automatically. The check
        // is cheap when unchanged (only the small manifest is fetched); the ~4 MB
        // download happens only when MaxMind publishes a newer database.
        $geoStatus = (new GeoDbUpdater())->run();
        Logger::debug('Cron: geo DB update status = ' . $geoStatus);

        update_option('dpxl_shield_last_cron_run', time());
    }

    public static function runCleanup(): void {
        global $wpdb;

        // Delete traffic log entries older than the configured retention period.
        $retentionHours = (int) Options::get('traffic_log_retention_hours', 24);
        $cutoff         = gmdate('Y-m-d H:i:s', time() - $retentionHours * HOUR_IN_SECONDS);

        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$wpdb->prefix}dpxl_shield_traffic_log WHERE timestamp < %s",
                $cutoff
            )
        );

        // Delete expired rate-limit buckets.
        $windowAgo = gmdate('Y-m-d H:i:s', time() - 3600);
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$wpdb->prefix}dpxl_shield_rate_buckets WHERE window_start < %s",
                $windowAgo
            )
        );

        Logger::debug('Cron: cleanup complete.');
    }
}
