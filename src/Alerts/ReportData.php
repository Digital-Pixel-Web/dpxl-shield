<?php
declare(strict_types=1);

namespace DPXL\Shield\Alerts;

/**
 * Shared data collector for the periodic security report.
 *
 * Both the HTML email (ActivityReport) and the branded PDF (PdfReport) draw
 * from the same numbers, so the queries live here once. The shape returned is
 * the contract both renderers rely on.
 */
class ReportData {

    /**
     * Collect the report figures for the given reporting window.
     *
     * @param  string $freq daily | weekly | monthly
     * @return array{
     *     freq: string, since: string, attacksBlocked: int,
     *     topIps: array<int,array<string,mixed>>, loginSuccess: int,
     *     loginFailed: int, scanIssues: int, criticalIssues: int,
     *     updatesNeeded: int, vulnComponents: array<int,array<string,mixed>>,
     *     topCountries: array<int,array<string,mixed>>,
     *     topFailedUsers: array<int,array<string,mixed>>,
     *     recentAttacks: array<int,array<string,mixed>>,
     *     modifiedFiles: array<int,array<string,mixed>>
     * }
     */
    public static function collect(string $freq): array {
        global $wpdb;

        $windows = [
            'daily'   => '-1 day',
            'monthly' => '-30 days',
        ];

        $since = date('Y-m-d H:i:s', strtotime($windows[$freq] ?? '-7 days'));

        $logTable     = $wpdb->prefix . 'dpxl_shield_traffic_log';
        $loginTable   = $wpdb->prefix . 'dpxl_shield_login_events';
        $scanTable    = $wpdb->prefix . 'dpxl_shield_scan_results';

        // Total attacks blocked.
        $attacksBlocked = (int) $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$logTable} WHERE waf_action='block' AND timestamp >= %s",
                $since
            )
        );

        // Top 5 blocked IPs.
        $topIps = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT ip, COUNT(*) as hits FROM {$logTable}
                 WHERE waf_action='block' AND timestamp >= %s
                 GROUP BY ip ORDER BY hits DESC LIMIT 5",
                $since
            ),
            ARRAY_A
        ) ?? [];

        // Successful logins.
        $loginSuccess = (int) $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$loginTable} WHERE result='success' AND timestamp >= %s",
                $since
            )
        );

        // Failed logins.
        $loginFailed = (int) $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$loginTable} WHERE result='failure' AND timestamp >= %s",
                $since
            )
        );

        // New scan issues.
        $scanIssues = (int) $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$scanTable} WHERE status='new' AND scanned_at >= %s",
                $since
            )
        );

        // Critical scan issues.
        $criticalIssues = (int) $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$scanTable} WHERE status='new' AND severity='critical' AND scanned_at >= %s",
                $since
            )
        );

        // Components running an outdated / vulnerable version (VulnerabilityScanner,
        // stage 9). DISTINCT file_path so repeated daily scans don't inflate the count.
        $updatesNeeded = (int) $wpdb->get_var(
            "SELECT COUNT(DISTINCT file_path) FROM {$scanTable}
             WHERE status='new' AND issue_type='vulnerable_version'"
        );

        // The components themselves (deduped), for a short "needs update" list.
        $vulnComponents = $wpdb->get_results(
            "SELECT file_path, MAX(details) AS details, MAX(severity) AS severity
             FROM {$scanTable}
             WHERE status='new' AND issue_type='vulnerable_version'
             GROUP BY file_path ORDER BY MAX(scanned_at) DESC LIMIT 5",
            ARRAY_A
        ) ?? [];

        // Top 5 blocked countries.
        $topCountries = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT country, COUNT(*) as hits FROM {$logTable}
                 WHERE waf_action='block' AND country IS NOT NULL AND country <> '' AND timestamp >= %s
                 GROUP BY country ORDER BY hits DESC LIMIT 5",
                $since
            ),
            ARRAY_A
        ) ?? [];

        // Top 5 usernames by failed-login attempts.
        $topFailedUsers = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT user_login, COUNT(*) as hits FROM {$loginTable}
                 WHERE result='failure' AND timestamp >= %s
                 GROUP BY user_login ORDER BY hits DESC LIMIT 5",
                $since
            ),
            ARRAY_A
        ) ?? [];

        // Most recent blocked attacks (time / IP / rule).
        $recentAttacks = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT timestamp, ip, waf_rule_id FROM {$logTable}
                 WHERE waf_action='block' AND timestamp >= %s
                 ORDER BY timestamp DESC LIMIT 8",
                $since
            ),
            ARRAY_A
        ) ?? [];

        // Recently changed files flagged by the integrity scan (deduped by path).
        $modifiedFiles = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT file_path, MAX(scanned_at) AS scanned_at, MAX(issue_type) AS issue_type FROM {$scanTable}
                 WHERE issue_type IN ('modified_core','modified_plugin') AND scanned_at >= %s
                 GROUP BY file_path ORDER BY scanned_at DESC LIMIT 8",
                $since
            ),
            ARRAY_A
        ) ?? [];

        return compact(
            'freq', 'since', 'attacksBlocked',
            'topIps', 'loginSuccess', 'loginFailed',
            'scanIssues', 'criticalIssues',
            'updatesNeeded', 'vulnComponents', 'topCountries', 'topFailedUsers',
            'recentAttacks', 'modifiedFiles'
        );
    }
}
