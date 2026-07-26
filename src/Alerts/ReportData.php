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
     *     loginFailed: int, scanIssues: int, criticalIssues: int
     * }
     */
    public static function collect(string $freq): array {
        global $wpdb;

        $since = match ($freq) {
            'daily'   => date('Y-m-d H:i:s', strtotime('-1 day')),
            'monthly' => date('Y-m-d H:i:s', strtotime('-30 days')),
            default   => date('Y-m-d H:i:s', strtotime('-7 days')),
        };

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

        return compact(
            'freq', 'since', 'attacksBlocked',
            'topIps', 'loginSuccess', 'loginFailed',
            'scanIssues', 'criticalIssues'
        );
    }
}
