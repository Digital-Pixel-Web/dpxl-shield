<?php
declare(strict_types=1);

namespace DPXL\Shield\Alerts;

use DPXL\Shield\Core\Options;

/**
 * Periodic activity summary email.
 *
 * Runs on the dpxl_shield_activity_report cron hook.
 * Frequency: daily | weekly | monthly (configurable).
 * Covers: attacks blocked, top IPs/countries, login events, scan results.
 */
class ActivityReport {

    public function send(): void {
        if (!Options::get('activity_report_enabled', true)) {
            return;
        }

        $recipient = Options::get('alert_email', get_option('admin_email'));

        if (!$recipient || !is_email((string) $recipient)) {
            return;
        }

        $data    = $this->gatherData();
        $subject = $this->buildSubject($data);
        $body    = $this->buildBody($data);

        wp_mail(
            (string) $recipient,
            $subject,
            $body,
            ['Content-Type: text/html; charset=UTF-8']
        );

        Options::set('activity_report_last_sent', time());
    }

    // ── Data collection ────────────────────────────────────────────────────

    /** @return array<string,mixed> */
    private function gatherData(): array {
        global $wpdb;

        $freq  = Options::get('activity_report_frequency', 'weekly');
        $since = match ($freq) {
            'daily'   => date('Y-m-d H:i:s', strtotime('-1 day')),
            'monthly' => date('Y-m-d H:i:s', strtotime('-30 days')),
            default   => date('Y-m-d H:i:s', strtotime('-7 days')),
        };

        $logTable   = $wpdb->prefix . 'dpxl_shield_traffic_log';
        $blockedTable = $wpdb->prefix . 'dpxl_shield_blocked_ips';
        $loginTable  = $wpdb->prefix . 'dpxl_shield_login_events';
        $scanTable   = $wpdb->prefix . 'dpxl_shield_scan_results';

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

    // ── Email building ─────────────────────────────────────────────────────

    /** @param array<string,mixed> $data */
    private function buildSubject(array $data): string {
        $siteName = get_option('blogname', get_option('siteurl'));
        $label    = ucfirst((string) ($data['freq'] ?? 'weekly'));

        return "[{$siteName}] DPXL Shield {$label} Security Report";
    }

    /** @param array<string,mixed> $data */
    private function buildBody(array $data): string {
        $siteUrl   = get_option('siteurl');
        $siteName  = get_option('blogname', $siteUrl);
        $generated = gmdate('Y-m-d H:i:s') . ' UTC';
        $since     = substr((string) ($data['since'] ?? ''), 0, 10);

        $topIpRows = '';

        foreach ((array) ($data['topIps'] ?? []) as $row) {
            $ip   = esc_html((string) ($row['ip']   ?? ''));
            $hits = (int) ($row['hits'] ?? 0);
            $topIpRows .= "<tr><td style='padding:4px 12px;'>{$ip}</td><td style='padding:4px 12px;text-align:right;'>{$hits}</td></tr>";
        }

        $topIpsTable = $topIpRows
            ? "<table style='width:100%;border-collapse:collapse;font-size:13px;'><thead><tr><th style='text-align:left;padding:4px 12px;background:#f6f7f7;'>IP</th><th style='text-align:right;padding:4px 12px;background:#f6f7f7;'>Hits</th></tr></thead><tbody>{$topIpRows}</tbody></table>"
            : '<p style="color:#666;font-size:13px;">No attacks blocked in this period.</p>';

        $scanAlert = ((int) ($data['criticalIssues'] ?? 0)) > 0
            ? '<p style="background:#fef7f7;border-left:4px solid #d63638;padding:10px 14px;color:#d63638;margin:12px 0;">⚠ ' . (int) $data['criticalIssues'] . ' critical scan issues require your attention.</p>'
            : '';

        return <<<HTML
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"></head>
        <body style="font-family:Arial,sans-serif;background:#f6f7f7;margin:0;padding:20px;">
          <div style="max-width:600px;margin:0 auto;background:#fff;border-radius:6px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.08);">
            <div style="background:#1d2327;padding:16px 24px;">
              <h2 style="color:#fff;margin:0;font-size:18px;">🔒 DPXL Shield Security Report</h2>
              <p style="color:rgba(255,255,255,.6);margin:4px 0 0;font-size:13px;">{$siteName} · Since {$since}</p>
            </div>
            <div style="padding:24px;">
              {$scanAlert}
              <table style="width:100%;border-collapse:collapse;font-size:14px;margin-bottom:20px;">
                <tr><td style="padding:8px 0;color:#666;">Attacks Blocked</td><td style="padding:8px 0;font-size:24px;font-weight:bold;color:#d63638;">{$data['attacksBlocked']}</td></tr>
                <tr><td style="padding:8px 0;color:#666;">Login Success</td><td style="padding:8px 0;">{$data['loginSuccess']}</td></tr>
                <tr><td style="padding:8px 0;color:#666;">Login Failed</td><td style="padding:8px 0;">{$data['loginFailed']}</td></tr>
                <tr><td style="padding:8px 0;color:#666;">New Scan Issues</td><td style="padding:8px 0;">{$data['scanIssues']}</td></tr>
              </table>
              <h3 style="font-size:14px;color:#3c434a;margin:0 0 8px;">Top Blocked IPs</h3>
              {$topIpsTable}
              <hr style="border:none;border-top:1px solid #eee;margin:20px 0;">
              <p style="font-size:12px;color:#999;margin:0;">
                Generated {$generated} by <strong>DPXL Shield</strong>.
                <a href="{$siteUrl}/wp-admin/admin.php?page=dpxl-shield" style="color:#2271b1;">Open Dashboard</a>
              </p>
            </div>
          </div>
        </body>
        </html>
        HTML;
    }
}
