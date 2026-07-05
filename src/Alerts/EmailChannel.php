<?php
declare(strict_types=1);

namespace DPXL\Shield\Alerts;

use DPXL\Shield\Core\Options;

/**
 * Email notification channel.
 *
 * Rate-limited to 1 email per event_type per hour to prevent flooding
 * during volumetric attacks. Rate-limit state is stored in transients.
 */
class EmailChannel {

    private const RATE_WINDOW = 3600; // 1 hour per event type

    /**
     * @param array<string,mixed> $context
     */
    public function send(
        string $level,
        string $eventType,
        string $description,
        array  $context = []
    ): void {
        if (!Options::get('email_alerts_enabled', true)) {
            return;
        }

        $recipient = Options::get('alert_email', get_option('admin_email'));

        if (!$recipient || !is_email((string) $recipient)) {
            return;
        }

        if ($this->isRateLimited($eventType)) {
            return;
        }

        $subject = $this->buildSubject($level, $eventType);
        $body    = $this->buildBody($level, $eventType, $description, $context);

        $headers = [
            'Content-Type: text/html; charset=UTF-8',
            'X-DPXL-Shield-Level: ' . $level,
        ];

        wp_mail((string) $recipient, $subject, $body, $headers);

        $this->markSent($eventType);
    }

    // ── Internals ──────────────────────────────────────────────────────────

    private function isRateLimited(string $eventType): bool {
        return (bool) get_transient('dpxl_alert_sent_' . md5($eventType));
    }

    private function markSent(string $eventType): void {
        set_transient('dpxl_alert_sent_' . md5($eventType), 1, self::RATE_WINDOW);
    }

    private function buildSubject(string $level, string $eventType): string {
        $siteName = get_option('blogname', get_option('siteurl'));
        $emoji    = match ($level) {
            'critical' => '[CRITICAL]',
            'high'     => '[HIGH]',
            'medium'   => '[WARNING]',
            default    => '[NOTICE]',
        };

        return sprintf('%s [%s] DPXL Shield — %s', $emoji, $siteName, $eventType);
    }

    /**
     * @param array<string,mixed> $context
     */
    private function buildBody(
        string $level,
        string $eventType,
        string $description,
        array  $context
    ): string {
        $siteUrl  = get_option('siteurl');
        $siteName = get_option('blogname', $siteUrl);
        $time     = gmdate('Y-m-d H:i:s') . ' UTC';
        $color    = match ($level) {
            'critical' => '#d63638',
            'high'     => '#f0b849',
            'medium'   => '#dba617',
            default    => '#2271b1',
        };

        $contextRows = '';

        foreach ($context as $key => $value) {
            $safeKey   = esc_html((string) $key);
            $safeValue = esc_html(is_array($value) ? wp_json_encode($value) : (string) $value);
            $contextRows .= "<tr><td style='padding:4px 8px;color:#666;'>{$safeKey}</td><td style='padding:4px 8px;'>{$safeValue}</td></tr>";
        }

        $contextTable = $contextRows
            ? "<table style='width:100%;border-collapse:collapse;margin-top:12px;font-size:13px;'>{$contextRows}</table>"
            : '';

        return <<<HTML
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"></head>
        <body style="font-family:Arial,sans-serif;background:#f6f7f7;margin:0;padding:20px;">
          <div style="max-width:600px;margin:0 auto;background:#fff;border-radius:6px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.08);">
            <div style="background:{$color};padding:16px 24px;">
              <h2 style="color:#fff;margin:0;font-size:18px;">DPXL Shield Alert</h2>
              <p style="color:rgba(255,255,255,.85);margin:4px 0 0;font-size:13px;">{$siteName} — {$siteUrl}</p>
            </div>
            <div style="padding:24px;">
              <table style="width:100%;border-collapse:collapse;font-size:14px;">
                <tr><td style="padding:6px 0;color:#666;width:120px;">Level</td><td style="padding:6px 0;font-weight:bold;color:{$color};">{$level}</td></tr>
                <tr><td style="padding:6px 0;color:#666;">Event</td><td style="padding:6px 0;">{$eventType}</td></tr>
                <tr><td style="padding:6px 0;color:#666;">Time</td><td style="padding:6px 0;">{$time}</td></tr>
                <tr><td style="padding:6px 0;color:#666;">Description</td><td style="padding:6px 0;">{$description}</td></tr>
              </table>
              {$contextTable}
              <hr style="border:none;border-top:1px solid #eee;margin:20px 0;">
              <p style="font-size:12px;color:#999;margin:0;">
                This alert was sent by <strong>DPXL Shield</strong> installed on <a href="{$siteUrl}" style="color:#2271b1;">{$siteUrl}</a>.
                <br>To manage alerts, go to <a href="{$siteUrl}/wp-admin/admin.php?page=dpxl-shield" style="color:#2271b1;">DPXL Shield Settings</a>.
              </p>
            </div>
          </div>
        </body>
        </html>
        HTML;
    }
}
