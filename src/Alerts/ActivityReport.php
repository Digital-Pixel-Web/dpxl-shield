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

        // Attach the branded PDF when enabled. A render/write failure must never
        // block the report — the HTML email still goes out on its own.
        $attachments = [];
        $pdfPath     = null;

        if (Options::get('activity_report_pdf_enabled', true)) {
            $pdfPath = (new PdfReport())->renderToFile($data);

            if ($pdfPath !== null) {
                $attachments[] = $pdfPath;
            }
        }

        wp_mail(
            (string) $recipient,
            $subject,
            $body,
            ['Content-Type: text/html; charset=UTF-8'],
            $attachments
        );

        if ($pdfPath !== null && file_exists($pdfPath)) {
            @unlink($pdfPath);
        }

        Options::set('activity_report_last_sent', time());
    }

    // ── Data collection ────────────────────────────────────────────────────

    /** @return array<string,mixed> */
    private function gatherData(): array {
        return ReportData::collect((string) Options::get('activity_report_frequency', 'weekly'));
    }

    // ── Email building ─────────────────────────────────────────────────────

    /** @param array<string,mixed> $data */
    private function buildSubject(array $data): string {
        $siteName = (string) get_option('blogname', '');
        $siteName = $siteName !== '' ? $siteName : EmailTemplate::siteHost();

        return sprintf(
            /* translators: 1: period label, 2: site name */
            __('[DPXL Shield] %1$s security report — %2$s', 'dpxl-shield'),
            $this->periodLabel((string) ($data['freq'] ?? 'weekly')),
            $siteName
        );
    }

    /** @param array<string,mixed> $data */
    private function buildBody(array $data): string {
        $criticals = (int) ($data['criticalIssues'] ?? 0);
        $issues    = (int) ($data['scanIssues'] ?? 0);

        // The report is routine by nature — it only borrows an alert colour
        // when the period actually ended with something to act on.
        $level   = $criticals > 0 ? 'critical' : ($issues > 0 ? 'medium' : 'info');
        $palette = EmailTemplate::palette($level);

        $period = $this->periodLabel((string) ($data['freq'] ?? 'weekly'));
        $since  = strtotime((string) ($data['since'] ?? '')) ?: time();
        $title  = sprintf(__('%s security report', 'dpxl-shield'), $period);

        $headline = $criticals > 0
            ? EmailTemplate::callout(
                sprintf(
                    /* translators: %d: number of critical issues */
                    _n(
                        '%d critical issue from the latest scan is still unresolved.',
                        '%d critical issues from the latest scan are still unresolved.',
                        $criticals,
                        'dpxl-shield'
                    ),
                    $criticals
                ),
                $palette['accent'],
                $palette['tint']
            )
            : '';

        $content = EmailTemplate::pill($period, $palette['accent'], $palette['tint'])
            . '<h1 style="margin:16px 0 0;font-size:21px;line-height:1.3;font-weight:600;color:#1d2327;">'
            . esc_html($title) . '</h1>'
            . '<p style="margin:10px 0 0;font-size:15px;line-height:1.6;color:#3c434a;">'
            . sprintf(
                /* translators: 1: start date, 2: end date */
                esc_html__('Activity on your site from %1$s to %2$s.', 'dpxl-shield'),
                esc_html(EmailTemplate::localTime($since, false)),
                esc_html(EmailTemplate::localTime(null, false))
            )
            . '</p>'
            . $headline
            . $this->buildStatGrid($data)
            . $this->buildTopIpsTable((array) ($data['topIps'] ?? []))
            . EmailTemplate::button(
                (string) get_option('siteurl') . '/wp-admin/admin.php?page=dpxl-shield',
                __('Open dashboard', 'dpxl-shield')
            );

        return EmailTemplate::render($title, $palette['accent'], $content);
    }

    /**
     * Headline number plus a three-up row of secondary stats.
     *
     * @param array<string,mixed> $data
     */
    private function buildStatGrid(array $data): string {
        $blocked = (int) ($data['attacksBlocked'] ?? 0);

        $secondary = [
            __('Logins', 'dpxl-shield')        => (int) ($data['loginSuccess'] ?? 0),
            __('Failed logins', 'dpxl-shield') => (int) ($data['loginFailed'] ?? 0),
            __('Scan issues', 'dpxl-shield')   => (int) ($data['scanIssues'] ?? 0),
        ];

        $cells = '';

        foreach ($secondary as $label => $value) {
            $cells .= '<td width="33%" style="padding:16px 14px;border-left:1px solid #f0f0f1;vertical-align:top;">'
                . '<div style="font-size:22px;font-weight:600;color:#1d2327;line-height:1.2;">' . number_format_i18n($value) . '</div>'
                . '<div style="margin-top:3px;font-size:12px;color:#787c82;">' . esc_html((string) $label) . '</div>'
                . '</td>';
        }

        return '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top:22px;border:1px solid #f0f0f1;border-radius:8px;">'
            . '<tr><td style="padding:18px;border-bottom:1px solid #f0f0f1;">'
            . '<div style="font-size:34px;font-weight:600;color:#1d2327;line-height:1.1;">' . number_format_i18n($blocked) . '</div>'
            . '<div style="margin-top:4px;font-size:13px;color:#787c82;">' . esc_html__('Attacks blocked', 'dpxl-shield') . '</div>'
            . '</td></tr>'
            . '<tr>' . preg_replace('/border-left:1px solid #f0f0f1;/', '', $cells, 1) . '</tr>'
            . '</table>';
    }

    /** @param array<int,array<string,mixed>> $topIps */
    private function buildTopIpsTable(array $topIps): string {
        if ($topIps === []) {
            return '<p style="margin:22px 0 0;font-size:14px;line-height:1.6;color:#787c82;">'
                . esc_html__('No attacks were blocked in this period.', 'dpxl-shield') . '</p>';
        }

        $rows = '';

        foreach ($topIps as $row) {
            $rows .= '<tr>'
                . '<td style="padding:10px 14px;border-top:1px solid #f0f0f1;color:#1d2327;">' . esc_html((string) ($row['ip'] ?? '')) . '</td>'
                . '<td align="right" style="padding:10px 14px;border-top:1px solid #f0f0f1;color:#50575e;">' . number_format_i18n((int) ($row['hits'] ?? 0)) . '</td>'
                . '</tr>';
        }

        return '<h2 style="margin:26px 0 0;font-size:13px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:#787c82;">'
            . esc_html__('Most blocked IPs', 'dpxl-shield') . '</h2>'
            . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top:10px;border:1px solid #f0f0f1;border-radius:8px;font-size:14px;">'
            . '<tr>'
            . '<td style="padding:9px 14px;background:#f6f7f7;font-size:12px;color:#787c82;">' . esc_html__('IP address', 'dpxl-shield') . '</td>'
            . '<td align="right" style="padding:9px 14px;background:#f6f7f7;font-size:12px;color:#787c82;">' . esc_html__('Blocks', 'dpxl-shield') . '</td>'
            . '</tr>'
            . $rows
            . '</table>';
    }

    private function periodLabel(string $freq): string {
        return match ($freq) {
            'daily'   => __('Daily', 'dpxl-shield'),
            'monthly' => __('Monthly', 'dpxl-shield'),
            default   => __('Weekly', 'dpxl-shield'),
        };
    }
}
