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

        // Alerts are dispatched from cron and from the WAF's pre-WordPress path,
        // where the admin-only gettext filter never runs — without this the
        // shared email shell would go out in English. try/finally so a throw
        // while rendering cannot leave the global filter installed.
        ReportI18n::activate();

        try {
            $subject = $this->buildSubject($level, $eventType);
            $body    = $this->buildBody($level, $eventType, $description, $context);
        } finally {
            ReportI18n::deactivate();
        }

        $headers = [
            'Content-Type: text/html; charset=UTF-8',
            'X-DPXL-Shield-Level: ' . $level,
            'X-DPXL-Shield-Event: ' . $eventType,
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

    /**
     * Subject reads as a sentence, not as a log line. Severity travels in the
     * X-DPXL-Shield-Level header (and the pill in the body) so routine events
     * do not arrive shouting [CRITICAL] in the inbox list.
     */
    private function buildSubject(string $level, string $eventType): string {
        $siteName = (string) get_option('blogname', '');
        $siteName = $siteName !== '' ? $siteName : EmailTemplate::siteHost();

        return sprintf(
            /* translators: 1: event title, 2: site name */
            __('[DPXL Shield] %1$s — %2$s', 'dpxl-shield'),
            EventCatalog::label($eventType),
            $siteName
        );
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
        $palette = EmailTemplate::palette($level);
        $title   = EventCatalog::label($eventType);
        $summary = EventCatalog::summary($eventType);

        // The dispatcher's description is the specific, factual line
        // ("Admin 'x' logged in from 1.2.3.4"). The catalog summary is the
        // generic explanation. Show the specific one first.
        $lead = $description !== '' ? $description : $summary;

        $note = ($description !== '' && $summary !== '')
            ? '<p style="margin:12px 0 0;font-size:14px;line-height:1.6;color:#787c82;">' . esc_html($summary) . '</p>'
            : '';

        $content = EmailTemplate::pill($palette['label'], $palette['accent'], $palette['tint'])
            . '<h1 style="margin:16px 0 0;font-size:21px;line-height:1.3;font-weight:600;color:#1d2327;">' . esc_html($title) . '</h1>'
            . '<p style="margin:10px 0 0;font-size:15px;line-height:1.6;color:#3c434a;">' . esc_html($lead) . '</p>'
            . $note
            . EmailTemplate::detailTable($this->buildDetailRows($context))
            . EmailTemplate::button(
                (string) get_option('siteurl') . '/wp-admin/admin.php?page=dpxl-shield',
                __('Open DPXL Shield', 'dpxl-shield')
            );

        return EmailTemplate::render(
            $title,
            $palette['accent'],
            $content,
            sprintf(__('Event ID: %s', 'dpxl-shield'), esc_html($eventType))
        );
    }

    /**
     * Detail rows: time first, then whatever context the dispatcher supplied,
     * with humanised field labels.
     *
     * @param  array<string,mixed> $context
     * @return array<string,string>
     */
    private function buildDetailRows(array $context): array {
        $rows = [__('When', 'dpxl-shield') => EmailTemplate::localTime()];

        foreach ($context as $key => $value) {
            if ($value === null || $value === '' || is_object($value)) {
                continue;
            }

            $rows[EventCatalog::fieldLabel((string) $key)] = self::stringify($value);
        }

        return $rows;
    }

    /**
     * Renders a context value as one line of text.
     *
     * Nested arrays have to be walked rather than cast: `(string) []` is the
     * word "Array", so a context holding one entry per check used to render as
     * "Array, Array, Array" in the email — the reader learned nothing. An
     * associative sub-array is shown as "key: value" so the shape survives.
     *
     * @param mixed $value
     */
    private static function stringify($value): string {
        if (is_bool($value)) {
            return $value ? 'yes' : 'no';
        }

        if (!is_array($value)) {
            return (string) $value;
        }

        $parts = [];

        foreach ($value as $key => $item) {
            $rendered = self::stringify($item);

            if ($rendered === '') {
                continue;
            }

            $parts[] = is_string($key) ? "{$key}: {$rendered}" : $rendered;
        }

        return implode(', ', $parts);
    }
}
