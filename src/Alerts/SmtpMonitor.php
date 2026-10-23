<?php
declare(strict_types=1);

namespace DPXL\Shield\Alerts;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

use DPXL\Shield\Core\Logger;
use DPXL\Shield\Core\Options;

/**
 * Watches whether the site can actually send mail.
 *
 * Mail is the channel every other alert travels on, which makes it the one
 * failure nobody hears about: when sending breaks, the message saying so breaks
 * with it. A monitor that only sent an email would be silent exactly when it
 * mattered. So a mail outage is reported through every channel that does not
 * depend on mail — the audit log, the outbound integrations (Slack, Discord,
 * PagerDuty, SIEM) and a notice inside wp-admin — and the email is attempted
 * too, on the chance that only one recipient or one message was the problem.
 *
 * When sending recovers, a summary goes out by email, because that is the
 * moment the reader can finally be reached and the one fact they need is how
 * long they were in the dark.
 *
 * The loop this must not create: an alert about mail failing is itself
 * dispatched through the alert pipeline, which sends mail, which fails, which
 * fires `wp_mail_failed` again. `$dispatching` closes that door.
 */
class SmtpMonitor {

    private const OPT_FAILURES   = 'dpxl_shield_smtp_consecutive_failures';
    private const OPT_FIRST_FAIL = 'dpxl_shield_smtp_first_failure_at';
    private const OPT_LAST_FAIL  = 'dpxl_shield_smtp_last_failure_at';
    private const OPT_LAST_ERROR = 'dpxl_shield_smtp_last_error';
    private const OPT_LAST_OK    = 'dpxl_shield_smtp_last_success_at';
    private const OPT_NOTIFIED   = 'dpxl_shield_smtp_outage_notified';

    /**
     * Re-entrancy guard.
     *
     * Static rather than instance state: the alert pipeline builds its own
     * objects, so an instance flag would not be seen by the failure that the
     * alert's own send attempt provokes.
     */
    private static bool $dispatching = false;

    public function registerHooks(): void {
        if (!Options::get('smtp_monitor_enabled', true)) {
            return;
        }

        add_action('wp_mail_failed', [$this, 'onFailure'], 10, 1);

        // WordPress 5.9+. Without it the monitor would only ever learn about
        // failures and never about the recovery that ends them.
        add_action('wp_mail_succeeded', [$this, 'onSuccess'], 10, 1);

        add_action('admin_notices', [$this, 'maybeOutageNotice']);
    }

    // ── Signals ────────────────────────────────────────────────────────────

    /** @param mixed $error WP_Error when WordPress supplies one. */
    public function onFailure($error = null): void {
        if (self::$dispatching) {
            return;
        }

        $failures = (int) get_option(self::OPT_FAILURES, 0) + 1;
        $message  = self::errorMessage($error);
        $now      = current_time('mysql', true);

        update_option(self::OPT_FAILURES, $failures, false);
        update_option(self::OPT_LAST_FAIL, $now, false);
        update_option(self::OPT_LAST_ERROR, $message, false);

        if ($failures === 1) {
            update_option(self::OPT_FIRST_FAIL, $now, false);
        }

        Logger::error("SmtpMonitor: send failed ({$failures} in a row) — {$message}");

        // One alert per outage, not one per message. A broken mail server fails
        // every queued send, and a hundred identical alerts would bury the fact
        // in the channels that are still working.
        if ($failures < self::threshold() || get_option(self::OPT_NOTIFIED)) {
            return;
        }

        update_option(self::OPT_NOTIFIED, true, false);

        self::$dispatching = true;

        try {
            do_action('dpxl_shield_alert', [
                'level'       => 'high',
                'event_type'  => 'smtp_failure',
                'description' => "Mail delivery failed {$failures} times in a row: {$message}",
                'context'     => [
                    'failures'   => $failures,
                    'last_error' => $message,
                    'since'      => (string) get_option(self::OPT_FIRST_FAIL, $now),
                ],
            ]);
        } finally {
            self::$dispatching = false;
        }
    }

    /** @param mixed $mailData Array of the sent message; unused. */
    public function onSuccess($mailData = null): void {
        if (self::$dispatching) {
            return;
        }

        $now = current_time('mysql', true);
        update_option(self::OPT_LAST_OK, $now, false);

        if ((int) get_option(self::OPT_FAILURES, 0) === 0) {
            return;   // Nothing to recover from.
        }

        $since    = (string) get_option(self::OPT_FIRST_FAIL, '');
        $failures = (int) get_option(self::OPT_FAILURES, 0);
        $notified = (bool) get_option(self::OPT_NOTIFIED);

        update_option(self::OPT_FAILURES, 0, false);
        update_option(self::OPT_NOTIFIED, false, false);

        Logger::error("SmtpMonitor: sending recovered after {$failures} failures");

        // Only worth announcing if the outage was announced. A single failure
        // that fixed itself before the threshold is not news.
        if (!$notified) {
            return;
        }

        // Guarded like the failure path, and for a sharper reason: this alert
        // goes out by mail the moment mail starts working, so it is the send
        // most likely to meet a relay that is only half back. Unguarded, its
        // own failure would re-enter onFailure() and open a fresh outage from
        // inside the recovery that was announcing the end of one.
        self::$dispatching = true;

        try {
            do_action('dpxl_shield_alert', [
                'level'       => 'medium',
                'event_type'  => 'smtp_recovered',
                'description' => "Mail delivery recovered after {$failures} failed attempts",
                'context'     => [
                    'failures' => $failures,
                    'since'    => $since,
                    'duration' => self::humanDuration($since, $now),
                ],
            ]);
        } finally {
            self::$dispatching = false;
        }
    }

    // ── Admin notice ───────────────────────────────────────────────────────

    /**
     * The channel that works when mail does not: anyone who opens wp-admin
     * sees it, with no dependency on the thing that is broken.
     */
    public function maybeOutageNotice(): void {
        if (!function_exists('current_user_can') || !current_user_can('manage_options')) {
            return;
        }

        if ((int) get_option(self::OPT_FAILURES, 0) < self::threshold()) {
            return;
        }

        $error = (string) get_option(self::OPT_LAST_ERROR, '');
        $since = (string) get_option(self::OPT_FIRST_FAIL, '');

        printf(
            '<div class="notice notice-error"><p><strong>%s</strong> %s</p><p><code>%s</code></p></div>',
            esc_html__('O site não está conseguindo enviar e-mails.', 'dpxl-shield'),
            esc_html(sprintf(
                /* translators: %s: date and time the failures started. */
                __('Nenhuma mensagem sai desde %s. Enquanto isso durar, nenhum alerta do DPXL Shield chega por e-mail — por isso este aviso está aqui.', 'dpxl-shield'),
                $since !== '' ? EmailTemplate::localTime((int) strtotime($since)) : '—'
            )),
            esc_html($error !== '' ? $error : __('sem detalhe do servidor', 'dpxl-shield'))
        );
    }

    // ── State, for Diagnostics ─────────────────────────────────────────────

    /**
     * @return array{healthy: bool, failures: int, last_error: string, since: string, last_success: string}
     */
    public static function status(): array {
        $failures = (int) get_option(self::OPT_FAILURES, 0);

        return [
            'healthy'      => $failures < self::threshold(),
            'failures'     => $failures,
            'last_error'   => (string) get_option(self::OPT_LAST_ERROR, ''),
            'since'        => (string) get_option(self::OPT_FIRST_FAIL, ''),
            'last_success' => (string) get_option(self::OPT_LAST_OK, ''),
        ];
    }

    // ── Internals ──────────────────────────────────────────────────────────

    /**
     * Consecutive failures before anyone is told.
     *
     * Not one: a single refused recipient, or one timeout on a busy relay, is
     * not an outage, and reporting it as one is how an alert loses its meaning.
     * Two in a row means the next message is not getting through either.
     */
    private static function threshold(): int {
        return max(1, (int) Options::get('smtp_failure_threshold', 2));
    }

    /** @param mixed $error */
    public static function errorMessage($error): string {
        if (is_object($error) && method_exists($error, 'get_error_message')) {
            $message = trim((string) $error->get_error_message());

            if ($message !== '') {
                return mb_substr($message, 0, 300);
            }
        }

        if (is_string($error) && $error !== '') {
            return mb_substr(trim($error), 0, 300);
        }

        return 'Erro não informado pelo servidor de e-mail.';
    }

    public static function humanDuration(string $from, string $to): string {
        $start = strtotime($from);
        $end   = strtotime($to);

        if ($start === false || $end === false || $end <= $start) {
            return '—';
        }

        $seconds = $end - $start;

        if ($seconds < 3600) {
            return sprintf('%d min', max(1, (int) round($seconds / 60)));
        }

        if ($seconds < 86400) {
            return sprintf('%d h %d min', (int) floor($seconds / 3600), (int) floor(($seconds % 3600) / 60));
        }

        return sprintf('%d dia(s) %d h', (int) floor($seconds / 86400), (int) floor(($seconds % 86400) / 3600));
    }
}
