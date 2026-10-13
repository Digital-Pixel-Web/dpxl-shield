<?php
declare(strict_types=1);

namespace DPXL\Shield\Alerts;

use DPXL\Shield\Core\Options;
use DPXL\Shield\Firewall\CountryBlocker;
use DPXL\Shield\LoginSecurity\LoginAudit;
use DPXL\Shield\Tools\WhoisLookup;

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
     *
     * The one exception is `critical`: the cost of an unopened malware alert
     * is higher than the cost of the noise. That trade only holds while
     * "critical" stays rare — which is the whole point of the severity scale.
     */
    private function buildSubject(string $level, string $eventType): string {
        $siteName = (string) get_option('blogname', '');
        $siteName = $siteName !== '' ? $siteName : EmailTemplate::siteHost();

        $format = $level === 'critical'
            ? '[DPXL Shield · CRÍTICO] %1$s — %2$s'
            : '[DPXL Shield] %1$s — %2$s';

        return sprintf($format, EventCatalog::label($eventType), $siteName);
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

        // The lead is the catalog's pt-BR sentence, not the dispatcher's
        // description: the latter is written in English at each call site
        // ("Admin 'x' logged in from 1.2.3.4") and repeats what the identity
        // block below already shows. It travels in the technical details
        // instead, so nothing is lost.
        $lead   = $summary !== '' ? $summary : $description;
        $caveat = EventCatalog::caveat($eventType);
        $link   = EventCatalog::primaryLink($eventType);

        $content = EmailTemplate::pill($palette['label'], $palette['accent'], $palette['tint'])
            . '<h1 style="margin:16px 0 0;font-size:21px;line-height:1.3;font-weight:600;color:#1d2327;">' . esc_html($title) . '</h1>'
            . '<p style="margin:10px 0 0;font-size:15px;line-height:1.6;color:#3c434a;">' . esc_html($lead) . '</p>'
            . EmailTemplate::identityBlock($this->buildIdentityRows($context))
            . ($caveat !== '' ? EmailTemplate::callout($caveat, '#2271b1', '#f0f6fc') : '')
            . EmailTemplate::actionList('O que fazer', EventCatalog::actions($eventType))
            . EmailTemplate::button(
                (string) get_option('siteurl') . '/wp-admin/admin.php?' . $link['query'],
                $link['label']
            )
            . EmailTemplate::techDetails(
                'Detalhes técnicos',
                $this->buildDetailRows($eventType, $description, $context)
            );

        return EmailTemplate::render($title, $palette['accent'], $content);
    }

    /**
     * "Quem / de onde" — the block that turns an address into something the
     * reader can judge.
     *
     * The complaint that started this: an alert showed
     * "Endereço IP: 2804:d45:b005:1800:dcd6:a6ff:45ec:ac02" and nothing else,
     * and the reader asked what that was. An address on its own answers no
     * question anyone actually has.
     *
     * @param  array<string,mixed> $context
     * @return list<array{label: string, value: string, note?: string}>
     */
    private function buildIdentityRows(array $context): array {
        $rows = [];

        $user = (string) ($context['username'] ?? ($context['user_login'] ?? ''));

        if ($user !== '') {
            $userId = isset($context['user_id']) && $context['user_id'] !== ''
                ? 'ID ' . self::stringify($context['user_id'])
                : '';

            $rows[] = ['label' => 'Conta', 'value' => $user, 'note' => $userId];
        }

        $ip = (string) ($context['ip'] ?? '');

        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return $rows;
        }

        $origin = self::describeOrigin($ip);

        $rows[] = ['label' => 'Origem',   'value' => $origin['value'], 'note' => $origin['note']];
        $rows[] = ['label' => 'Endereço', 'value' => $ip,              'note' => self::describeAddress($ip)];

        return $rows;
    }

    /**
     * Country from the bundled GeoLite2 (a local file read), organisation from
     * whatever the Whois tool has already cached.
     *
     * Nothing here goes out to the network — see WhoisLookup::cached(). An
     * alert is built inside the request that triggered it, and no login should
     * get slower to decorate an email. When the organisation is unknown the row
     * says so and points at the tool, instead of leaving a blank that reads as
     * "checked, nothing there".
     *
     * @return array{value: string, note: string}
     */
    private static function describeOrigin(string $ip): array {
        $country = CountryBlocker::resolveCountryName($ip);
        $whois   = WhoisLookup::cached($ip);

        $org = is_array($whois) ? trim((string) ($whois['org'] ?? '')) : '';
        $asn = is_array($whois) ? trim((string) ($whois['asn'] ?? '')) : '';

        if ($org !== '' && $asn !== '') {
            $org .= ' (' . $asn . ')';
        }

        if ($country !== null && $country !== '') {
            return [
                'value' => $country,
                'note'  => $org !== ''
                    ? $org
                    : 'Provedor não identificado. Consulte o endereço em Ferramentas → Consulta Whois.',
            ];
        }

        if ($org !== '') {
            return ['value' => $org, 'note' => 'País não identificado.'];
        }

        return [
            'value' => 'Não identificada',
            'note'  => 'Consulte o endereço em Ferramentas → Consulta Whois.',
        ];
    }

    /**
     * IPv4 or IPv6, and for IPv6 the network the address belongs to.
     *
     * The network is the unit the plugin actually compares against (see
     * LoginAudit::networkId, 1.6.3): residential IPv6 rotates the address
     * inside a prefix, so naming the network names the thing the alert is
     * really about.
     */
    private static function describeAddress(string $ip): string {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return 'IPv4';
        }

        $network = LoginAudit::networkId($ip);

        return $network !== $ip ? 'IPv6 · rede ' . $network : 'IPv6';
    }

    /**
     * The raw record, shown last: time, the dispatcher's own context, its
     * English description, and the event slug.
     *
     * Deliberately repeats the full address the identity block already showed —
     * this is the block you forward to someone who needs the exact values.
     *
     * @param  array<string,mixed> $context
     * @return array<string,string>
     */
    private function buildDetailRows(string $eventType, string $description, array $context): array {
        $rows = ['Quando' => EmailTemplate::localTime()];

        foreach ($context as $key => $value) {
            if ($value === null || $value === '' || is_object($value)) {
                continue;
            }

            $rows[EventCatalog::fieldLabel((string) $key)] = self::stringify($value);
        }

        if ($description !== '') {
            $rows['Detalhe do evento'] = $description;
        }

        $rows['Evento'] = $eventType;

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
