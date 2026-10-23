<?php
declare(strict_types=1);

namespace DPXL\Shield\Integrations;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

use DPXL\Shield\Alerts\EventCatalog;

/**
 * Shapes an alert into the body each destination expects.
 *
 * A single generic JSON blob does not work: Slack renders `text`, Discord wants
 * `content`/`embeds`, and PagerDuty's Events API v2 rejects anything that is not
 * its own envelope. Getting this wrong means the alert is accepted with a 200
 * and then displayed as nothing.
 */
final class PayloadBuilder {

    /** Context keys that must never leave the site. */
    private const REDACTED_KEYS = [
        'password', 'pass', 'pwd', 'secret', 'token', 'api_key', 'apikey',
        'authorization', 'auth', 'cookie', 'session', 'nonce', 'hash',
        'private_key', 'credential', 'credentials',
    ];

    /** Colour per severity, for the chat clients that render an accent bar. */
    private const COLOURS = [
        Severity::CRITICAL => '#b32d2e',
        Severity::HIGH     => '#bd5b00',
        Severity::MEDIUM   => '#9a6700',
        Severity::LOW      => '#2271b1',
        Severity::INFO     => '#2271b1',
    ];

    private function __construct() {}

    /**
     * @param  array<string,mixed> $context
     * @return array<string,mixed> Body to JSON-encode for this endpoint.
     */
    public static function build(WebhookEndpoint $endpoint, Event $event): array {
        switch ($endpoint->format()) {
            case WebhookEndpoint::FORMAT_SLACK:
                return self::slack($event);
            case WebhookEndpoint::FORMAT_DISCORD:
                return self::discord($event);
            case WebhookEndpoint::FORMAT_PAGERDUTY:
                return self::pagerDuty($endpoint, $event);
            default:
                return self::generic($event);
        }
    }

    // ── Formats ──────────────────────────────────────────────────────────────

    /**
     * Stable machine-readable envelope — the one a SIEM ingests.
     *
     * @return array<string,mixed>
     */
    private static function generic(Event $event): array {
        return [
            'source'      => 'dpxl-shield',
            'version'     => defined('DPXL_SHIELD_VERSION') ? DPXL_SHIELD_VERSION : '',
            'site'        => self::siteUrl(),
            'event_type'  => $event->type(),
            'event_label' => EventCatalog::label($event->type()),
            'level'       => $event->level(),
            'description' => $event->description(),
            'context'     => self::redact($event->context()),
            'timestamp'   => gmdate('c', $event->timestamp()),
        ];
    }

    /** @return array<string,mixed> */
    private static function slack(Event $event): array {
        $title = EventCatalog::label($event->type());

        $fields = [];

        foreach (self::redact($event->context()) as $key => $value) {
            $fields[] = [
                'title' => EventCatalog::fieldLabel((string) $key),
                'value' => self::scalar($value),
                'short' => true,
            ];
        }

        return [
            // `text` doubles as the notification preview and the fallback for
            // clients that do not render attachments.
            'text'        => sprintf('[%s] %s — %s', strtoupper($event->level()), $title, self::siteHost()),
            'attachments' => [[
                'color'     => self::COLOURS[$event->level()] ?? self::COLOURS[Severity::INFO],
                'title'     => $title,
                'text'      => $event->description(),
                'fields'    => $fields,
                'footer'    => 'DPXL Shield · ' . self::siteHost(),
                'ts'        => $event->timestamp(),
            ]],
        ];
    }

    /** @return array<string,mixed> */
    private static function discord(Event $event): array {
        $fields = [];

        foreach (self::redact($event->context()) as $key => $value) {
            $fields[] = [
                'name'   => EventCatalog::fieldLabel((string) $key),
                'value'  => self::scalar($value),
                'inline' => true,
            ];
        }

        return [
            'content' => sprintf('**[%s]** %s', strtoupper($event->level()), self::siteHost()),
            'embeds'  => [[
                'title'       => EventCatalog::label($event->type()),
                'description' => $event->description(),
                // Discord wants the colour as an integer, not a hex string.
                'color'       => hexdec(ltrim(self::COLOURS[$event->level()] ?? self::COLOURS[Severity::INFO], '#')),
                'fields'      => array_slice($fields, 0, 25), // Discord caps embeds at 25 fields.
                'timestamp'   => gmdate('c', $event->timestamp()),
                'footer'      => ['text' => 'DPXL Shield'],
            ]],
        ];
    }

    /**
     * PagerDuty Events API v2.
     *
     * The endpoint URL is the events endpoint; the "secret" field carries the
     * integration routing key, which is what identifies the service.
     *
     * @return array<string,mixed>
     */
    private static function pagerDuty(WebhookEndpoint $endpoint, Event $event): array {
        // PagerDuty only recognises these severities.
        $severity = in_array($event->level(), ['critical', 'error', 'warning', 'info'], true)
            ? $event->level()
            : ($event->level() === Severity::HIGH ? 'error' : ($event->level() === Severity::MEDIUM ? 'warning' : 'info'));

        return [
            'routing_key'  => $endpoint->secret(),
            'event_action' => 'trigger',
            // Groups repeat occurrences of the same event on the same site into
            // one incident instead of paging on every request.
            'dedup_key'    => substr(hash('sha256', self::siteUrl() . '|' . $event->type()), 0, 32),
            'payload'      => [
                'summary'        => sprintf('%s — %s', EventCatalog::label($event->type()), self::siteHost()),
                'severity'       => $severity,
                'source'         => self::siteHost(),
                'component'      => 'dpxl-shield',
                'group'          => 'wordpress-security',
                'class'          => $event->type(),
                'custom_details' => array_merge(
                    ['description' => $event->description()],
                    self::redact($event->context())
                ),
            ],
        ];
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /**
     * Strips values whose key looks like a credential.
     *
     * Alert context is assembled at dozens of call sites, so this is a safety
     * net rather than the primary control: a webhook leaves the server, and a
     * token that lands in someone's Slack channel is a token that leaked.
     *
     * @param  array<string,mixed> $context
     * @return array<string,mixed>
     */
    private static function redact(array $context): array {
        $clean = [];

        foreach ($context as $key => $value) {
            $name = strtolower((string) $key);

            $sensitive = false;

            foreach (self::REDACTED_KEYS as $needle) {
                if (strpos($name, $needle) !== false) {
                    $sensitive = true;
                    break;
                }
            }

            if ($sensitive) {
                $clean[$key] = '[redacted]';
                continue;
            }

            if (is_array($value)) {
                $clean[$key] = self::redact($value);
                continue;
            }

            if (is_object($value)) {
                continue; // Not serialisable in any useful way.
            }

            $clean[$key] = $value;
        }

        return $clean;
    }

    /**
     * @param  mixed $value
     */
    private static function scalar($value): string {
        if (is_array($value)) {
            return implode(', ', array_map([self::class, 'scalar'], $value));
        }

        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }

        return (string) $value;
    }

    private static function siteUrl(): string {
        return function_exists('get_option') ? (string) get_option('siteurl') : '';
    }

    private static function siteHost(): string {
        $host = function_exists('wp_parse_url')
            ? wp_parse_url(self::siteUrl(), PHP_URL_HOST)
            : parse_url(self::siteUrl(), PHP_URL_HOST);

        return is_string($host) && $host !== '' ? $host : self::siteUrl();
    }
}
