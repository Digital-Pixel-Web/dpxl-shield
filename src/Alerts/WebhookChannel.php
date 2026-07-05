<?php
declare(strict_types=1);

namespace DPXL\Shield\Alerts;

use DPXL\Shield\Core\Options;

/**
 * Webhook notification channel (Slack, Discord, PagerDuty).
 *
 * Premium feature — no-op unless a webhook URL is configured.
 * Sends a JSON POST to the configured endpoint on every alert.
 */
class WebhookChannel {

    /**
     * @param array<string,mixed> $context
     */
    public function send(
        string $level,
        string $eventType,
        string $description,
        array  $context = []
    ): void {
        $url = Options::get('webhook_url', '');

        if (empty($url) || !filter_var($url, FILTER_VALIDATE_URL)) {
            return;
        }

        $payload = wp_json_encode([
            'source'      => 'dpxl-shield',
            'site'        => get_option('siteurl'),
            'level'       => $level,
            'event_type'  => $eventType,
            'description' => $description,
            'context'     => $context,
            'timestamp'   => gmdate('c'),
        ]);

        wp_remote_post((string) $url, [
            'timeout'     => 5,
            'blocking'    => false,
            'headers'     => ['Content-Type' => 'application/json'],
            'body'        => $payload,
            'data_format' => 'body',
        ]);
    }
}
