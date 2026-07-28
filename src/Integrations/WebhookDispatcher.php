<?php
declare(strict_types=1);

namespace DPXL\Shield\Integrations;

use DPXL\Shield\Core\Options;

/**
 * Delivers alerts to the configured outbound webhooks.
 *
 * Timing: alerts are raised in the middle of a request, so delivering inline
 * would add the remote service's latency to a page load — which is why the old
 * implementation fired non-blocking and never learned whether anything arrived.
 * Instead events are queued during the request and flushed on `shutdown`, after
 * the response has gone to the browser. Delivery is then blocking, so failures
 * are visible and retryable without anyone waiting on them.
 */
final class WebhookDispatcher {

    /** Per-request ceiling. A volumetric attack can raise hundreds of alerts. */
    private const MAX_QUEUE = 20;

    private const TIMEOUT_SECONDS = 8;

    /** One retry, for transient failures only. */
    private const MAX_ATTEMPTS = 2;

    public const STATUS_OK        = 'ok';
    public const STATUS_HTTP_FAIL = 'http_fail';
    public const STATUS_NET_FAIL  = 'net_fail';
    public const STATUS_SKIPPED   = 'skipped';

    /** @var Event[] */
    private $queue = [];

    /** @var bool */
    private $flushHooked = false;

    /** @var bool */
    private $dropped = false;

    public function registerHooks(): void {
        if ($this->flushHooked) {
            return;
        }

        $this->flushHooked = true;

        // 100 → after TrafficLogger (99), so the log row is written first.
        add_action('shutdown', [$this, 'flush'], 100);
    }

    /**
     * Queues an alert. Cheap — no network here.
     *
     * @param array<string,mixed> $context
     */
    public function enqueue(string $level, string $eventType, string $description, array $context = []): void {
        if (!self::isConfigured()) {
            return;
        }

        if (count($this->queue) >= self::MAX_QUEUE) {
            $this->dropped = true;
            return;
        }

        $this->queue[] = new Event($level, $eventType, $description, $context);

        $this->registerHooks();
    }

    /** Delivers everything queued. Safe to call twice — the queue is drained. */
    public function flush(): void {
        if ($this->queue === []) {
            return;
        }

        $queue       = $this->queue;
        $this->queue = [];

        $endpoints = self::endpoints();

        if ($endpoints === []) {
            return;
        }

        if ($this->dropped) {
            // Say so rather than letting the gap look like nothing happened.
            $queue[] = new Event(
                Severity::MEDIUM,
                'fw.rule_triggered',
                sprintf(
                    'Webhook queue overflowed: more than %d alerts were raised in a single request and the excess was not delivered.',
                    self::MAX_QUEUE
                )
            );

            $this->dropped = false;
        }

        foreach ($endpoints as $endpoint) {
            foreach ($queue as $event) {
                if (!$endpoint->accepts($event->level())) {
                    continue;
                }

                $this->deliver($endpoint, $event);
            }
        }
    }

    /**
     * Sends a single event now, bypassing the queue. Used by the "send test"
     * button, where the admin is waiting for the result.
     *
     * @return array{status:string,code:int,message:string}
     */
    public function deliverNow(WebhookEndpoint $endpoint, Event $event): array {
        return $this->deliver($endpoint, $event);
    }

    // ── Delivery ─────────────────────────────────────────────────────────────

    /**
     * @return array{status:string,code:int,message:string}
     */
    private function deliver(WebhookEndpoint $endpoint, Event $event): array {
        $body = wp_json_encode(PayloadBuilder::build($endpoint, $event));

        if (!is_string($body)) {
            return $this->record($endpoint, self::STATUS_SKIPPED, 0, 'Payload could not be encoded.');
        }

        $result = ['status' => self::STATUS_NET_FAIL, 'code' => 0, 'message' => 'No attempt made.'];

        for ($attempt = 1; $attempt <= self::MAX_ATTEMPTS; $attempt++) {
            $response = wp_remote_post($endpoint->url(), [
                'timeout'     => self::TIMEOUT_SECONDS,
                'blocking'    => true,
                'sslverify'   => true,
                'redirection' => 0,
                'headers'     => $this->headers($endpoint, $body),
                'body'        => $body,
                'data_format' => 'body',
            ]);

            if (is_wp_error($response)) {
                $result = [
                    'status'  => self::STATUS_NET_FAIL,
                    'code'    => 0,
                    'message' => $response->get_error_message(),
                ];

                continue; // Transient — worth one retry.
            }

            $code = (int) wp_remote_retrieve_response_code($response);

            if ($code >= 200 && $code < 300) {
                return $this->record($endpoint, self::STATUS_OK, $code, '');
            }

            $result = [
                'status'  => self::STATUS_HTTP_FAIL,
                'code'    => $code,
                'message' => trim(substr((string) wp_remote_retrieve_body($response), 0, 200)),
            ];

            // 4xx means the request itself is wrong — a bad URL, a revoked Slack
            // hook, a malformed routing key. Retrying just repeats the mistake.
            if ($code >= 400 && $code < 500) {
                break;
            }
        }

        return $this->record($endpoint, $result['status'], $result['code'], $result['message']);
    }

    /**
     * @return array<string,string>
     */
    private function headers(WebhookEndpoint $endpoint, string $body): array {
        $headers = [
            'Content-Type' => 'application/json',
            'User-Agent'   => 'DPXL Shield/' . (defined('DPXL_SHIELD_VERSION') ? DPXL_SHIELD_VERSION : '0'),
        ];

        // Slack, Discord and PagerDuty authenticate by URL or routing key and
        // ignore extra headers; signing is for the generic SIEM receiver, which
        // otherwise has no way to tell a real payload from a forged one.
        if ($endpoint->format() === WebhookEndpoint::FORMAT_GENERIC && $endpoint->secret() !== '') {
            $timestamp = (string) time();

            // The timestamp is inside the signed material, so a captured payload
            // cannot be replayed later with a fresh timestamp.
            $headers['X-DPXL-Timestamp'] = $timestamp;
            $headers['X-DPXL-Signature'] = 'sha256=' . hash_hmac('sha256', $timestamp . '.' . $body, $endpoint->secret());
        }

        return $headers;
    }

    /**
     * @return array{status:string,code:int,message:string}
     */
    private function record(WebhookEndpoint $endpoint, string $status, int $code, string $message): array {
        $all = (array) Options::get('webhook_status', []);

        $all[$endpoint->id()] = [
            'status'  => $status,
            'code'    => $code,
            'message' => mb_substr($message, 0, 200),
            'time'    => time(),
        ];

        Options::set('webhook_status', $all);

        return ['status' => $status, 'code' => $code, 'message' => $message];
    }

    // ── Configuration ────────────────────────────────────────────────────────

    /**
     * @return WebhookEndpoint[]
     */
    public static function endpoints(): array {
        $stored = Options::get('webhook_endpoints', []);

        if (!is_array($stored)) {
            return [];
        }

        $endpoints = [];

        foreach ($stored as $row) {
            if (!is_array($row)) {
                continue;
            }

            $endpoint = WebhookEndpoint::fromArray($row);

            if ($endpoint !== null && $endpoint->isEnabled()) {
                $endpoints[] = $endpoint;
            }
        }

        return $endpoints;
    }

    /** @return WebhookEndpoint[] Including disabled ones — for the settings UI. */
    public static function allEndpoints(): array {
        $stored = Options::get('webhook_endpoints', []);

        if (!is_array($stored)) {
            return [];
        }

        $endpoints = [];

        foreach ($stored as $row) {
            if (!is_array($row)) {
                continue;
            }

            $endpoint = WebhookEndpoint::fromArray($row);

            if ($endpoint !== null) {
                $endpoints[] = $endpoint;
            }
        }

        return $endpoints;
    }

    public static function isConfigured(): bool {
        return self::endpoints() !== [];
    }
}
