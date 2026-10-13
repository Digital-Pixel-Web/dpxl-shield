<?php
declare(strict_types=1);

namespace DPXL\Shield\Traffic;

use DPXL\Shield\Firewall\IpBlocklist;
use DPXL\Shield\Core\Logger;

/**
 * Detects automated scanning / enumeration behaviour by tracking
 * per-IP request patterns across a rolling 60-second window.
 *
 * Detection rules:
 *   - >50 unique URLs  in 60s → scanner / crawler
 *   - >20 HTTP 404s    in 60s → discovery / brute-force
 *   - >30 REST hits    in 60s → REST API abuse
 *
 * Counters are stored in APCu (preferred) with a DB fallback so
 * they survive across workers on the same host.
 *
 * Detected IPs are auto-blocked for 30 minutes.
 */
class AnomalyDetector {

    private const WINDOW_SECONDS = 60;
    private const BLOCK_DURATION = 1800; // 30 minutes

    private const RULES = [
        'unique_urls' => ['threshold' => 50, 'reason' => 'Automated scanner detected (>50 unique URLs in 60s)'],
        'errors_404'  => ['threshold' => 20, 'reason' => 'Discovery scan detected (>20 404s in 60s)'],
        'rest_hits'   => ['threshold' => 30, 'reason' => 'REST API abuse detected (>30 REST hits in 60s)'],
    ];

    public function registerHooks(): void {
        // Run after WordPress routing is established (priority 99 on init).
        add_action('init', [$this, 'recordRequest'], 99);

        // Catch 404s after WordPress confirms the miss.
        add_action('wp', [$this, 'recordNotFound'], 10);
    }

    // ── Hook handlers ──────────────────────────────────────────────────────

    /**
     * Whether this request is exempt from behavioural blocking.
     *
     * An authenticated administrator is not a scanner. Working in wp-admin
     * passes 50 unique URLs a minute without trying — every admin-ajax call
     * carries its own query string, so each one counts as a distinct URL — and
     * the penalty here is not a log line but a 30-minute block of the person
     * who owns the site. On one real install this locked the administrator out
     * six times before anyone connected the alert to the cause.
     *
     * Someone who can already install plugins gains nothing by crawling the
     * site, so the detector has no signal to offer about them either way.
     */
    private function isExempt(): bool {
        return function_exists('current_user_can') && current_user_can('manage_options');
    }

    public function recordRequest(): void {
        if ($this->isExempt()) {
            return;
        }

        $ip  = $this->resolveIp();
        $uri = $_SERVER['REQUEST_URI'] ?? '/';

        // Track unique URLs.
        $this->increment($ip, 'unique_urls', $uri, true);

        // Track REST API hits.
        if (defined('REST_REQUEST') && REST_REQUEST) {
            $this->increment($ip, 'rest_hits');
        }

        $this->evaluateThresholds($ip);
    }

    public function recordNotFound(): void {
        if (!is_404() || $this->isExempt()) {
            return;
        }

        $ip = $this->resolveIp();
        $this->increment($ip, 'errors_404');
        $this->evaluateThresholds($ip);
    }

    // ── Threshold evaluation ───────────────────────────────────────────────

    private function evaluateThresholds(string $ip): void {
        // Skip already-blocked IPs to avoid redundant DB writes.
        if (IpBlocklist::isBlocked($ip)) {
            return;
        }

        foreach (self::RULES as $metric => $rule) {
            $count = $this->getCount($ip, $metric);

            if ($count >= $rule['threshold']) {
                $this->triggerBlock($ip, $metric, $rule['reason'], $count);
                return; // One block per request is enough.
            }
        }
    }

    private function triggerBlock(string $ip, string $metric, string $reason, int $count): void {
        Logger::error("AnomalyDetector: blocking {$ip} — {$metric}={$count} — {$reason}");

        IpBlocklist::blockIp($ip, $reason, 'auto_anomaly', self::BLOCK_DURATION);

        do_action('dpxl_shield_alert', [
            'level'       => 'high',
            'event_type'  => 'anomaly_detected',
            'description' => "{$reason} (IP: {$ip}, count: {$count})",
            'context'     => ['ip' => $ip, 'metric' => $metric, 'count' => $count],
        ]);
    }

    // ── Counter persistence ────────────────────────────────────────────────

    /**
     * Increment a counter for the given IP + metric.
     *
     * When $track=true, the raw $value is used as the set member so we can
     * count *unique* values rather than total hits (unique_urls case).
     */
    private function increment(string $ip, string $metric, string $value = '', bool $track = false): void {
        if (function_exists('apcu_fetch')) {
            $this->apcuIncrement($ip, $metric, $value, $track);
        } else {
            $this->dbIncrement($ip, $metric);
        }
    }

    private function apcuIncrement(string $ip, string $metric, string $value, bool $track): void {
        $key = $this->apcuKey($ip, $metric);

        if ($track && $value !== '') {
            // Store a JSON-encoded set of hashed values.
            $existing = apcu_fetch($key) ?: '[]';
            $set      = (array) json_decode((string) $existing, true);
            $hash     = md5($value);

            if (!in_array($hash, $set, true)) {
                $set[] = $hash;
                apcu_store($key, json_encode($set), self::WINDOW_SECONDS);
            }
        } else {
            if (!apcu_exists($key)) {
                apcu_store($key, 1, self::WINDOW_SECONDS);
            } else {
                apcu_inc($key);
            }
        }
    }

    private function dbIncrement(string $ip, string $metric): void {
        if (!function_exists('get_transient')) {
            return;
        }

        $key      = "dpxl_anomaly_{$metric}_" . md5($ip);
        $current  = (int) get_transient($key);
        set_transient($key, $current + 1, self::WINDOW_SECONDS);
    }

    private function getCount(string $ip, string $metric): int {
        if (function_exists('apcu_fetch')) {
            $key  = $this->apcuKey($ip, $metric);
            $data = apcu_fetch($key);

            if ($data === false) {
                return 0;
            }

            // JSON-encoded set (unique tracking) vs plain integer.
            if (is_string($data) && str_starts_with($data, '[')) {
                $set = json_decode($data, true);
                return is_array($set) ? count($set) : 0;
            }

            return (int) $data;
        }

        if (function_exists('get_transient')) {
            return (int) get_transient("dpxl_anomaly_{$metric}_" . md5($ip));
        }

        return 0;
    }

    private function apcuKey(string $ip, string $metric): string {
        return 'dpxl_anom_' . $metric . '_' . md5($ip);
    }

    // ── IP resolution ──────────────────────────────────────────────────────

    private function resolveIp(): string {
        foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'] as $header) {
            $ip = trim(explode(',', $_SERVER[$header] ?? '')[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }

        return '0.0.0.0';
    }
}
