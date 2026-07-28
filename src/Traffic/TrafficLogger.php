<?php
declare(strict_types=1);

namespace DPXL\Shield\Traffic;

use DPXL\Shield\Firewall\RuleResult;
use DPXL\Shield\Firewall\CountryBlocker;
use DPXL\Shield\Core\Options;

/**
 * Records each HTTP request to dpxl_shield_traffic_log.
 *
 * Lifecycle:
 *   1. start() is called at plugins_loaded to capture the request start time.
 *   2. setWafResult() is called by PluginInit after the WAF evaluates the request.
 *   3. The shutdown hook writes the final row including the HTTP response code.
 *
 * Retention: 24 h (cleaned by Cron::runCleanup).
 */
class TrafficLogger {

    private static float  $startTime   = 0.0;
    private static string $wafAction   = 'pass';
    private static string $wafRuleId   = '';
    private static bool   $initialized = false;
    private static bool   $skipLog     = false;

    public function registerHooks(): void {
        if (self::$initialized) {
            return;
        }

        self::$startTime   = microtime(true);
        self::$initialized = true;

        add_action('shutdown', [$this, 'writeLog'], 99);
    }

    public static function setWafResult(RuleResult $result): void {
        self::$wafAction = $result->decision;
        self::$wafRuleId = $result->ruleId ?? '';
    }

    /** Suppress logging for the current request (e.g. cron, asset requests). */
    public static function skip(): void {
        self::$skipLog = true;
    }

    // ── Shutdown handler ───────────────────────────────────────────────────

    public function writeLog(): void {
        if (!Options::get('traffic_log_enabled', true)) {
            return;
        }

        if (self::$skipLog) {
            return;
        }

        global $wpdb;

        $ip           = $this->resolveIp();
        $method       = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
        $uri          = substr($_SERVER['REQUEST_URI'] ?? '/', 0, 2000);
        $queryString  = substr($_SERVER['QUERY_STRING'] ?? '', 0, 1000) ?: null;
        $userAgent    = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500) ?: null;
        $referer      = substr($_SERVER['HTTP_REFERER'] ?? '', 0, 500) ?: null;
        $responseTime = round((microtime(true) - self::$startTime) * 1000, 2); // ms
        $statusCode   = http_response_code() ?: 200;

        $classifier = new TrafficClassifier();
        $isBot      = $classifier->isBot($userAgent ?? '', $ip) ? 1 : 0;

        // Geolocate the IP so the dashboard/report country widgets have data.
        // resolveCountry() is a cheap no-op (null) when the GeoLite2 DB is absent.
        $country = CountryBlocker::resolveCountry($ip);

        $wpdb->insert(
            $wpdb->prefix . 'dpxl_shield_traffic_log',
            [
                'ip'            => $ip,
                'method'        => $method,
                'uri'           => $uri,
                'query_string'  => $queryString,
                'status_code'   => $statusCode,
                'user_agent'    => $userAgent,
                'referer'       => $referer,
                'waf_action'    => self::$wafAction,
                'waf_rule_id'   => self::$wafRuleId ?: null,
                'response_time' => $responseTime,
                'is_bot'        => $isBot,
                'country'       => $country ?: null,
            ],
            ['%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%f', '%d', '%s']
        );
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
