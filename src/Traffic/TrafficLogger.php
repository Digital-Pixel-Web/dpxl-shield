<?php
declare(strict_types=1);

namespace DPXL\Shield\Traffic;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

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
        // WP-CLI runs are not traffic. And after `wp plugin uninstall` in the
        // same process the plugin's files are gone, so loading another class
        // here would end the command with a fatal error.
        if (PHP_SAPI === 'cli' || (defined('DPXL_SHIELD_FILE') && !file_exists(DPXL_SHIELD_FILE))) {
            return;
        }

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

    /**
     * A request Extended Protection blocked before WordPress loaded, imported
     * from EarlyEvents on a later request.
     *
     * @param array<string,mixed> $event
     */
    public static function logEarlyBlock(array $event): void {
        if (!Options::get('traffic_log_enabled', true)) {
            return;
        }

        global $wpdb;

        $ip        = (string) $event['ip'];
        $userAgent = (string) ($event['ua'] ?? '');
        $country   = CountryBlocker::resolveCountry($ip);

        $wpdb->insert(
            $wpdb->prefix . 'dpxl_shield_traffic_log',
            [
                'ip'            => $ip,
                'method'        => strtoupper(substr((string) ($event['method'] ?? 'GET'), 0, 10)),
                'uri'           => substr((string) ($event['uri'] ?? '/'), 0, 2000),
                'query_string'  => ((string) ($event['query'] ?? '')) ?: null,
                'status_code'   => 403,
                'user_agent'    => $userAgent ?: null,
                'referer'       => ((string) ($event['ref'] ?? '')) ?: null,
                'waf_action'    => 'block',
                'waf_rule_id'   => ((string) ($event['rule'] ?? '')) ?: null,
                'response_time' => 0,
                'is_bot'        => (new TrafficClassifier())->isBot($userAgent, $ip) ? 1 : 0,
                'country'       => $country ?: null,
                // `timestamp` keeps its database default, like every other row:
                // the import runs on the next WordPress request, seconds later.
            ],
            ['%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%f', '%d', '%s']
        );
    }

    // ── IP resolution ──────────────────────────────────────────────────────

    private function resolveIp(): string {
        // Spoof-resistant resolution lives in one place; see ClientIp.
        return \DPXL\Shield\Core\ClientIp::current();
    }
}
