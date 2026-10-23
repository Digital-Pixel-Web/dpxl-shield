<?php
declare(strict_types=1);

namespace DPXL\Shield\Firewall;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

class RateLimiter {

    private const WINDOW_SECONDS = 60;

    /** Limits: endpoint pattern → max requests per window */
    private static array $limits = [
        'login'  => 5,
        'xmlrpc' => 3,
        'rest'   => 60,
        '404'    => 20,
    ];

    public static function isExceeded(string $ip, string $uri): bool {
        $endpoint = self::classifyEndpoint($uri);

        if ($endpoint === null) {
            return false;
        }

        $limit = self::$limits[$endpoint];
        $key   = $ip . ':' . $endpoint;

        $count = self::increment($key);

        return $count > $limit;
    }

    private static function classifyEndpoint(string $uri): ?string {
        // Path only: a query string mentioning wp-login.php is not a login.
        $path = WafBypass::path($uri);

        if (str_ends_with($path, '/wp-login.php')) {
            return 'login';
        }

        if (str_ends_with($path, '/xmlrpc.php')) {
            return 'xmlrpc';
        }

        if (str_contains($path, '/wp-json/')) {
            return 'rest';
        }

        return null;  // 404 rate limiting handled in TrafficLogger (after WP loads).
    }

    private static function increment(string $key): int {
        // APCu path (pre-WordPress, zero latency)
        if (function_exists('apcu_inc') && function_exists('apcu_add')) {
            $cacheKey = 'dpxl_rl_' . md5(__DIR__ . '|' . $key); // per site: APCu is shared by every site in the PHP pool
            apcu_add($cacheKey, 0, self::WINDOW_SECONDS);

            return (int) apcu_inc($cacheKey);
        }

        // Database path (WordPress loaded)
        if (function_exists('current_time')) {
            return self::incrementDatabase($key);
        }

        return 0;
    }

    private static function incrementDatabase(string $key): int {
        global $wpdb;

        $table       = $wpdb->prefix . 'dpxl_shield_rate_buckets';
        $windowStart = gmdate('Y-m-d H:i:s', (int) floor(time() / self::WINDOW_SECONDS) * self::WINDOW_SECONDS);

        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $wpdb->query(
            $wpdb->prepare(
                "INSERT INTO `{$table}` (bucket_key, count, window_start)
                 VALUES (%s, 1, %s)
                 ON DUPLICATE KEY UPDATE
                     count = IF(window_start = %s, count + 1, 1),
                     window_start = %s",
                $key,
                $windowStart,
                $windowStart,
                $windowStart,
            )
        );

        return (int) $wpdb->get_var(
            $wpdb->prepare(
                "SELECT count FROM `{$table}` WHERE bucket_key = %s",
                $key
            )
        );
    }

    public static function updateLimit(string $endpoint, int $limit): void {
        self::$limits[$endpoint] = max(1, $limit);
    }
}
