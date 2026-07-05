<?php
declare(strict_types=1);

namespace DPXL\Shield\Firewall;

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
        if (str_contains($uri, 'wp-login.php')) {
            return 'login';
        }

        if (str_contains($uri, 'xmlrpc.php')) {
            return 'xmlrpc';
        }

        if (str_contains($uri, '/wp-json/')) {
            return 'rest';
        }

        return null;  // 404 rate limiting handled in TrafficLogger (after WP loads).
    }

    private static function increment(string $key): int {
        // APCu path (pre-WordPress, zero latency)
        if (function_exists('apcu_inc') && function_exists('apcu_add')) {
            $cacheKey = 'dpxl_rl_' . md5($key);
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

        $prev        = $wpdb->suppress_errors(true);
        $tableExists = (string) $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table)) === $table;

        if (!$tableExists) {
            $wpdb->suppress_errors($prev);
            return 0;
        }

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

        $count = (int) $wpdb->get_var(
            $wpdb->prepare(
                "SELECT count FROM `{$table}` WHERE bucket_key = %s",
                $key
            )
        );

        $wpdb->suppress_errors($prev);

        return $count;
    }

    public static function updateLimit(string $endpoint, int $limit): void {
        self::$limits[$endpoint] = max(1, $limit);
    }
}
