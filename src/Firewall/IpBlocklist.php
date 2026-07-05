<?php
declare(strict_types=1);

namespace DPXL\Shield\Firewall;

class IpBlocklist {

    private const TRANSIENT_KEY  = 'dpxl_shield_blocked_ips_cache';
    private const CACHE_TTL      = 300; // 5 minutes

    /** In-process cache so we don't hit DB/transient on every call within a request. */
    private static ?array $cache = null;

    public static function isBlocked(string $ip): bool {
        $list = self::getList();

        // Exact match
        if (in_array($ip, $list['exact'] ?? [], true)) {
            return true;
        }

        // CIDR match
        foreach ($list['cidr'] ?? [] as $cidr) {
            if (self::ipMatchesCidr($ip, $cidr)) {
                return true;
            }
        }

        return false;
    }

    public static function blockIp(
        string $ip,
        string $reason,
        string $source = 'manual',
        ?int   $durationSeconds = null,
    ): bool {
        global $wpdb;

        $expiresAt = $durationSeconds !== null
            ? gmdate('Y-m-d H:i:s', time() + $durationSeconds)
            : null;

        $existing = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT id FROM {$wpdb->prefix}dpxl_shield_blocked_ips WHERE ip = %s",
                $ip
            )
        );

        if ($existing) {
            $wpdb->update(
                $wpdb->prefix . 'dpxl_shield_blocked_ips',
                [
                    'block_count'  => $wpdb->get_var(
                        $wpdb->prepare(
                            "SELECT block_count + 1 FROM {$wpdb->prefix}dpxl_shield_blocked_ips WHERE ip = %s",
                            $ip
                        )
                    ),
                    'last_attempt' => current_time('mysql', true),
                    'expires_at'   => $expiresAt,
                ],
                ['ip' => $ip],
                ['%d', '%s', '%s'],
                ['%s']
            );
        } else {
            $wpdb->insert(
                $wpdb->prefix . 'dpxl_shield_blocked_ips',
                [
                    'ip'         => $ip,
                    'reason'     => $reason,
                    'source'     => $source,
                    'expires_at' => $expiresAt,
                    'blocked_at' => current_time('mysql', true),
                ],
                ['%s', '%s', '%s', '%s', '%s']
            );
        }

        self::invalidateCache();

        return $wpdb->last_error === '';
    }

    public static function unblockIp(string $ip): bool {
        global $wpdb;

        $wpdb->delete(
            $wpdb->prefix . 'dpxl_shield_blocked_ips',
            ['ip' => $ip],
            ['%s']
        );

        self::invalidateCache();

        return $wpdb->last_error === '';
    }

    private static function getList(): array {
        if (self::$cache !== null) {
            return self::$cache;
        }

        // Try APCu first (no DB hit)
        if (function_exists('apcu_fetch')) {
            $cached = apcu_fetch(self::TRANSIENT_KEY, $success);

            if ($success && is_array($cached)) {
                self::$cache = $cached;

                return $cached;
            }
        }

        // WordPress transient (available after WP loads)
        if (function_exists('get_transient')) {
            $cached = get_transient(self::TRANSIENT_KEY);

            if (is_array($cached)) {
                self::$cache = $cached;

                return $cached;
            }
        }

        $list = self::loadFromDatabase();

        // Store in cache
        if (function_exists('apcu_store')) {
            apcu_store(self::TRANSIENT_KEY, $list, self::CACHE_TTL);
        }

        if (function_exists('set_transient')) {
            set_transient(self::TRANSIENT_KEY, $list, self::CACHE_TTL);
        }

        self::$cache = $list;

        return $list;
    }

    private static function loadFromDatabase(): array {
        if (!function_exists('get_transient')) {
            // WordPress not loaded — try flat file fallback.
            return self::loadFromFile();
        }

        global $wpdb;

        $rows = $wpdb->get_results(
            "SELECT ip, cidr FROM {$wpdb->prefix}dpxl_shield_blocked_ips
             WHERE (expires_at IS NULL OR expires_at > UTC_TIMESTAMP())
             ORDER BY id ASC",
            ARRAY_A
        );

        $list = ['exact' => [], 'cidr' => []];

        foreach ($rows ?? [] as $row) {
            if (!empty($row['cidr'])) {
                $list['cidr'][] = $row['cidr'];
            } else {
                $list['exact'][] = $row['ip'];
            }
        }

        return $list;
    }

    private static function loadFromFile(): array {
        $file = defined('DPXL_SHIELD_PATH')
            ? DPXL_SHIELD_PATH . 'data/blocked-ips.php'
            : __DIR__ . '/../../data/blocked-ips.php';

        if (!file_exists($file)) {
            return ['exact' => [], 'cidr' => []];
        }

        $data = @include $file;

        return is_array($data) ? $data : ['exact' => [], 'cidr' => []];
    }

    private static function invalidateCache(): void {
        self::$cache = null;

        if (function_exists('apcu_delete')) {
            apcu_delete(self::TRANSIENT_KEY);
        }

        if (function_exists('delete_transient')) {
            delete_transient(self::TRANSIENT_KEY);
        }
    }

    /** Checks whether an IPv4 address falls within a CIDR range. */
    private static function ipMatchesCidr(string $ip, string $cidr): bool {
        if (!str_contains($cidr, '/')) {
            return $ip === $cidr;
        }

        [$subnet, $bits] = explode('/', $cidr, 2);

        $bits   = (int) $bits;
        $ipLong = ip2long($ip);
        $subLong = ip2long($subnet);

        if ($ipLong === false || $subLong === false || $bits < 0 || $bits > 32) {
            return false;
        }

        $mask = $bits === 0 ? 0 : (~0 << (32 - $bits));

        return ($ipLong & $mask) === ($subLong & $mask);
    }
}
