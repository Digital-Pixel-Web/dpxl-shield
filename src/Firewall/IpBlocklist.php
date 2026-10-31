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
        ?int   $durationSeconds = null
    ): bool {
        global $wpdb;

        // $wpdb is NULL when running in Extended Protection context (auto_prepend_file)
        // before WordPress loads. Guard here to prevent a fatal "call to member function
        // on null" when the WAF blocks a request pre-WordPress.
        if (!$wpdb instanceof \wpdb) {
            // Extended Protection: queue it for the next request that loads
            // WordPress, which writes it through this same method.
            EarlyEvents::queueBan($ip, $reason, $source, $durationSeconds);

            return false;
        }

        // A duration of 0 (or none) means permanent. The REST endpoint, the
        // Live Traffic "Block" button and the importer all pass 0 for "forever",
        // but 0 used to become expires_at = now: every manual block lapsed the
        // moment it was saved and vanished from the list.
        $permanent = $durationSeconds === null || $durationSeconds <= 0;
        $expiresAt = $permanent ? null : gmdate('Y-m-d H:i:s', time() + $durationSeconds);

        $table    = $wpdb->prefix . 'dpxl_shield_blocked_ips';
        $existing = $wpdb->get_row(
            $wpdb->prepare("SELECT id, is_permanent FROM {$table} WHERE ip = %s", $ip),
            ARRAY_A
        );

        if ($existing) {
            $data    = ['last_attempt' => current_time('mysql', true)];
            $formats = ['%s'];

            // An automatic, timed block must never shorten a permanent one.
            if ($permanent) {
                $data['is_permanent'] = 1;
                $data['expires_at']   = null;
                $formats[] = '%d';
                $formats[] = null;
            } elseif (empty($existing['is_permanent'])) {
                $data['expires_at'] = $expiresAt;
                $formats[] = '%s';
            }

            $wpdb->update($table, $data, ['id' => (int) $existing['id']], $formats, ['%d']);
            $wpdb->query($wpdb->prepare("UPDATE {$table} SET block_count = block_count + 1 WHERE id = %d", (int) $existing['id']));
        } else {
            $wpdb->insert(
                $table,
                [
                    'ip'           => $ip,
                    'reason'       => $reason,
                    'source'       => $source,
                    'expires_at'   => $expiresAt,
                    'is_permanent' => $permanent ? 1 : 0,
                    'blocked_at'   => current_time('mysql', true),
                ],
                ['%s', '%s', '%s', '%s', '%d', '%s']
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
            $cached = apcu_fetch(self::apcuKey(), $success);

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

        // Before WordPress loads there is no database, only the flat-file
        // snapshot. Caching that in APCu would hand the in-WordPress layer an
        // empty or stale list for the next five minutes, so it is not cached.
        if (!self::databaseAvailable()) {
            self::$cache = self::loadFromFile();

            return self::$cache;
        }

        $list = self::loadFromDatabase();

        // Store in cache
        if (function_exists('apcu_store')) {
            apcu_store(self::apcuKey(), $list, self::CACHE_TTL);
        }

        if (function_exists('set_transient')) {
            set_transient(self::TRANSIENT_KEY, $list, self::CACHE_TTL);
        }

        self::$cache = $list;

        return $list;
    }

    private static function loadFromDatabase(): array {
        global $wpdb;

        // WordPress not loaded, or $wpdb not yet available (Extended Protection
        // runs pre-WordPress) — fall back to the flat-file blocklist instead of
        // dereferencing a null $wpdb. Mirrors the guard in blockIp() (v1.0.19).
        if (!self::databaseAvailable()) {
            return self::loadFromFile();
        }

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

    private static function databaseAvailable(): bool {
        global $wpdb;

        return function_exists('get_transient') && $wpdb instanceof \wpdb;
    }

    private static function loadFromFile(): array {
        $data = @include \DPXL\Shield\Core\EarlyConfig::blockedIpsPath();

        if (!is_array($data)) {
            return ['exact' => [], 'cidr' => []];
        }

        // Timed blocks carry their expiry, so the snapshot never outlives them.
        $now  = time();
        $live = static function ($entry) use ($now): bool {
            return is_string($entry) || (is_array($entry) && (empty($entry[1]) || (int) $entry[1] > $now));
        };
        $flatten = static function ($entry): string {
            return is_array($entry) ? (string) $entry[0] : (string) $entry;
        };

        return [
            'exact' => array_map($flatten, array_filter((array) ($data['exact'] ?? []), $live)),
            'cidr'  => array_map($flatten, array_filter((array) ($data['cidr'] ?? []), $live)),
        ];
    }

    private static function invalidateCache(): void {
        self::$cache = null;

        // Keep the pre-WordPress snapshot in step with the database.
        \DPXL\Shield\Core\EarlyConfig::writeBlocklist();

        if (function_exists('apcu_delete')) {
            apcu_delete(self::apcuKey());
        }

        if (function_exists('delete_transient')) {
            delete_transient(self::TRANSIENT_KEY);
        }
    }

    /** Checks whether an IPv4 address falls within a CIDR range. */
    private static function ipMatchesCidr(string $ip, string $cidr): bool {
        // IPv6 ranges too — the readme promised CIDR support, and ip2long()
        // below only ever understood IPv4.
        if (str_contains($cidr, ':') || str_contains($ip, ':')) {
            return \DPXL\Shield\Core\ClientIp::inRange($ip, $cidr);
        }

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

    /**
     * APCu is shared by every site in the same PHP pool, so an un-namespaced
     * key let one site's cached list answer for another's.
     */
    private static function apcuKey(): string {
        return self::TRANSIENT_KEY . '_' . md5(__DIR__);
    }
}
