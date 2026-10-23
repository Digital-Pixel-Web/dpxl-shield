<?php
declare(strict_types=1);

namespace DPXL\Shield\Api;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

/**
 * Persistence for API tokens.
 *
 * Only ever holds the SHA-256 hash and the clear-text lookup fragment; the
 * plaintext exists exactly once, in the response to the request that created it.
 */
final class TokenStore {

    /** Hard ceiling, so a compromised admin session cannot quietly mint hundreds. */
    public const MAX_TOKENS = 20;

    /** last_used_at is refreshed at most this often, to avoid a write per API call. */
    private const TOUCH_INTERVAL = 300;

    private function __construct() {}

    private static function table(): string {
        global $wpdb;

        return $wpdb->prefix . 'dpxl_shield_api_tokens';
    }

    /**
     * Creates a token and returns the plaintext — the only time it is available.
     *
     * @return array{success:bool,error?:string,plain?:string,token?:array<string,mixed>}
     */
    public static function create(string $label): array {
        global $wpdb;

        if (self::count() >= self::MAX_TOKENS) {
            return ['success' => false, 'error' => 'token_limit'];
        }

        $label = trim($label);
        $label = $label !== '' ? mb_substr($label, 0, 60) : 'API token';

        $token = ApiToken::generate();

        $inserted = $wpdb->insert(
            self::table(),
            [
                'label'        => $label,
                'token_hash'   => $token['hash'],
                'token_lookup' => $token['lookup'],
                'created_at'   => gmdate('Y-m-d H:i:s'),
            ],
            ['%s', '%s', '%s', '%s']
        );

        if (!$inserted) {
            return ['success' => false, 'error' => 'insert_failed'];
        }

        return [
            'success' => true,
            'plain'   => $token['plain'],
            'token'   => [
                'id'           => (int) $wpdb->insert_id,
                'label'        => $label,
                'masked'       => ApiToken::mask($token['lookup']),
                'created_at'   => gmdate('c'),
                'last_used_at' => null,
                'last_used_ip' => null,
            ],
        ];
    }

    /**
     * Finds the token row matching a plaintext credential.
     *
     * The indexed lookup fragment narrows to one row; the decision itself is a
     * constant-time hash comparison, so response timing does not reveal how much
     * of a guessed token was correct.
     *
     * @return array<string,mixed>|null
     */
    public static function findByPlaintext(string $plain): ?array {
        global $wpdb;

        if (!ApiToken::looksValid($plain)) {
            return null;
        }

        $table = self::table();

        $row = $wpdb->get_row(
            $wpdb->prepare(
                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                "SELECT * FROM {$table} WHERE token_lookup = %s LIMIT 1",
                ApiToken::lookup($plain)
            ),
            ARRAY_A
        );

        if (!is_array($row)) {
            // Still spend a comparison so a miss and a wrong-hash hit take a
            // similar amount of work.
            hash_equals(str_repeat('0', 64), ApiToken::hash($plain));
            return null;
        }

        if (!hash_equals((string) $row['token_hash'], ApiToken::hash($plain))) {
            return null;
        }

        return $row;
    }

    /** Records usage, throttled so a busy integration does not write on every call. */
    public static function touch(int $id, string $lastUsedAt, string $ip): void {
        global $wpdb;

        if ($lastUsedAt !== '' && (time() - (int) strtotime($lastUsedAt)) < self::TOUCH_INTERVAL) {
            return;
        }

        $wpdb->update(
            self::table(),
            ['last_used_at' => gmdate('Y-m-d H:i:s'), 'last_used_ip' => $ip],
            ['id' => $id],
            ['%s', '%s'],
            ['%d']
        );
    }

    /**
     * All tokens, in display form. Never returns the hash.
     *
     * @return array<int,array<string,mixed>>
     */
    public static function all(): array {
        global $wpdb;

        $table = self::table();

        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $rows = $wpdb->get_results("SELECT * FROM {$table} ORDER BY id DESC", ARRAY_A);

        if (!is_array($rows)) {
            return [];
        }

        $items = [];

        foreach ($rows as $row) {
            $items[] = [
                'id'           => (int) $row['id'],
                'label'        => (string) $row['label'],
                'masked'       => ApiToken::mask((string) $row['token_lookup']),
                'created_at'   => (string) $row['created_at'],
                'last_used_at' => $row['last_used_at'] !== null ? (string) $row['last_used_at'] : null,
                'last_used_ip' => $row['last_used_ip'] !== null ? (string) $row['last_used_ip'] : null,
            ];
        }

        return $items;
    }

    public static function revoke(int $id): bool {
        global $wpdb;

        return (bool) $wpdb->delete(self::table(), ['id' => $id], ['%d']);
    }

    public static function count(): int {
        global $wpdb;

        $table = self::table();

        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        return (int) $wpdb->get_var("SELECT COUNT(*) FROM {$table}");
    }
}
