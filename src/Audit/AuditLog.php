<?php
declare(strict_types=1);

namespace DPXL\Shield\Audit;

use DPXL\Shield\Core\Logger;
use DPXL\Shield\Core\Options;

/**
 * Immutable audit log with SHA-256 hash chain.
 *
 * Each row stores:
 *   chain_hash = SHA256( id || timestamp || event_type || description || prev_chain_hash )
 *
 * Tampering any historical row breaks every subsequent hash in the chain,
 * which the "Verify Log Integrity" function detects.
 *
 * Logging modes (option dpxl_shield_audit_mode):
 *   disabled            — nothing is written
 *   preview             — local DB only (future: no remote sync)
 *   significant_events  — auth, firewall, user, plugin, settings (default)
 *   all_events          — includes content events
 */
class AuditLog {

    private const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
    private const BATCH_SIZE   = 500; // rows per verification pass

    // ── Write ──────────────────────────────────────────────────────────────

    /**
     * Record a new audit event.
     *
     * @param string               $eventType  One of AuditEvents::* constants
     * @param string               $severity   critical|high|medium|low|info
     * @param string               $description Human-readable summary
     * @param array<string,mixed>  $context    Optional extra data (JSON-encoded)
     */
    public static function log(
        string $eventType,
        string $severity,
        string $description,
        array  $context = []
    ): void {
        $mode = Options::get('audit_mode', 'significant_events');

        if ($mode === 'disabled') {
            return;
        }

        if ($mode === 'significant_events' && !AuditEvents::isSignificant($eventType)) {
            return;
        }

        global $wpdb;

        $timestamp  = current_time('mysql', true); // UTC
        $actorIp    = self::resolveIp();
        $actorUser  = get_current_user_id() ?: null;
        $prevHash   = self::lastChainHash();

        $chainHash  = self::computeChainHash($timestamp, $eventType, $description, $prevHash);

        $wpdb->insert(
            $wpdb->prefix . 'dpxl_shield_audit_log',
            [
                'timestamp'   => $timestamp,
                'event_type'  => $eventType,
                'severity'    => $severity,
                'actor_ip'    => $actorIp,
                'actor_user'  => $actorUser,
                'description' => $description,
                'context'     => !empty($context) ? wp_json_encode($context) : null,
                'chain_hash'  => $chainHash,
            ],
            ['%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s']
        );

        if ($wpdb->last_error) {
            Logger::error('AuditLog: DB insert failed — ' . $wpdb->last_error);
        }
    }

    // ── Chain verification ─────────────────────────────────────────────────

    /**
     * Verify the hash chain integrity for all stored log entries.
     *
     * @return array{valid: bool, broken_at: int|null, total: int}
     */
    public static function verifyChain(): array {
        global $wpdb;

        $table    = $wpdb->prefix . 'dpxl_shield_audit_log';
        $total    = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$table}");
        $prevHash = self::GENESIS_HASH;
        $offset   = 0;

        while ($offset < $total) {
            $rows = $wpdb->get_results(
                $wpdb->prepare(
                    "SELECT id, timestamp, event_type, description, chain_hash
                     FROM {$table}
                     ORDER BY id ASC
                     LIMIT %d OFFSET %d",
                    self::BATCH_SIZE,
                    $offset
                ),
                ARRAY_A
            );

            if (empty($rows)) {
                break;
            }

            foreach ($rows as $row) {
                $expected = self::computeChainHash(
                    (string) $row['timestamp'],
                    (string) $row['event_type'],
                    (string) $row['description'],
                    $prevHash
                );

                if (!hash_equals($expected, (string) $row['chain_hash'])) {
                    return ['valid' => false, 'broken_at' => (int) $row['id'], 'total' => $total];
                }

                $prevHash = (string) $row['chain_hash'];
            }

            $offset += self::BATCH_SIZE;
        }

        return ['valid' => true, 'broken_at' => null, 'total' => $total];
    }

    // ── Query helpers ──────────────────────────────────────────────────────

    /**
     * @param array{severity?: string, event_type?: string, limit?: int, offset?: int} $filters
     * @return array<int,array<string,mixed>>
     */
    public static function query(array $filters = []): array {
        global $wpdb;

        $table  = $wpdb->prefix . 'dpxl_shield_audit_log';
        $where  = [];
        $values = [];

        if (!empty($filters['severity'])) {
            $where[]  = 'severity = %s';
            $values[] = $filters['severity'];
        }

        if (!empty($filters['event_type'])) {
            $where[]  = 'event_type LIKE %s';
            $values[] = $filters['event_type'] . '%';
        }

        $whereClause = $where ? 'WHERE ' . implode(' AND ', $where) : '';
        $limit       = (int) ($filters['limit']  ?? 50);
        $offset      = (int) ($filters['offset'] ?? 0);

        $sql = "SELECT id, timestamp, event_type, severity, actor_ip, actor_user, description, context
                FROM {$table}
                {$whereClause}
                ORDER BY id DESC
                LIMIT %d OFFSET %d";

        $values[] = $limit;
        $values[] = $offset;

        return $wpdb->get_results($wpdb->prepare($sql, ...$values), ARRAY_A) ?? [];
    }

    // ── Internal ───────────────────────────────────────────────────────────

    private static function lastChainHash(): string {
        global $wpdb;

        $hash = $wpdb->get_var(
            "SELECT chain_hash FROM {$wpdb->prefix}dpxl_shield_audit_log ORDER BY id DESC LIMIT 1"
        );

        return $hash ? (string) $hash : self::GENESIS_HASH;
    }

    private static function computeChainHash(
        string $timestamp,
        string $eventType,
        string $description,
        string $prevHash
    ): string {
        return hash('sha256', $timestamp . $eventType . $description . $prevHash);
    }

    private static function resolveIp(): string {
        foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'] as $header) {
            $ip = trim(explode(',', $_SERVER[$header] ?? '')[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }

        return 'cli';
    }
}
