<?php
declare(strict_types=1);

namespace DPXL\Shield\Api;

use DPXL\Shield\Core\Options;

/**
 * Read-only integration API — the pull half of the SIEM story.
 *
 * Lives in its own namespace rather than alongside the admin panel routes so the
 * externally reachable surface is obvious at a glance: everything under
 * `dpxl-shield-api/v1` is token-authenticated and read-only, everything under
 * `dpxl-shield/v1` needs a WordPress session.
 *
 * Pagination is by cursor, not offset. These tables are append-heavy — rows
 * arrive between a client's calls — and with an offset the client would re-read
 * or skip records every time that happened.
 */
final class PublicApi {

    public const NS = 'dpxl-shield-api/v1';

    private const MAX_LIMIT     = 200;
    private const DEFAULT_LIMIT = 50;

    public function registerHooks(): void {
        add_action('rest_api_init', [$this, 'registerRoutes']);
    }

    public function registerRoutes(): void {
        $auth = [ApiAuth::class, 'authorize'];

        $collectionArgs = [
            'after' => [
                'description' => 'Return records with an id greater than this. Use next_cursor from the previous page.',
                'type'        => 'integer',
            ],
            'limit' => [
                'description' => 'Maximum records to return (1–' . self::MAX_LIMIT . ').',
                'type'        => 'integer',
            ],
        ];

        register_rest_route(self::NS, '/status', [
            'methods'             => 'GET',
            'callback'            => [$this, 'getStatus'],
            'permission_callback' => $auth,
        ]);

        register_rest_route(self::NS, '/events', [
            'methods'             => 'GET',
            'callback'            => [$this, 'getEvents'],
            'permission_callback' => $auth,
            'args'                => $collectionArgs,
        ]);

        register_rest_route(self::NS, '/traffic', [
            'methods'             => 'GET',
            'callback'            => [$this, 'getTraffic'],
            'permission_callback' => $auth,
            'args'                => $collectionArgs,
        ]);

        register_rest_route(self::NS, '/scan-results', [
            'methods'             => 'GET',
            'callback'            => [$this, 'getScanResults'],
            'permission_callback' => $auth,
            'args'                => $collectionArgs,
        ]);
    }

    // ── Endpoints ────────────────────────────────────────────────────────────

    /** Cheap health/identity check — the call an integration makes to verify wiring. */
    public function getStatus(): \WP_REST_Response {
        global $wpdb;

        $trafficTable = $wpdb->prefix . 'dpxl_shield_traffic_log';

        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $blocked24h = (int) $wpdb->get_var(
            "SELECT COUNT(*) FROM {$trafficTable}
             WHERE waf_action = 'block' AND timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)"
        );

        return rest_ensure_response([
            'site'              => get_option('siteurl'),
            'plugin_version'    => defined('DPXL_SHIELD_VERSION') ? DPXL_SHIELD_VERSION : '',
            'firewall_enabled'  => (bool) Options::get('firewall_enabled', true),
            'extended_mode'     => defined('DPXL_SHIELD_EXTENDED_ACTIVE'),
            'waf_rules_version' => (string) Options::get('threat_feed_version', ''),
            'blocked_last_24h'  => $blocked24h,
            'server_time'       => gmdate('c'),
        ]);
    }

    public function getEvents(\WP_REST_Request $request): \WP_REST_Response {
        global $wpdb;

        $table = $wpdb->prefix . 'dpxl_shield_audit_log';

        // chain_hash is included on purpose: it lets an external system verify
        // the audit log's tamper-evident chain independently of this site.
        return $this->collection(
            $request,
            $table,
            ['id', 'timestamp', 'event_type', 'severity', 'actor_ip', 'actor_user', 'description', 'context', 'chain_hash']
        );
    }

    public function getTraffic(\WP_REST_Request $request): \WP_REST_Response {
        global $wpdb;

        $table = $wpdb->prefix . 'dpxl_shield_traffic_log';

        return $this->collection(
            $request,
            $table,
            ['id', 'timestamp', 'ip', 'method', 'uri', 'status_code', 'user_agent', 'waf_action', 'waf_rule_id', 'is_bot', 'country']
        );
    }

    public function getScanResults(\WP_REST_Request $request): \WP_REST_Response {
        global $wpdb;

        $table = $wpdb->prefix . 'dpxl_shield_scan_results';

        return $this->collection(
            $request,
            $table,
            ['id', 'scan_id', 'scanned_at', 'file_path', 'issue_type', 'severity', 'signature_id', 'details', 'status']
        );
    }

    // ── Shared query shape ───────────────────────────────────────────────────

    /**
     * Cursor-paginated read of one table.
     *
     * The column list is a hard-coded allowlist per endpoint, never anything
     * derived from the request, so a new column cannot start leaking by accident
     * and no client input reaches the SQL except as prepared values.
     *
     * @param string[] $columns
     */
    private function collection(\WP_REST_Request $request, string $table, array $columns): \WP_REST_Response {
        global $wpdb;

        $after = max(0, (int) $request->get_param('after'));
        $limit = (int) $request->get_param('limit');
        $limit = $limit > 0 ? min($limit, self::MAX_LIMIT) : self::DEFAULT_LIMIT;

        $select = implode(', ', array_map(static function (string $column): string {
            return '`' . $column . '`';
        }, $columns));

        // Ascending by id: a cursor client wants the oldest unseen record first,
        // and ids only ever grow, so a page can never contain a row the client
        // has already been given.
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                "SELECT {$select} FROM {$table} WHERE id > %d ORDER BY id ASC LIMIT %d",
                $after,
                $limit
            ),
            ARRAY_A
        );

        $rows = is_array($rows) ? $rows : [];

        $lastId = $rows !== [] ? (int) $rows[count($rows) - 1]['id'] : $after;

        return rest_ensure_response([
            'items'       => $rows,
            'count'       => count($rows),
            // Always present, so a client can keep polling from where it stopped
            // even when a page comes back empty.
            'next_cursor' => $lastId,
            'has_more'    => count($rows) === $limit,
        ]);
    }
}
