<?php
declare(strict_types=1);

namespace DPXL\Shield\Admin;

use DPXL\Shield\Core\Options;
use DPXL\Shield\Firewall\IpBlocklist;
use DPXL\Shield\Firewall\AllowlistManager;
use DPXL\Shield\Firewall\CustomPatternBlocker;
use DPXL\Shield\Audit\AuditLog;
use DPXL\Shield\Scanner\ScanOrchestrator;
use DPXL\Shield\Scanner\FileRepair;
use DPXL\Shield\Tools\WhoisLookup;
use DPXL\Shield\Tools\ImportExport;
use DPXL\Shield\Tools\Diagnostics;
use DPXL\Shield\Bootstrap\AutoPrepend;
use DPXL\Shield\LoginSecurity\TwoFactorAuth;
use DPXL\Shield\LoginSecurity\LoginAudit;
use DPXL\Shield\LoginSecurity\BackupCodes;

/**
 * Registers all REST API endpoints for the admin panel.
 *
 * All routes require `manage_options` capability.
 * Namespace: dpxl-shield/v1
 */
class RestApi {

    private const NS   = 'dpxl-shield/v1';
    private const PERM = 'manage_options';

    public function registerHooks(): void {
        // Priority -999: clean any PHP notices/warnings that accumulated during
        // plugins_loaded before the REST server begins. When WP_DEBUG_DISPLAY is
        // On, PHP notices emitted before WordPress's REST handler runs are buffered
        // and prepended to the JSON response, breaking JSON.parse() in the browser.
        add_action('rest_api_init', [$this, 'cleanRestOutputBuffer'], -999);

        add_action('rest_api_init', [$this, 'registerRoutes']);
    }

    /**
     * Cleans any buffered PHP notices/warnings before the REST response is sent.
     * Suppressed content is forwarded to error_log when WP_DEBUG is active so
     * the root-cause notice can still be identified and fixed.
     */
    public function cleanRestOutputBuffer(): void {
        if (ob_get_level() > 0 && ob_get_length() > 0) {
            $stray = ob_get_contents();
            ob_clean();

            if ($stray && defined('WP_DEBUG') && WP_DEBUG) {
                error_log('[DPXL Shield] REST pre-response output suppressed: ' . substr(wp_strip_all_tags((string) $stray), 0, 500));
            }
        }
    }

    public function registerRoutes(): void {
        $auth = [$this, 'checkPermission'];

        // Dashboard
        register_rest_route(self::NS, '/dashboard',           ['methods' => 'GET',    'callback' => [$this, 'getDashboard'],        'permission_callback' => $auth]);

        // Firewall overview / Extended Protection
        register_rest_route(self::NS, '/firewall/status',     ['methods' => 'GET',    'callback' => [$this, 'getFirewallStatus'],   'permission_callback' => $auth]);
        register_rest_route(self::NS, '/firewall/top-ips',    ['methods' => 'GET',    'callback' => [$this, 'getTopBlockedIps'],    'permission_callback' => $auth]);
        register_rest_route(self::NS, '/extended/status',     ['methods' => 'GET',    'callback' => [$this, 'getExtendedStatus'],   'permission_callback' => $auth]);
        register_rest_route(self::NS, '/extended/enable',     ['methods' => 'POST',   'callback' => [$this, 'enableExtendedMode'],  'permission_callback' => $auth]);
        register_rest_route(self::NS, '/extended/disable',    ['methods' => 'POST',   'callback' => [$this, 'disableExtendedMode'], 'permission_callback' => $auth]);

        // Traffic log
        register_rest_route(self::NS, '/traffic',             ['methods' => 'GET',    'callback' => [$this, 'getTraffic'],          'permission_callback' => $auth]);

        // Blocked IPs
        register_rest_route(self::NS, '/blocked-ips',         ['methods' => 'GET',    'callback' => [$this, 'getBlockedIps'],       'permission_callback' => $auth]);
        register_rest_route(self::NS, '/blocked-ips',         ['methods' => 'POST',   'callback' => [$this, 'blockIp'],             'permission_callback' => $auth]);
        register_rest_route(self::NS, '/blocked-ips/(?P<ip>[^/]+)', ['methods' => 'DELETE', 'callback' => [$this, 'unblockIp'],    'permission_callback' => $auth]);
        register_rest_route(self::NS, '/blocked-ips/(?P<ip>[^/]+)/permanent', ['methods' => 'POST', 'callback' => [$this, 'makePermanent'], 'permission_callback' => $auth]);

        // Country blocks
        register_rest_route(self::NS, '/country-blocks',      ['methods' => 'GET',    'callback' => [$this, 'getCountryBlocks'],    'permission_callback' => $auth]);
        register_rest_route(self::NS, '/country-blocks',      ['methods' => 'POST',   'callback' => [$this, 'saveCountryBlocks'],   'permission_callback' => $auth]);

        // Custom patterns
        register_rest_route(self::NS, '/custom-patterns',     ['methods' => 'GET',    'callback' => [$this, 'getCustomPatterns'],   'permission_callback' => $auth]);
        register_rest_route(self::NS, '/custom-patterns',     ['methods' => 'POST',   'callback' => [$this, 'addCustomPattern'],    'permission_callback' => $auth]);
        register_rest_route(self::NS, '/custom-patterns/(?P<id>\d+)', ['methods' => 'DELETE', 'callback' => [$this, 'deleteCustomPattern'], 'permission_callback' => $auth]);

        // Allowlist
        register_rest_route(self::NS, '/allowlist',           ['methods' => 'GET',    'callback' => [$this, 'getAllowlist'],         'permission_callback' => $auth]);
        register_rest_route(self::NS, '/allowlist',           ['methods' => 'POST',   'callback' => [$this, 'addAllowlistPattern'], 'permission_callback' => $auth]);
        register_rest_route(self::NS, '/allowlist',           ['methods' => 'DELETE', 'callback' => [$this, 'removeAllowlistPattern'], 'permission_callback' => $auth]);

        // Audit log
        register_rest_route(self::NS, '/audit-log',           ['methods' => 'GET',    'callback' => [$this, 'getAuditLog'],         'permission_callback' => $auth]);
        register_rest_route(self::NS, '/audit-log/verify',    ['methods' => 'POST',   'callback' => [$this, 'verifyAuditChain'],    'permission_callback' => $auth]);

        // WHOIS
        register_rest_route(self::NS, '/whois/(?P<ip>[^/]+)', ['methods' => 'GET',    'callback' => [$this, 'whoisLookup'],         'permission_callback' => $auth]);

        // Diagnostics
        register_rest_route(self::NS, '/diagnostics',         ['methods' => 'GET',    'callback' => [$this, 'getDiagnostics'],      'permission_callback' => $auth]);

        // Scan
        register_rest_route(self::NS, '/scan/results',        ['methods' => 'GET',    'callback' => [$this, 'getScanResults'],      'permission_callback' => $auth]);
        register_rest_route(self::NS, '/scan/status',         ['methods' => 'GET',    'callback' => [$this, 'getScanStatus'],       'permission_callback' => $auth]);
        register_rest_route(self::NS, '/scan/run',            ['methods' => 'POST',   'callback' => [$this, 'triggerScan'],         'permission_callback' => $auth]);
        register_rest_route(self::NS, '/scan/cancel',         ['methods' => 'POST',   'callback' => [$this, 'cancelScan'],          'permission_callback' => $auth]);
        register_rest_route(self::NS, '/scan/repair',         ['methods' => 'POST',   'callback' => [$this, 'repairFile'],          'permission_callback' => $auth]);
        register_rest_route(self::NS, '/scan/repair-all',     ['methods' => 'POST',   'callback' => [$this, 'repairAllFiles'],      'permission_callback' => $auth]);
        register_rest_route(self::NS, '/scan/dismiss/(?P<id>\d+)', ['methods' => 'POST', 'callback' => [$this, 'dismissScanResult'], 'permission_callback' => $auth]);

        // Login events
        register_rest_route(self::NS, '/login-events',        ['methods' => 'GET',    'callback' => [$this, 'getLoginEvents'],      'permission_callback' => $auth]);

        // Two-factor authentication
        register_rest_route(self::NS, '/2fa/setup',           ['methods' => 'GET',    'callback' => [$this, 'getTwoFactorSetup'],   'permission_callback' => $auth]);
        register_rest_route(self::NS, '/2fa/activate',        ['methods' => 'POST',   'callback' => [$this, 'activateTwoFactor'],   'permission_callback' => $auth]);
        register_rest_route(self::NS, '/2fa/recovery-codes/regenerate', ['methods' => 'POST', 'callback' => [$this, 'regenerateTwoFactorCodes'], 'permission_callback' => $auth]);

        // Settings
        register_rest_route(self::NS, '/settings',            ['methods' => 'GET',    'callback' => [$this, 'getSettings'],         'permission_callback' => $auth]);
        register_rest_route(self::NS, '/settings',            ['methods' => 'POST',   'callback' => [$this, 'saveSettings'],        'permission_callback' => $auth]);

        // Import / Export
        register_rest_route(self::NS, '/export',              ['methods' => 'GET',    'callback' => [$this, 'exportSettings'],      'permission_callback' => $auth]);
        register_rest_route(self::NS, '/import',              ['methods' => 'POST',   'callback' => [$this, 'importSettings'],      'permission_callback' => $auth]);
    }

    // ── Permission ─────────────────────────────────────────────────────────

    public function checkPermission(): bool {
        return current_user_can(self::PERM);
    }

    // ── Dashboard ──────────────────────────────────────────────────────────

    public function getDashboard(): \WP_REST_Response {
        global $wpdb;

        $logTable   = $wpdb->prefix . 'dpxl_shield_traffic_log';
        $loginTable = $wpdb->prefix . 'dpxl_shield_login_events';
        $scanTable  = $wpdb->prefix . 'dpxl_shield_scan_results';

        $now      = current_time('mysql', true);
        $day      = date('Y-m-d H:i:s', strtotime('-24 hours'));
        $week     = date('Y-m-d H:i:s', strtotime('-7 days'));
        $month    = date('Y-m-d H:i:s', strtotime('-30 days'));

        $attacksToday = (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$logTable} WHERE waf_action='block' AND timestamp >= %s", $day));
        $attacksWeek  = (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$logTable} WHERE waf_action='block' AND timestamp >= %s", $week));
        $attacksMonth = (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$logTable} WHERE waf_action='block' AND timestamp >= %s", $month));

        $openIssues = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$scanTable} WHERE status='new'");
        $criticalIssues = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$scanTable} WHERE status='new' AND severity='critical'");

        // Recent logins (last 10).
        $recentLogins = $wpdb->get_results(
            $wpdb->prepare("SELECT user_login, ip, result, timestamp FROM {$loginTable} ORDER BY timestamp DESC LIMIT %d", 10),
            ARRAY_A
        ) ?? [];

        // Hourly attack counts for the last 24h chart.
        $attackChart = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT DATE_FORMAT(timestamp, '%%Y-%%m-%%d %%H:00:00') as hour, COUNT(*) as count
                 FROM {$logTable} WHERE waf_action='block' AND timestamp >= %s
                 GROUP BY hour ORDER BY hour ASC",
                $day
            ),
            ARRAY_A
        ) ?? [];

        return rest_ensure_response([
            'attacks'       => ['today' => $attacksToday, 'week' => $attacksWeek, 'month' => $attacksMonth],
            'scan_issues'   => ['total' => $openIssues, 'critical' => $criticalIssues],
            'recent_logins' => $recentLogins,
            'attack_chart'  => $attackChart,
            'extended_mode' => defined('DPXL_SHIELD_EXTENDED_ACTIVE'),
            'firewall_ok'   => Options::get('firewall_enabled', true),
            'scan_ok'       => $criticalIssues === 0,
            'login_ok'      => (bool) Options::get('brute_force_enabled', true),
        ]);
    }


    // ── Firewall overview / Extended Protection ───────────────────────────────

    public function getFirewallStatus(): \WP_REST_Response {
        global $wpdb;

        $blockedTable = $wpdb->prefix . 'dpxl_shield_blocked_ips';
        $rulesFile    = defined('DPXL_SHIELD_PATH') ? DPXL_SHIELD_PATH . 'rules/waf-rules.json' : '';
        $rulesCount   = 0;

        if ($rulesFile && file_exists($rulesFile)) {
            $json = json_decode((string) file_get_contents($rulesFile), true);
            $rulesCount = is_array($json['rules'] ?? null) ? count($json['rules']) : 0;
        }

        $blockedCount = (int) $wpdb->get_var(
            "SELECT COUNT(*) FROM {$blockedTable}
             WHERE (expires_at IS NULL OR expires_at > UTC_TIMESTAMP() OR is_permanent = 1)"
        );

        $autoPrepend   = new AutoPrepend();
        $extendedState = $autoPrepend->getStatus();

        return rest_ensure_response(array_merge([
            'waf_enabled'      => (bool) Options::get('firewall_enabled', true),
            'rules_count'      => $rulesCount,
            'blocked_count'    => $blockedCount,
            'brute_enabled'    => (bool) Options::get('brute_force_enabled', true),
            'extended_active'  => $extendedState['active'],
            'extended_method'  => $extendedState['method'],
        ], $extendedState));
    }

    public function getTopBlockedIps(\WP_REST_Request $request): \WP_REST_Response {
        global $wpdb;

        $period = sanitize_key((string) ($request->get_param('period') ?? '24h'));
        $periodMap = [
            '24h' => '-24 hours',
            '7d'  => '-7 days',
            '30d' => '-30 days',
        ];

        $since = gmdate('Y-m-d H:i:s', strtotime($periodMap[$period] ?? '-24 hours'));
        $limit = min(max((int) ($request->get_param('limit') ?? 10), 1), 50);
        $table = $wpdb->prefix . 'dpxl_shield_traffic_log';

        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT ip, COALESCE(country, '') AS country, COUNT(*) AS hits
                 FROM {$table}
                 WHERE waf_action = 'block' AND timestamp >= %s
                 GROUP BY ip, country
                 ORDER BY hits DESC
                 LIMIT %d",
                $since,
                $limit
            ),
            ARRAY_A
        ) ?? [];

        return rest_ensure_response(['items' => $rows]);
    }

    public function getExtendedStatus(): \WP_REST_Response {
        return rest_ensure_response((new AutoPrepend())->getStatus());
    }

    public function enableExtendedMode(): \WP_REST_Response {
        $result = (new AutoPrepend())->enableHtaccessAfterBackup(true);

        return rest_ensure_response($result);
    }

    public function disableExtendedMode(): \WP_REST_Response {
        $result = (new AutoPrepend())->disable();

        return rest_ensure_response($result);
    }

    // ── Traffic log ────────────────────────────────────────────────────────

    public function getTraffic(\WP_REST_Request $request): \WP_REST_Response {
        global $wpdb;

        $limit   = min((int) ($request->get_param('limit')  ?? 50), 200);
        $offset  = (int) ($request->get_param('offset') ?? 0);
        $type    = sanitize_text_field($request->get_param('type')   ?? '');
        $ip      = sanitize_text_field($request->get_param('ip')     ?? '');
        $url     = sanitize_text_field($request->get_param('url')    ?? '');

        $where  = [];
        $values = [];

        if ($type === 'blocked') { $where[] = "waf_action = 'block'"; }
        elseif ($type === 'bot') { $where[] = "is_bot = 1 AND waf_action != 'block'"; }
        elseif ($type === 'human') { $where[] = "is_bot = 0 AND waf_action = 'pass'"; }

        if ($ip)  { $where[] = 'ip = %s'; $values[] = $ip; }
        if ($url) { $where[] = 'uri LIKE %s'; $values[] = '%' . $wpdb->esc_like($url) . '%'; }

        $wc  = $where ? 'WHERE ' . implode(' AND ', $where) : '';
        $tbl = $wpdb->prefix . 'dpxl_shield_traffic_log';

        $values[] = $limit;
        $values[] = $offset;

        $rows = $wpdb->get_results(
            $wpdb->prepare("SELECT * FROM {$tbl} {$wc} ORDER BY id DESC LIMIT %d OFFSET %d", ...$values),
            ARRAY_A
        ) ?? [];

        $total = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$tbl} {$wc}");

        return rest_ensure_response(['items' => $rows, 'total' => $total]);
    }

    // ── Blocked IPs ────────────────────────────────────────────────────────

    public function getBlockedIps(\WP_REST_Request $request): \WP_REST_Response {
        global $wpdb;

        $limit  = min((int) ($request->get_param('limit') ?? 50), 500);
        $offset = (int) ($request->get_param('offset') ?? 0);

        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM {$wpdb->prefix}dpxl_shield_blocked_ips
                 WHERE (expires_at IS NULL OR expires_at > UTC_TIMESTAMP() OR is_permanent = 1)
                 ORDER BY blocked_at DESC LIMIT %d OFFSET %d",
                $limit, $offset
            ),
            ARRAY_A
        ) ?? [];

        $total = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}dpxl_shield_blocked_ips WHERE (expires_at IS NULL OR expires_at > UTC_TIMESTAMP() OR is_permanent = 1)");

        return rest_ensure_response(['items' => $rows, 'total' => $total]);
    }

    public function blockIp(\WP_REST_Request $request): \WP_REST_Response {
        $ip      = sanitize_text_field($request->get_param('ip')     ?? '');
        $reason  = sanitize_text_field($request->get_param('reason') ?? 'Manually blocked');
        $duration = (int) ($request->get_param('duration') ?? 0); // 0 = permanent

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return new \WP_REST_Response(['error' => 'Invalid IP address.'], 400);
        }

        IpBlocklist::blockIp($ip, $reason, 'manual', $duration);

        return rest_ensure_response(['success' => true]);
    }

    public function unblockIp(\WP_REST_Request $request): \WP_REST_Response {
        $ip = urldecode(sanitize_text_field($request->get_param('ip') ?? ''));
        IpBlocklist::unblockIp($ip);

        return rest_ensure_response(['success' => true]);
    }

    public function makePermanent(\WP_REST_Request $request): \WP_REST_Response {
        global $wpdb;

        $ip = urldecode(sanitize_text_field($request->get_param('ip') ?? ''));

        $wpdb->update(
            $wpdb->prefix . 'dpxl_shield_blocked_ips',
            ['is_permanent' => 1, 'expires_at' => null],
            ['ip'           => $ip],
            ['%d', null],
            ['%s']
        );

        return rest_ensure_response(['success' => true]);
    }

    // ── Country blocks ─────────────────────────────────────────────────────

    public function getCountryBlocks(): \WP_REST_Response {
        global $wpdb;

        $rows = $wpdb->get_results(
            "SELECT * FROM {$wpdb->prefix}dpxl_shield_country_blocks ORDER BY country_name ASC",
            ARRAY_A
        ) ?? [];

        return rest_ensure_response(['items' => $rows]);
    }

    public function saveCountryBlocks(\WP_REST_Request $request): \WP_REST_Response {
        global $wpdb;

        $blocks = (array) ($request->get_param('blocks') ?? []);
        $mode   = sanitize_key($request->get_param('mode') ?? 'block');
        $table  = $wpdb->prefix . 'dpxl_shield_country_blocks';

        $wpdb->query("TRUNCATE TABLE {$table}");

        foreach ($blocks as $country) {
            $code = strtoupper(substr((string) ($country['code'] ?? ''), 0, 2));
            $name = sanitize_text_field($country['name'] ?? '');

            if (strlen($code) !== 2 || !$name) {
                continue;
            }

            $wpdb->insert($table, ['country_code' => $code, 'country_name' => $name, 'mode' => $mode === 'allow' ? 'allow' : 'block'], ['%s', '%s', '%s']);
        }

        return rest_ensure_response(['success' => true]);
    }

    // ── Custom patterns ────────────────────────────────────────────────────

    public function getCustomPatterns(): \WP_REST_Response {
        global $wpdb;

        $rows = $wpdb->get_results(
            "SELECT * FROM {$wpdb->prefix}dpxl_shield_custom_patterns ORDER BY id ASC",
            ARRAY_A
        ) ?? [];

        return rest_ensure_response(['items' => $rows]);
    }

    public function addCustomPattern(\WP_REST_Request $request): \WP_REST_Response {
        global $wpdb;

        $allowed_fields  = ['user_agent', 'referer', 'hostname', 'url'];
        $allowed_matches = ['contains', 'equals', 'regex'];
        $allowed_actions = ['block', 'log_only'];

        $field      = sanitize_key($request->get_param('field')      ?? '');
        $pattern    = sanitize_text_field($request->get_param('pattern')   ?? '');
        $match_type = sanitize_key($request->get_param('match_type') ?? 'contains');
        $action     = sanitize_key($request->get_param('action')     ?? 'block');
        $reason     = sanitize_text_field($request->get_param('reason')    ?? '');

        if (!in_array($field, $allowed_fields, true) || !$pattern) {
            return new \WP_REST_Response(['error' => 'Invalid field or empty pattern.'], 400);
        }

        $wpdb->insert(
            $wpdb->prefix . 'dpxl_shield_custom_patterns',
            [
                'field'      => $field,
                'pattern'    => substr($pattern, 0, 500),
                'match_type' => in_array($match_type, $allowed_matches, true) ? $match_type : 'contains',
                'action'     => in_array($action, $allowed_actions, true) ? $action : 'block',
                'reason'     => substr($reason, 0, 255),
            ],
            ['%s', '%s', '%s', '%s', '%s']
        );

        CustomPatternBlocker::invalidateCache();

        return rest_ensure_response(['success' => true, 'id' => (int) $wpdb->insert_id]);
    }

    public function deleteCustomPattern(\WP_REST_Request $request): \WP_REST_Response {
        global $wpdb;

        $id = (int) $request->get_param('id');
        $wpdb->delete($wpdb->prefix . 'dpxl_shield_custom_patterns', ['id' => $id], ['%d']);

        CustomPatternBlocker::invalidateCache();

        return rest_ensure_response(['success' => true]);
    }

    // ── Allowlist ──────────────────────────────────────────────────────────

    public function getAllowlist(): \WP_REST_Response {
        return rest_ensure_response(['patterns' => AllowlistManager::getAll()]);
    }

    public function addAllowlistPattern(\WP_REST_Request $request): \WP_REST_Response {
        $pattern = sanitize_text_field($request->get_param('pattern') ?? '');

        if (!$pattern) {
            return new \WP_REST_Response(['error' => 'Pattern is required.'], 400);
        }

        AllowlistManager::addPattern($pattern);

        return rest_ensure_response(['success' => true]);
    }

    public function removeAllowlistPattern(\WP_REST_Request $request): \WP_REST_Response {
        $pattern = sanitize_text_field($request->get_param('pattern') ?? '');
        AllowlistManager::removePattern($pattern);

        return rest_ensure_response(['success' => true]);
    }

    // ── Audit log ──────────────────────────────────────────────────────────

    public function getAuditLog(\WP_REST_Request $request): \WP_REST_Response {
        $rows = AuditLog::query([
            'severity'   => sanitize_key($request->get_param('severity')   ?? ''),
            'event_type' => sanitize_text_field($request->get_param('event_type') ?? ''),
            'limit'      => min((int) ($request->get_param('limit') ?? 50), 200),
            'offset'     => (int) ($request->get_param('offset') ?? 0),
        ]);

        return rest_ensure_response(['items' => $rows]);
    }

    public function verifyAuditChain(): \WP_REST_Response {
        $result = AuditLog::verifyChain();

        return rest_ensure_response($result);
    }

    // ── WHOIS ──────────────────────────────────────────────────────────────

    public function whoisLookup(\WP_REST_Request $request): \WP_REST_Response {
        $ip     = urldecode(sanitize_text_field($request->get_param('ip') ?? ''));
        $result = (new WhoisLookup())->lookup($ip);

        return rest_ensure_response($result);
    }

    // ── Diagnostics ────────────────────────────────────────────────────────

    public function getDiagnostics(): \WP_REST_Response {
        $checks = (new Diagnostics())->run();

        return rest_ensure_response(['checks' => $checks]);
    }

    // ── Scan ───────────────────────────────────────────────────────────────

    public function getScanResults(\WP_REST_Request $request): \WP_REST_Response {
        global $wpdb;

        $status = sanitize_key($request->get_param('status') ?? 'new');
        $limit  = min((int) ($request->get_param('limit') ?? 50), 200);
        $offset = (int) ($request->get_param('offset') ?? 0);
        $scanId = sanitize_text_field((string) ($request->get_param('scan_id') ?? ''));

        // By default, show the latest scan only. The previous implementation showed
        // all historical "new" results, which made the scanner look duplicated and
        // much more alarming than it really was.
        if ($scanId === '') {
            $scanId = (string) get_option('dpxl_shield_last_scan_id', '');
        }

        $where  = ['status = %s'];
        $params = [$status];

        if ($scanId !== '') {
            $where[]  = 'scan_id = %s';
            $params[] = $scanId;
        }

        $whereSql = 'WHERE ' . implode(' AND ', $where);

        $rowsParams = array_merge($params, [$limit, $offset]);
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM {$wpdb->prefix}dpxl_shield_scan_results {$whereSql} ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low', 'info'), id DESC LIMIT %d OFFSET %d",
                ...$rowsParams
            ),
            ARRAY_A
        ) ?? [];

        $total = (int) $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$wpdb->prefix}dpxl_shield_scan_results {$whereSql}",
                ...$params
            )
        );

        $critical = (int) $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$wpdb->prefix}dpxl_shield_scan_results {$whereSql} AND severity = %s",
                ...array_merge($params, ['critical'])
            )
        );

        $repairable = (int) $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$wpdb->prefix}dpxl_shield_scan_results {$whereSql} AND issue_type IN ('modified_core', 'modified_plugin')",
                ...$params
            )
        );

        return rest_ensure_response([
            'items'            => $rows,
            'total'            => $total,
            'critical_total'   => $critical,
            'repairable_count' => $repairable,
            'scan_id'          => $scanId,
        ]);
    }

    public function getScanStatus(): \WP_REST_Response {
        ScanOrchestrator::resetStaleScanIfNeeded();

        $filesScanned = (int) get_option('dpxl_shield_scan_files_scanned', 0);
        $filesTotal   = (int) get_option('dpxl_shield_scan_files_total', 0);
        $running      = (bool) get_option('dpxl_shield_scan_running', false);
        $stageStatus  = get_option('dpxl_shield_scan_stage_status', []);

        if (!is_array($stageStatus)) {
            $stageStatus = [];
        }

        $percent = $filesTotal > 0 ? min(100, (int) floor(($filesScanned / $filesTotal) * 100)) : 0;

        return rest_ensure_response([
            'running'        => $running,
            'current_stage'  => (string) get_option('dpxl_shield_scan_current_stage', 'idle'),
            'stage_status'   => $stageStatus,
            'files_scanned'  => $filesScanned,
            'files_total'    => $filesTotal,
            'progress'       => $percent,
            'current_file'   => (string) get_option('dpxl_shield_scan_current_file', ''),
            'started_at'     => (string) get_option('dpxl_shield_scan_started_at', ''),
            'updated_at'     => (string) get_option('dpxl_shield_scan_updated_at', ''),
            'last_scan_at'   => (string) get_option('dpxl_shield_last_scan_at', ''),
            'issue_count'    => (int) get_option('dpxl_shield_last_scan_issue_count', 0),
            'issues_found'   => (int) get_option('dpxl_shield_scan_issues_found', 0),
            'last_error'     => (string) get_option('dpxl_shield_scan_last_error', ''),
        ]);
    }

    public function triggerScan(): \WP_REST_Response {
        ScanOrchestrator::resetStaleScanIfNeeded();

        if (get_option('dpxl_shield_scan_running')) {
            return new \WP_REST_Response(['error' => 'A scan is already running.'], 409);
        }

        ScanOrchestrator::prepareQueuedScan();

        // Schedule for immediate execution via WP-Cron.
        wp_schedule_single_event(time(), 'dpxl_shield_full_scan');
        spawn_cron();

        return rest_ensure_response([
            'success' => true,
            'message' => 'Scan queued. DPXL Shield will start it through WP-Cron immediately.',
        ]);
    }

    public function cancelScan(): \WP_REST_Response {
        (new ScanOrchestrator())->cancel();

        return rest_ensure_response([
            'success' => true,
            'message' => 'Cancellation requested. The scanner will stop at the next safe checkpoint.',
        ]);
    }

    public function repairFile(\WP_REST_Request $request): \WP_REST_Response {
        $path = (string) ($request->get_param('file_path') ?? '');

        if (!$path || !str_starts_with($path, ABSPATH)) {
            return new \WP_REST_Response(['error' => 'Invalid file path.'], 400);
        }

        $result = (new FileRepair())->repairFile($path);

        return rest_ensure_response($result);
    }

    public function repairAllFiles(): \WP_REST_Response {
        $result = (new FileRepair())->repairAll();

        return rest_ensure_response($result);
    }

    public function dismissScanResult(\WP_REST_Request $request): \WP_REST_Response {
        global $wpdb;

        $id = (int) $request->get_param('id');
        $wpdb->update(
            $wpdb->prefix . 'dpxl_shield_scan_results',
            ['status' => 'false_positive'],
            ['id'     => $id],
            ['%s'],
            ['%d']
        );

        return rest_ensure_response(['success' => true]);
    }

    // ── Login events ───────────────────────────────────────────────────────

    public function getLoginEvents(\WP_REST_Request $request): \WP_REST_Response {
        global $wpdb;

        $result = sanitize_key($request->get_param('result') ?? '');
        $limit  = min((int) ($request->get_param('limit') ?? 20), 100);
        $offset = (int) ($request->get_param('offset') ?? 0);

        $where  = $result ? $wpdb->prepare('WHERE result = %s', $result) : '';

        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM {$wpdb->prefix}dpxl_shield_login_events {$where} ORDER BY timestamp DESC LIMIT %d OFFSET %d",
                $limit, $offset
            ),
            ARRAY_A
        ) ?? [];

        return rest_ensure_response(['items' => $rows]);
    }


    // ── Two-factor authentication ─────────────────────────────────────────

    public function getTwoFactorSetup(): \WP_REST_Response {
        $user = wp_get_current_user();

        if (!$user || !$user->exists()) {
            return new \WP_REST_Response(['error' => __('Usuário não encontrado.', 'dpxl-shield')], 404);
        }

        $enabled = (bool) get_user_meta($user->ID, 'dpxl_shield_totp_enabled', true);

        if ($enabled) {
            return rest_ensure_response([
                'enabled' => true,
                'message' => __('A autenticação de dois fatores já está ativa para este usuário.', 'dpxl-shield'),
                'recovery_codes_remaining' => BackupCodes::remainingCount($user->ID),
            ]);
        }

        $twoFactor = new TwoFactorAuth(new LoginAudit());
        $totp      = $twoFactor->generateSecret($user);
        $secret    = $totp->getSecret();
        $uri       = $totp->getProvisioningUri();

        return rest_ensure_response([
            'enabled'          => false,
            'manual_key'       => $this->formatTotpSecret($secret),
            'manual_key_raw'   => $secret,
            'provisioning_uri' => $uri,
            'issuer'           => get_bloginfo('name') . ' (DPXL Shield)',
            'account'          => $user->user_login,
            'recovery_message' => __('Os códigos de recuperação serão gerados depois que você confirmar o primeiro código do aplicativo.', 'dpxl-shield'),
        ]);
    }

    public function activateTwoFactor(\WP_REST_Request $request): \WP_REST_Response {
        $user = wp_get_current_user();
        $code = sanitize_text_field((string) $request->get_param('code'));
        $code = preg_replace('/\s+/', '', $code ?? '');

        if (!$user || !$user->exists()) {
            return new \WP_REST_Response(['error' => __('Usuário não encontrado.', 'dpxl-shield')], 404);
        }

        if (!ctype_digit($code) || strlen($code) !== 6) {
            return new \WP_REST_Response(['error' => __('Digite um código de 6 dígitos válido.', 'dpxl-shield')], 400);
        }

        $codes = (new TwoFactorAuth(new LoginAudit()))->activate($user->ID, $code);

        if (empty($codes)) {
            return new \WP_REST_Response(['error' => __('Código inválido. Confira o horário do servidor e tente novamente.', 'dpxl-shield')], 400);
        }

        return rest_ensure_response([
            'success'      => true,
            'enabled'      => true,
            'message'      => __('2FA ativado com sucesso. Salve seus códigos de recuperação agora.', 'dpxl-shield'),
            'backup_codes' => $codes,
        ]);
    }

    public function regenerateTwoFactorCodes(): \WP_REST_Response {
        $user = wp_get_current_user();

        if (!$user || !$user->exists()) {
            return new \WP_REST_Response(['error' => __('Usuário não encontrado.', 'dpxl-shield')], 404);
        }

        $enabled = (bool) get_user_meta($user->ID, 'dpxl_shield_totp_enabled', true);

        if (!$enabled) {
            return new \WP_REST_Response(['error' => __('Ative o 2FA antes de gerar códigos de recuperação.', 'dpxl-shield')], 400);
        }

        return rest_ensure_response([
            'success'      => true,
            'backup_codes' => BackupCodes::generate($user->ID),
            'message'      => __('Novos códigos de recuperação gerados. Os códigos antigos foram substituídos.', 'dpxl-shield'),
        ]);
    }

    private function formatTotpSecret(string $secret): string {
        return trim(chunk_split($secret, 4, ' '));
    }

    // ── Settings ───────────────────────────────────────────────────────────

    public function getSettings(): \WP_REST_Response {
        // Return all options with prefix stripped.
        global $wpdb;

        $rows = $wpdb->get_results(
            "SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE 'dpxl_shield_%'",
            ARRAY_A
        ) ?? [];

        $settings = [];
        $skip     = ['_site_check_enc_key', '_site_check_timeout_shwp'];

        foreach ($rows as $row) {
            $key = substr((string) $row['option_name'], strlen('dpxl_shield_'));

            if (in_array($key, $skip, true)) {
                continue;
            }

            $settings[$key] = maybe_unserialize($row['option_value']);
        }

        return rest_ensure_response($settings);
    }

    public function saveSettings(\WP_REST_Request $request): \WP_REST_Response {
        $settings = $request->get_json_params();

        if (!is_array($settings)) {
            return new \WP_REST_Response(['error' => 'Invalid payload.'], 400);
        }

        $protected = ['_site_check_enc_key', '_site_check_timeout_shwp'];

        foreach ($settings as $key => $value) {
            $key = sanitize_key((string) $key);

            if (in_array($key, $protected, true)) {
                continue;
            }

            Options::set($key, $value);
        }

        return rest_ensure_response(['success' => true]);
    }

    // ── Import / Export ────────────────────────────────────────────────────

    public function exportSettings(): \WP_REST_Response {
        $export = (new ImportExport())->export();

        return new \WP_REST_Response(
            $export['json'],
            200,
            [
                'Content-Type'        => 'application/json',
                'Content-Disposition' => 'attachment; filename="' . $export['filename'] . '"',
            ]
        );
    }

    public function importSettings(\WP_REST_Request $request): \WP_REST_Response {
        $json = $request->get_body();

        if (!$json) {
            return new \WP_REST_Response(['error' => 'Empty body.'], 400);
        }

        $result = (new ImportExport())->import($json);

        return rest_ensure_response($result);
    }
}
