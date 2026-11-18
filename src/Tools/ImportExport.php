<?php
declare(strict_types=1);

namespace DPXL\Shield\Tools;

use DPXL\Shield\Core\Options;
use DPXL\Shield\Firewall\IpBlocklist;
use DPXL\Shield\Firewall\AllowlistManager;

/**
 * Exports all plugin configuration to a signed JSON bundle.
 * Imports that bundle back with schema validation and integrity check.
 *
 * Exported:
 *   - All dpxl_shield_* options
 *   - Manually-added blocked IPs (is_permanent = 1)
 *   - Allowed IP / URI patterns
 *   - Custom pattern blocker rules
 *   - Country block rules
 *
 * Not exported:
 *   - Traffic logs (too large)
 *   - Scan results (too large)
 *   - TOTP secrets (security)
 *   - Encryption keys
 *   - Webhook endpoints (they carry live credentials — see EXCLUDED_OPTS)
 */
class ImportExport {

    private const FORMAT_VERSION = '1.0';
    private const HASH_ALGO      = 'sha256';

    /**
     * Options kept out of the bundle.
     *
     * `webhook_endpoints` holds live credentials: signing secrets, PagerDuty
     * routing keys, and — for Slack and Discord — the URL itself, which is the
     * credential. The bundle is a plain JSON file an administrator downloads and
     * may forward, so none of that belongs in it. Excluding the endpoints also
     * avoids the worse outcome of restoring one bundle across many sites and
     * silently pointing all of them at a single channel.
     *
     * `webhook_status` is per-site delivery history — meaningless elsewhere.
     *
     * `spamhaus_dqs_key` is a credential too, and a rate-limited one: the key
     * is the account. Copying a bundle across many sites would have them all
     * query under one key and burn its quota, which ends with the key blocked
     * for every site at once.
     */
    private const EXCLUDED_OPTS = [
        'integrity_key',
        'integrity_store',
        'webhook_endpoints',
        'webhook_status',
        'spamhaus_dqs_key',
        // Same reasoning: personal API credentials, not portable settings.
        'google_safe_browsing_key',
        'vuln_api_token',
        // Per-site state that must not be overwritten from another site.
        'known_ips',
        'file_checksums',
        'integrity_baseline_at',
        'integrity_version',
        'integrity_violation',
        'last_fatal',
    ];

    // ── Export ─────────────────────────────────────────────────────────────

    /** @return array{json: string, filename: string} */
    public function export(): array {
        $bundle = [
            'format_version' => self::FORMAT_VERSION,
            'exported_at'    => gmdate('c'),
            'site_url'       => get_option('siteurl'),
            'plugin_version' => defined('DPXL_SHIELD_VERSION') ? DPXL_SHIELD_VERSION : '1.0.0',
            'data'           => [
                'options'          => $this->exportOptions(),
                'blocked_ips'      => $this->exportBlockedIps(),
                'allowlist'        => AllowlistManager::getAll(),
                'custom_patterns'  => $this->exportCustomPatterns(),
                'country_blocks'   => $this->exportCountryBlocks(),
            ],
        ];

        $json = (string) wp_json_encode($bundle, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        // Sign the bundle: append hash after removing any prior hash field.
        $bundle['hash'] = hash(self::HASH_ALGO, $json);
        $json = (string) wp_json_encode($bundle, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        $filename = sprintf(
            'dpxl-shield-export-%s-%s.json',
            wp_parse_url((string) get_option('siteurl'), PHP_URL_HOST) ?: 'site',
            gmdate('Ymd-His')
        );

        return ['json' => $json, 'filename' => $filename];
    }

    // ── Import ─────────────────────────────────────────────────────────────

    /**
     * @return array{success: bool, message: string, counts: array<string,int>}
     */
    public function import(string $json): array {
        $bundle = json_decode($json, true);

        if (!is_array($bundle)) {
            return ['success' => false, 'message' => 'Invalid JSON.', 'counts' => []];
        }

        // Verify hash integrity.
        $providedHash = (string) ($bundle['hash'] ?? '');
        unset($bundle['hash']);

        $expectedJson = (string) wp_json_encode($bundle, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        $expectedHash = hash(self::HASH_ALGO, $expectedJson);

        if (!hash_equals($expectedHash, $providedHash)) {
            return ['success' => false, 'message' => 'Bundle integrity check failed — file may be corrupted or tampered.', 'counts' => []];
        }

        // Version compatibility check.
        $formatVersion = (string) ($bundle['format_version'] ?? '');

        if ($formatVersion !== self::FORMAT_VERSION) {
            return ['success' => false, 'message' => "Unsupported format version: {$formatVersion}.", 'counts' => []];
        }

        $data   = (array) ($bundle['data'] ?? []);
        $counts = [];

        $counts['options'] = $this->importOptions((array) ($data['options'] ?? []));
        $counts['blocked_ips'] = $this->importBlockedIps((array) ($data['blocked_ips'] ?? []));

        if (!empty($data['allowlist']) && is_array($data['allowlist'])) {
            AllowlistManager::import($data['allowlist']);
            $counts['allowlist'] = count($data['allowlist']);
        }

        $counts['custom_patterns'] = $this->importCustomPatterns((array) ($data['custom_patterns'] ?? []));
        $counts['country_blocks']  = $this->importCountryBlocks((array) ($data['country_blocks'] ?? []));

        return ['success' => true, 'message' => 'Import completed successfully.', 'counts' => $counts];
    }

    // ── Options ────────────────────────────────────────────────────────────

    /** @return array<string,mixed> */
    private function exportOptions(): array {
        global $wpdb;

        $rows = $wpdb->get_results(
            "SELECT option_name, option_value FROM {$wpdb->options}
             WHERE option_name LIKE 'dpxl_shield_%'",
            ARRAY_A
        ) ?? [];

        $options = [];

        foreach ($rows as $row) {
            $name = (string) $row['option_name'];

            // Strip the prefix for cleaner export.
            $key = substr($name, strlen('dpxl_shield_'));

            if (in_array($key, self::EXCLUDED_OPTS, true)) {
                continue;
            }

            $options[$key] = maybe_unserialize($row['option_value']);
        }

        return $options;
    }

    private function importOptions(array $options): int {
        $count = 0;

        foreach ($options as $key => $value) {
            if (in_array((string) $key, self::EXCLUDED_OPTS, true)) {
                continue;
            }

            Options::set((string) $key, $value);
            $count++;
        }

        return $count;
    }

    // ── Blocked IPs ────────────────────────────────────────────────────────

    /** @return array<int,array<string,mixed>> */
    private function exportBlockedIps(): array {
        global $wpdb;

        return $wpdb->get_results(
            "SELECT ip, cidr, reason, source, blocked_at, is_permanent
             FROM {$wpdb->prefix}dpxl_shield_blocked_ips
             WHERE is_permanent = 1",
            ARRAY_A
        ) ?? [];
    }

    private function importBlockedIps(array $ips): int {
        $count = 0;

        foreach ($ips as $row) {
            $ip = (string) ($row['ip'] ?? '');

            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                continue;
            }

            IpBlocklist::blockIp($ip, (string) ($row['reason'] ?? 'Imported'), 'manual', 0);
            $count++;
        }

        return $count;
    }

    // ── Custom patterns ────────────────────────────────────────────────────

    /** @return array<int,array<string,mixed>> */
    private function exportCustomPatterns(): array {
        global $wpdb;

        return $wpdb->get_results(
            "SELECT field, pattern, match_type, action, reason FROM {$wpdb->prefix}dpxl_shield_custom_patterns",
            ARRAY_A
        ) ?? [];
    }

    private function importCustomPatterns(array $patterns): int {
        global $wpdb;
        $count = 0;

        $allowedFields  = ['user_agent', 'referer', 'hostname', 'url'];
        $allowedMatches = ['contains', 'equals', 'regex'];
        $allowedActions = ['block', 'log_only'];

        foreach ($patterns as $row) {
            if (!in_array($row['field'] ?? '', $allowedFields, true)) {
                continue;
            }

            $wpdb->insert(
                $wpdb->prefix . 'dpxl_shield_custom_patterns',
                [
                    'field'      => $row['field'],
                    'pattern'    => substr((string) ($row['pattern'] ?? ''), 0, 500),
                    'match_type' => in_array($row['match_type'] ?? '', $allowedMatches, true) ? $row['match_type'] : 'contains',
                    'action'     => in_array($row['action'] ?? '', $allowedActions, true) ? $row['action'] : 'block',
                    'reason'     => substr((string) ($row['reason'] ?? ''), 0, 255),
                ],
                ['%s', '%s', '%s', '%s', '%s']
            );
            $count++;
        }

        return $count;
    }

    // ── Country blocks ─────────────────────────────────────────────────────

    /** @return array<int,array<string,mixed>> */
    private function exportCountryBlocks(): array {
        global $wpdb;

        return $wpdb->get_results(
            "SELECT country_code, country_name, mode FROM {$wpdb->prefix}dpxl_shield_country_blocks",
            ARRAY_A
        ) ?? [];
    }

    private function importCountryBlocks(array $blocks): int {
        global $wpdb;
        $count = 0;

        foreach ($blocks as $row) {
            $code = strtoupper(substr((string) ($row['country_code'] ?? ''), 0, 2));

            if (strlen($code) !== 2) {
                continue;
            }

            $wpdb->replace(
                $wpdb->prefix . 'dpxl_shield_country_blocks',
                [
                    'country_code' => $code,
                    'country_name' => substr((string) ($row['country_name'] ?? ''), 0, 100),
                    'mode'         => ($row['mode'] ?? 'block') === 'allow' ? 'allow' : 'block',
                ],
                ['%s', '%s', '%s']
            );
            $count++;
        }

        return $count;
    }
}
