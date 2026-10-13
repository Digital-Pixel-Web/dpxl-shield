<?php
declare(strict_types=1);

namespace DPXL\Shield\Firewall;

use MaxMind\Db\Reader;
use DPXL\Shield\Core\Logger;

/**
 * Country-based blocking / allow-listing via MaxMind GeoLite2.
 *
 * Requires the GeoLite2-Country.mmdb database file in the plugin's data/
 * directory. The database is ~6 MB and must be downloaded separately
 * (MaxMind requires a free account).
 *
 * Modes:
 *   'block'  → block every IP whose country is in the list
 *   'allow'  → block every IP whose country is NOT in the list
 */
class CountryBlocker {

    private const APCu_KEY  = 'dpxl_shield_country_config';
    private const APCu_TTL  = 300;   // 5 minutes
    private const DB_TTL    = 300;   // fallback transient TTL

    /** In-process cache: ['codes' => string[], 'mode' => string] */
    private static ?array $config = null;

    public static function check(string $ip): RuleResult {
        $cfg = self::getConfig();

        if (empty($cfg['codes'])) {
            return RuleResult::pass();
        }

        $country = self::resolveCountry($ip);

        if ($country === null) {
            return RuleResult::pass();   // Unknown country → pass (don't block innocent traffic)
        }

        $mode = $cfg['mode'] ?? 'block';

        if ($mode === 'block' && in_array($country, $cfg['codes'], true)) {
            return RuleResult::block('country-block', "Country blocked: {$country}", 'medium');
        }

        if ($mode === 'allow' && !in_array($country, $cfg['codes'], true)) {
            return RuleResult::block('country-allow', "Country not in allowlist: {$country}", 'medium');
        }

        return RuleResult::pass();
    }

    /**
     * Resolves the ISO 3166-1 alpha-2 country code for an IP address.
     * Returns null if the database is missing or the IP is not found.
     */
    public static function resolveCountry(string $ip): ?string {
        $mmdbPath = self::mmdbPath();

        if (!file_exists($mmdbPath)) {
            return null;
        }

        try {
            $reader  = new Reader($mmdbPath);
            $record  = $reader->get($ip);
            $reader->close();

            return $record['country']['iso_code'] ?? null;
        } catch (\Exception $e) {
            Logger::error('CountryBlocker: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Country name for an IP, in Portuguese when the database carries it.
     *
     * GeoLite2-Country ships localised names (`names['pt-BR']`), so an alert
     * email can say "Brasil" instead of "BR" without the plugin bundling its
     * own ISO table. Falls back to English, then to the ISO code, then null —
     * an unknown origin is reported as unknown, never guessed.
     */
    public static function resolveCountryName(string $ip, string $locale = 'pt-BR'): ?string {
        $mmdbPath = self::mmdbPath();

        if (!file_exists($mmdbPath)) {
            return null;
        }

        try {
            $reader = new Reader($mmdbPath);
            $record = $reader->get($ip);
            $reader->close();
        } catch (\Exception $e) {
            Logger::error('CountryBlocker: ' . $e->getMessage());
            return null;
        }

        if (!is_array($record) || !isset($record['country'])) {
            return null;
        }

        $country = $record['country'];
        $names   = isset($country['names']) && is_array($country['names']) ? $country['names'] : [];

        foreach ([$locale, 'pt-BR', 'en'] as $candidate) {
            if (isset($names[$candidate]) && $names[$candidate] !== '') {
                return (string) $names[$candidate];
            }
        }

        return isset($country['iso_code']) && $country['iso_code'] !== ''
            ? (string) $country['iso_code']
            : null;
    }

    public static function isDatabasePresent(): bool {
        return file_exists(self::mmdbPath());
    }

    public static function invalidateCache(): void {
        self::$config = null;

        if (function_exists('apcu_delete')) {
            apcu_delete(self::APCu_KEY);
        }

        if (function_exists('delete_transient')) {
            delete_transient(self::APCu_KEY);
        }
    }

    // ── Internal ───────────────────────────────────────────────────────────

    /** @return array{codes:string[], mode:string} */
    private static function getConfig(): array {
        if (self::$config !== null) {
            return self::$config;
        }

        // APCu (fastest — shared across requests, pre-WordPress capable)
        if (function_exists('apcu_fetch')) {
            $cached = apcu_fetch(self::APCu_KEY, $ok);

            if ($ok && is_array($cached)) {
                return self::$config = $cached;
            }
        }

        // WordPress transient (available after WP loads)
        if (function_exists('get_transient')) {
            $cached = get_transient(self::APCu_KEY);

            if (is_array($cached)) {
                return self::$config = $cached;
            }
        }

        $config = self::loadFromDatabase();

        if (function_exists('apcu_store')) {
            apcu_store(self::APCu_KEY, $config, self::APCu_TTL);
        }

        if (function_exists('set_transient')) {
            set_transient(self::APCu_KEY, $config, self::DB_TTL);
        }

        return self::$config = $config;
    }

    private static function loadFromDatabase(): array {
        global $wpdb;

        // No WordPress / no $wpdb (Extended Protection runs pre-WordPress):
        // return an empty config instead of dereferencing a null $wpdb.
        if (!function_exists('get_transient') || !$wpdb instanceof \wpdb) {
            return ['codes' => [], 'mode' => 'block'];
        }

        $rows = $wpdb->get_results(
            "SELECT country_code, mode
             FROM {$wpdb->prefix}dpxl_shield_country_blocks
             ORDER BY country_code ASC",
            ARRAY_A
        );

        if (empty($rows)) {
            return ['codes' => [], 'mode' => 'block'];
        }

        return [
            'codes' => array_column($rows, 'country_code'),
            'mode'  => $rows[0]['mode'] ?? 'block',
        ];
    }

    private static function mmdbPath(): string {
        return defined('DPXL_SHIELD_PATH')
            ? DPXL_SHIELD_PATH . 'data/GeoLite2-Country.mmdb'
            : __DIR__ . '/../../data/GeoLite2-Country.mmdb';
    }
}
