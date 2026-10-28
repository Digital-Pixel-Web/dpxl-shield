<?php
declare(strict_types=1);

namespace DPXL\Shield\Core;

use DPXL\Shield\Threat\AtomicFile;

/**
 * Writes the two files Extended Protection reads before WordPress loads:
 *
 *   early-config.php  — firewall on/off, rate limits, allowlisted URIs
 *   blocked-ips.php   — snapshot of the active blocklist, with expiries
 *
 * Both live in the plugin's data folder (see dataDir()), next to the threat
 * feed, the country database and the early event queue.
 *
 * The pre-WordPress loader has always read these files, but nothing ever wrote
 * them. With no config the loader treated the firewall as switched off, and
 * because Extended mode also turns the in-WordPress WAF off, enabling Extended
 * Protection left the site with no rule-based firewall at all.
 *
 * Both files are plain `<?php return [...]` arrays built with var_export(), so
 * no value read from the database can become code.
 */
final class EarlyConfig {

    /** Upper bound for the blocklist snapshot, so the file stays cheap to include. */
    private const MAX_BLOCKED = 20000;

    /** Test hook: points the files somewhere disposable. */
    private static ?string $dataDirOverride = null;

    private static ?string $resolvedDataDir = null;

    private function __construct() {}

    /**
     * wp-content/uploads/dpxl-shield — where every file the plugin writes at
     * runtime lives.
     *
     * Not the plugin folder: WordPress replaces it on every update, which
     * wiped the feed, the country database and the firewall config each time.
     * The pre-WordPress loader cannot ask WordPress where uploads are, so both
     * sides derive the same path: the uploads folder beside the plugins
     * folder. A site that moved its uploads elsewhere gets WordPress's own
     * uploads path instead; the Extended Protection loader then carries that
     * path in DPXL_SHIELD_DATA_DIR.
     */
    public static function dataDir(): string {
        if (self::$dataDirOverride !== null) {
            return self::$dataDirOverride;
        }

        // Set by the Extended Protection loader (AutoPrepend), which records
        // the folder WordPress resolved when protection was turned on.
        if (defined('DPXL_SHIELD_DATA_DIR') && is_string(DPXL_SHIELD_DATA_DIR) && DPXL_SHIELD_DATA_DIR !== '') {
            return DPXL_SHIELD_DATA_DIR;
        }

        return self::$resolvedDataDir ??= self::resolveDataDir();
    }

    /** The data folder before 1.12.1, inside the plugin. Only uninstall still looks at it. */
    public static function legacyDataDir(): string {
        return dirname(__DIR__, 2) . '/data';
    }

    private static function resolveDataDir(): string {
        // src/Core → plugin → plugins → wp-content.
        $besidePlugins = dirname(__DIR__, 4) . '/uploads';

        if (is_dir($besidePlugins) || !function_exists('wp_upload_dir')) {
            return $besidePlugins . '/dpxl-shield';
        }

        $switched = false;

        // One folder for the whole network: the firewall protects the install,
        // not a single site of it.
        if (function_exists('is_multisite') && is_multisite() && !is_main_site()) {
            switch_to_blog(get_main_site_id());
            $switched = true;
        }

        $uploads = wp_upload_dir(null, false);

        if ($switched) {
            restore_current_blog();
        }

        $base = is_array($uploads) && !empty($uploads['basedir']) ? (string) $uploads['basedir'] : $besidePlugins;

        return rtrim($base, '/\\') . '/dpxl-shield';
    }

    public static function useDataDir(?string $dir): void {
        self::$dataDirOverride = $dir;
    }

    public static function configPath(): string {
        return self::dataDir() . '/early-config.php';
    }

    public static function blockedIpsPath(): string {
        return self::dataDir() . '/blocked-ips.php';
    }

    /** Rewrites both files. Safe to call on any request that has WordPress loaded. */
    public static function writeAll(): void {
        self::writeConfig();
        self::writeBlocklist();
    }

    /** Writes the files only if one is missing — e.g. on the first request after an install. */
    public static function ensure(): void {
        if (!is_file(self::configPath()) || !is_file(self::blockedIpsPath())) {
            self::writeAll();
        }
    }

    /** Creates the data folder, closed to the web, and returns whether it is usable. */
    public static function ensureDataDir(): bool {
        $dir = self::dataDir();

        if (!Fs::mkdirP($dir)) {
            return false;
        }

        \DPXL\Shield\Scanner\FileRepair::protectDirectory($dir);

        return true;
    }

    public static function writeConfig(): bool {
        if (!function_exists('get_option')) {
            return false;
        }

        $config = [
            'firewall_enabled' => (bool) Options::get('firewall_enabled', true),
            'rate_limits'      => [
                'login'  => (int) Options::get('rate_limit_login', 5),
                'xmlrpc' => (int) Options::get('rate_limit_xmlrpc', 10),
                'rest'   => (int) Options::get('rate_limit_rest', 60),
            ],
            'allowlisted_uris' => array_values(array_map('strval', (array) Options::get('allowlisted_uris', []))),
            'generated_at'     => time(),
        ];

        return self::write(self::configPath(), $config);
    }

    public static function writeBlocklist(): bool {
        global $wpdb;

        if (!function_exists('get_option') || !$wpdb instanceof \wpdb) {
            return false;
        }

        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT ip, cidr, is_permanent, TIMESTAMPDIFF(SECOND, UTC_TIMESTAMP(), expires_at) AS ttl
                 FROM {$wpdb->prefix}dpxl_shield_blocked_ips
                 WHERE (expires_at IS NULL OR expires_at > UTC_TIMESTAMP() OR is_permanent = 1)
                 ORDER BY id DESC
                 LIMIT %d",
                self::MAX_BLOCKED
            ),
            ARRAY_A
        );

        if (!is_array($rows)) {
            return false;
        }

        $list = ['exact' => [], 'cidr' => []];

        foreach ($rows as $row) {
            // expires_at is stored in UTC; the TTL is computed in SQL so the
            // MySQL session time zone cannot shift it. 0 = never expires.
            $ttl     = $row['ttl'] ?? null;
            $expires = (!empty($row['is_permanent']) || $ttl === null) ? 0 : time() + (int) $ttl;

            if (!empty($row['cidr'])) {
                $list['cidr'][] = [(string) $row['cidr'], $expires];
            } elseif (filter_var((string) $row['ip'], FILTER_VALIDATE_IP) !== false) {
                $list['exact'][] = [(string) $row['ip'], $expires];
            }
        }

        return self::write(self::blockedIpsPath(), $list);
    }

    /** @param array<string,mixed> $data */
    private static function write(string $path, array $data): bool {
        if (!self::ensureDataDir()) {
            return false;
        }

        $php = "<?php\n// Generated by DPXL Shield. Do not edit — it is rewritten on every change.\n"
            . "if (!defined('ABSPATH') && !defined('DPXL_SHIELD_EXTENDED_ACTIVE')) { exit; }\n"
            . 'return ' . var_export($data, true) . ";\n"; // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- writes a PHP literal into a generated file, not debug output.

        // No .bak copy: a .php.bak is served as plain text by most servers.
        Fs::delete($path . '.bak');

        return AtomicFile::write($path, $php, false);
    }
}
