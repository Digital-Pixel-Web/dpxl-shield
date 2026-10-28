<?php
declare(strict_types=1);

namespace DPXL\Shield\Firewall\Rules;

/**
 * Loads data-driven WAF rules from the active feed file.
 *
 * The file (data/waf-rules.active.json) is produced by the ThreatFeedUpdater
 * after signature + checksum verification, so by the time it reaches disk it is
 * trusted. This loader is intentionally dependency-free — only filesystem and
 * PCRE calls — so it runs in the pre-WordPress Extended-mode path where $wpdb,
 * Options and the WP API do not exist yet.
 *
 * It never throws: a missing, unreadable, malformed or empty file yields an
 * empty rule set, which simply leaves the built-in rules (the protection floor)
 * in charge. Each rule entry is validated independently — one bad regex or a
 * disallowed action drops that entry, never the whole feed.
 */
class RuleRepository {

    /** Hard cap on feed rules, so a malformed/hostile file can't create unbounded work. */
    private const MAX_RULES = 5000;

    /** Per-request memo, keyed by resolved path. @var array<string, list<JsonRule>> */
    private static array $cache = [];

    /** Absolute path to the active feed file, or null to use the default location. */
    private static function defaultPath(): string {
        return \DPXL\Shield\Core\EarlyConfig::dataDir() . '/waf-rules.active.json';
    }

    /**
     * @return list<JsonRule> Validated feed rules; empty when the file is absent/invalid.
     */
    public static function load(?string $path = null): array {
        $path ??= self::defaultPath();

        if (isset(self::$cache[$path])) {
            return self::$cache[$path];
        }

        return self::$cache[$path] = self::build(self::decode($path));
    }

    /** Feed version string from the file's meta, or '' when unavailable. */
    public static function version(?string $path = null): string {
        $data = self::decode($path ?? self::defaultPath());

        $version = $data['meta']['version'] ?? '';

        return is_string($version) ? $version : '';
    }

    /** Clears the per-request memo (used by tests). */
    public static function flushCache(): void {
        self::$cache = [];
    }

    // ── Internals ──────────────────────────────────────────────────────────

    /** @return array<string,mixed> Decoded JSON, or [] on any failure. */
    private static function decode(string $path): array {
        if (!is_readable($path)) {
            return [];
        }

        $raw = @file_get_contents($path);

        if ($raw === false || $raw === '') {
            return [];
        }

        $data = json_decode($raw, true);

        return is_array($data) ? $data : [];
    }

    /**
     * @param  array<string,mixed> $data
     * @return list<JsonRule>
     */
    private static function build(array $data): array {
        $rules = $data['rules'] ?? null;

        if (!is_array($rules)) {
            return [];
        }

        $built = [];

        foreach ($rules as $entry) {
            if (count($built) >= self::MAX_RULES) {
                break;
            }

            $rule = self::makeRule($entry);

            if ($rule !== null) {
                $built[] = $rule;
            }
        }

        return $built;
    }

    /**
     * Validates a single entry and builds a JsonRule, or returns null to skip it.
     *
     * @param mixed $entry
     */
    private static function makeRule($entry): ?JsonRule {
        if (!is_array($entry)) {
            return null;
        }

        $id      = $entry['id']      ?? '';
        $pattern = $entry['pattern'] ?? '';
        $action  = $entry['action']  ?? 'block';

        // Required: non-empty id + pattern. v1 accepts block-only (see JsonRule).
        if (!is_string($id) || $id === '' || !is_string($pattern) || $pattern === '') {
            return null;
        }

        if ($action !== 'block') {
            return null;
        }

        // Reject a pattern PCRE can't compile — @preg_match returns false on error.
        if (@preg_match($pattern, '') === false) {
            return null;
        }

        $targets = self::normaliseTargets($entry['targets'] ?? null);

        if ($targets === []) {
            return null;
        }

        $priority = isset($entry['priority']) && is_numeric($entry['priority'])
            ? (int) $entry['priority']
            : 50;

        $severity = isset($entry['severity']) && is_string($entry['severity'])
            ? $entry['severity']
            : 'high';

        $enabled = !isset($entry['enabled']) || (bool) $entry['enabled'];

        return new JsonRule($id, $priority, $targets, $pattern, $severity, $enabled);
    }

    /**
     * Filters declared targets to the recognised set; falls back to GET/POST/COOKIE.
     *
     * @param  mixed $targets
     * @return list<string>
     */
    private static function normaliseTargets($targets): array {
        if (!is_array($targets) || $targets === []) {
            return ['get', 'post', 'cookie'];
        }

        $clean = [];

        foreach ($targets as $target) {
            if (!is_string($target)) {
                continue;
            }

            $target = strtolower(trim($target));

            if (in_array($target, JsonRule::TARGETS, true) && !in_array($target, $clean, true)) {
                $clean[] = $target;
            }
        }

        return $clean;
    }
}
