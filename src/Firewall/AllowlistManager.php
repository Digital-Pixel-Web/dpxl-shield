<?php
declare(strict_types=1);

namespace DPXL\Shield\Firewall;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

use DPXL\Shield\Core\Options;

/**
 * Manages the list of URI patterns that bypass the WAF entirely.
 *
 * Patterns support two formats:
 *   - Exact / prefix:  "/my-legacy-endpoint"
 *   - Regex (PCRE):    "/\/wp-json\/my-plugin\/v1\/.* /"  (wrapped in forward slashes)
 */
class AllowlistManager {

    private const OPTION_KEY = 'allowlisted_uris';

    public static function isAllowlisted(string $uri): bool {
        foreach (self::getPatterns() as $pattern) {
            $pattern = trim($pattern);

            if ($pattern === '') {
                continue;
            }

            if (self::matchesPattern($pattern, $uri)) {
                return true;
            }
        }

        return false;
    }

    /** @return string[] */
    public static function getPatterns(): array {
        $stored = Options::get(self::OPTION_KEY, []);
        return is_array($stored) ? array_filter($stored) : [];
    }

    /** @param string[] $patterns */
    public static function setPatterns(array $patterns): void {
        Options::set(self::OPTION_KEY, array_values(array_filter(array_map('trim', $patterns))));
    }

    public static function addPattern(string $pattern): void {
        $patterns = self::getPatterns();

        if (!in_array($pattern, $patterns, true)) {
            $patterns[] = $pattern;
            self::setPatterns($patterns);
        }
    }

    public static function removePattern(string $pattern): void {
        self::setPatterns(array_values(array_filter(self::getPatterns(), fn($p) => $p !== $pattern)));
    }

    /** @return string[] */
    public static function getAll(): array {
        return self::getPatterns();
    }

    /** @param string[] $patterns */
    public static function import(array $patterns): void {
        $existing = self::getPatterns();
        $merged   = array_unique(array_merge($existing, array_filter(array_map('trim', $patterns))));
        self::setPatterns(array_values($merged));
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private static function matchesPattern(string $pattern, string $uri): bool {
        // PCRE regex: pattern wrapped in /…/
        if (str_starts_with($pattern, '/') && strlen($pattern) > 2) {
            $lastSlash = strrpos($pattern, '/');

            if ($lastSlash > 0) {
                if (@preg_match($pattern, $uri) === 1) {
                    return true;
                }
            }
        }

        // Exact or prefix string match.
        return $uri === $pattern || str_starts_with($uri, $pattern);
    }
}
