<?php
declare(strict_types=1);

namespace DPXL\Shield\Firewall;

/**
 * Blocks requests matching admin-defined patterns on specific HTTP fields.
 *
 * Evaluated fields: user_agent | referer | hostname | url
 * Match types:      contains | equals | regex
 * Actions:          block | log_only
 *
 * Rules are cached in APCu / transient to avoid a DB hit on every request.
 * Cache is invalidated whenever a rule is created, updated, or deleted.
 */
class CustomPatternBlocker {

    private const CACHE_KEY = 'dpxl_shield_custom_patterns';
    private const CACHE_TTL = 300;

    private static ?array $rules = null;

    public static function check(Request $request): RuleResult {
        foreach (self::getRules() as $rule) {
            if (self::isExpired($rule)) {
                continue;
            }

            $value = self::targetValue($request, (string) ($rule['field'] ?? ''));

            if ($value === null) {
                continue;
            }

            if (!self::matches($value, (string) ($rule['pattern'] ?? ''), (string) ($rule['match_type'] ?? 'contains'))) {
                continue;
            }

            $reason = $rule['reason'] ?: "Custom pattern match on field '{$rule['field']}'";

            if (($rule['action'] ?? 'block') === 'block') {
                return RuleResult::block('custom-pattern', $reason, 'medium');
            }

            return RuleResult::logOnly('custom-pattern', $reason);
        }

        return RuleResult::pass();
    }

    public static function invalidateCache(): void {
        self::$rules = null;

        if (function_exists('apcu_delete')) {
            apcu_delete(self::CACHE_KEY);
        }

        if (function_exists('delete_transient')) {
            delete_transient(self::CACHE_KEY);
        }
    }

    // ── Internal ───────────────────────────────────────────────────────────

    private static function getRules(): array {
        if (self::$rules !== null) {
            return self::$rules;
        }

        if (function_exists('apcu_fetch')) {
            $cached = apcu_fetch(self::CACHE_KEY, $ok);

            if ($ok && is_array($cached)) {
                return self::$rules = $cached;
            }
        }

        if (function_exists('get_transient')) {
            $cached = get_transient(self::CACHE_KEY);

            if (is_array($cached)) {
                return self::$rules = $cached;
            }
        }

        $rules = self::loadFromDatabase();

        if (function_exists('apcu_store')) {
            apcu_store(self::CACHE_KEY, $rules, self::CACHE_TTL);
        }

        if (function_exists('set_transient')) {
            set_transient(self::CACHE_KEY, $rules, self::CACHE_TTL);
        }

        return self::$rules = $rules;
    }

    private static function loadFromDatabase(): array {
        global $wpdb;

        // No WordPress / no $wpdb (Extended Protection runs pre-WordPress):
        // return no rules instead of dereferencing a null $wpdb.
        if (!function_exists('get_transient') || !$wpdb instanceof \wpdb) {
            return [];
        }

        return $wpdb->get_results(
            "SELECT field, pattern, match_type, action, reason, expires_at
             FROM {$wpdb->prefix}dpxl_shield_custom_patterns
             ORDER BY id ASC",
            ARRAY_A
        ) ?? [];
    }

    private static function targetValue(Request $request, string $field): ?string {
        $values = [
            'user_agent' => $request->userAgent,
            'referer'    => $request->referer,
            'hostname'   => $request->host,
            'url'        => $request->uri,
        ];

        return $values[$field] ?? null;
    }

    private static function matches(string $value, string $pattern, string $type): bool {
        switch ($type) {
            case 'contains':
                return str_contains(strtolower($value), strtolower($pattern));
            case 'equals':
                return strtolower($value) === strtolower($pattern);
            case 'regex':
                return @preg_match($pattern, $value) === 1;
            default:
                return false;
        }
    }

    private static function isExpired(array $rule): bool {
        return !empty($rule['expires_at']) && strtotime((string) $rule['expires_at']) < time();
    }
}
