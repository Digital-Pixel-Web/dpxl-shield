<?php
declare(strict_types=1);

namespace DPXL\Shield\Integrations;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

/**
 * Ordering for the alert severity levels.
 *
 * The rest of the plugin passes severity around as a bare string. Webhook
 * endpoints need to answer "is this at least as severe as my threshold?", which
 * needs a rank — that comparison lives here so the order is defined once.
 */
final class Severity {

    public const INFO     = 'info';
    public const LOW      = 'low';
    public const MEDIUM   = 'medium';
    public const HIGH     = 'high';
    public const CRITICAL = 'critical';

    /** Lowest to highest. */
    private const ORDER = [
        self::INFO     => 0,
        self::LOW      => 1,
        self::MEDIUM   => 2,
        self::HIGH     => 3,
        self::CRITICAL => 4,
    ];

    private function __construct() {}

    /** @return string[] Levels from lowest to highest. */
    public static function all(): array {
        return array_keys(self::ORDER);
    }

    public static function isValid(string $level): bool {
        return isset(self::ORDER[$level]);
    }

    /** Unknown levels rank as INFO — an unrecognised label must never be treated as urgent. */
    public static function rank(string $level): int {
        return self::ORDER[$level] ?? self::ORDER[self::INFO];
    }

    /** True when $level is at least as severe as $threshold. */
    public static function atLeast(string $level, string $threshold): bool {
        return self::rank($level) >= self::rank($threshold);
    }
}
