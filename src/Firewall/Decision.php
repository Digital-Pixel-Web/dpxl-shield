<?php
declare(strict_types=1);

namespace DPXL\Shield\Firewall;

/**
 * What the firewall decided to do with a request.
 *
 * A plain class of string constants rather than an enum: the plugin supports
 * PHP 7.4, where enums do not exist. The values are the same strings that are
 * stored in the traffic log's waf_action column, so a Decision can be compared,
 * persisted and read back without conversion.
 */
final class Decision {

    public const PASS      = 'pass';
    public const BLOCK     = 'block';
    public const CHALLENGE = 'challenge';
    public const LOG_ONLY  = 'log_only';

    /** Not instantiable — this is a namespace for constants. */
    private function __construct() {}

    /** @return string[] Every valid decision value. */
    public static function all(): array {
        return [self::PASS, self::BLOCK, self::CHALLENGE, self::LOG_ONLY];
    }

    public static function isValid(string $decision): bool {
        return in_array($decision, self::all(), true);
    }
}
