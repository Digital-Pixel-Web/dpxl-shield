<?php
declare(strict_types=1);

namespace DPXL\Shield\Firewall;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

/**
 * The outcome of evaluating one rule against a request.
 *
 * Immutable by convention: the properties are read-only in spirit but declared
 * plainly, since `readonly` and promoted constructor properties are PHP 8
 * features and the plugin's floor is 7.4.
 */
class RuleResult {

    /** @var string One of the Decision constants. */
    public $decision;

    /** @var string */
    public $ruleId;

    /** @var string */
    public $reason;

    /** @var string */
    public $severity;

    public function __construct(
        string $decision,
        string $ruleId = '',
        string $reason = '',
        string $severity = 'low'
    ) {
        $this->decision = $decision;
        $this->ruleId   = $ruleId;
        $this->reason   = $reason;
        $this->severity = $severity;
    }

    public static function pass(): self {
        return new self(Decision::PASS);
    }

    public static function block(string $ruleId, string $reason, string $severity = 'high'): self {
        return new self(Decision::BLOCK, $ruleId, $reason, $severity);
    }

    public static function challenge(string $ruleId, string $reason): self {
        return new self(Decision::CHALLENGE, $ruleId, $reason, 'medium');
    }

    public static function logOnly(string $ruleId, string $reason): self {
        return new self(Decision::LOG_ONLY, $ruleId, $reason, 'low');
    }
}
