<?php
declare(strict_types=1);

namespace DPXL\Shield\Firewall;

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

    /**
     * @var string Name of the request parameter that triggered the rule, when
     * the rule knows it (e.g. "referrer"). Empty otherwise. Logged so a false
     * positive can be traced to the form field that caused it.
     */
    public $field = '';

    public function __construct(
        string $decision,
        string $ruleId = '',
        string $reason = '',
        string $severity = 'low',
        string $field = ''
    ) {
        $this->decision = $decision;
        $this->ruleId   = $ruleId;
        $this->reason   = $reason;
        $this->severity = $severity;
        $this->field    = $field;
    }

    public static function pass(): self {
        return new self(Decision::PASS);
    }

    public static function block(string $ruleId, string $reason, string $severity = 'high', string $field = ''): self {
        return new self(Decision::BLOCK, $ruleId, $reason, $severity, $field);
    }

    public static function challenge(string $ruleId, string $reason): self {
        return new self(Decision::CHALLENGE, $ruleId, $reason, 'medium');
    }

    public static function logOnly(string $ruleId, string $reason): self {
        return new self(Decision::LOG_ONLY, $ruleId, $reason, 'low');
    }
}
