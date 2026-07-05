<?php
declare(strict_types=1);

namespace DPXL\Shield\Firewall;

class RuleResult {

    public function __construct(
        public readonly Decision $decision,
        public readonly string $ruleId   = '',
        public readonly string $reason   = '',
        public readonly string $severity = 'low',
    ) {}

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
