<?php
declare(strict_types=1);

namespace DPXL\Shield\Firewall\Rules;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

use DPXL\Shield\Firewall\Decision;
use DPXL\Shield\Firewall\Request;
use DPXL\Shield\Firewall\RuleResult;

class RuleEngine {

    /** @var RuleInterface[] */
    private array $rules = [];

    public function __construct() {
        $this->registerDefaults();
    }

    private function registerDefaults(): void {
        // Built-in rules are the immutable protection floor — always present.
        $this->addRule(new GenericHeuristicRule());  // priority 5  — critical obfuscation
        $this->addRule(new SqlInjectionRule());       // priority 10
        $this->addRule(new RfiRule());                // priority 11
        $this->addRule(new LfiRule());                // priority 12
        $this->addRule(new XssRule());                // priority 15
        $this->addRule(new WordPressRule());           // priority 20

        // Threat-feed rules add coverage on top (block-only). Absent/invalid feed
        // file → no rules added; the built-ins above still run. Safe pre-WordPress.
        foreach (RuleRepository::load() as $rule) {
            $this->addRule($rule);
        }
    }

    public function addRule(RuleInterface $rule): void {
        $this->rules[] = $rule;
        usort($this->rules, static fn(RuleInterface $a, RuleInterface $b) => $a->getPriority() <=> $b->getPriority());
    }

    public function evaluate(Request $request): RuleResult {
        foreach ($this->rules as $rule) {
            if (!$rule->isEnabled()) {
                continue;
            }

            $result = $rule->evaluate($request);

            // Any non-PASS decision stops the chain (block/challenge/log_only already logged).
            if ($result->decision !== Decision::PASS) {
                return $result;
            }
        }

        return RuleResult::pass();
    }

    /** @return RuleInterface[] */
    public function getRules(): array {
        return $this->rules;
    }
}
