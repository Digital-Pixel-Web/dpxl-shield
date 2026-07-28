<?php
declare(strict_types=1);

namespace DPXL\Shield\Firewall\Rules;

use DPXL\Shield\Firewall\RuleResult;

abstract class AbstractRule implements RuleInterface {

    protected bool $enabled = true;

    public function isEnabled(): bool {
        return $this->enabled;
    }

    public function setEnabled(bool $enabled): static {
        $this->enabled = $enabled;

        return $this;
    }

    /**
     * Tests a regex pattern against a value; returns true on match.
     * Uses a timeout-safe approach with a character limit.
     */
    protected function matchesPattern(string $pattern, string $value): bool {
        if ($value === '') {
            return false;
        }

        // Truncate extremely long values before regex to prevent ReDoS.
        $value = substr($value, 0, 8192);

        $result = @preg_match($pattern, $value);

        return $result === 1;
    }

    /**
     * Checks whether a value matches any pattern in the list.
     *
     * @param string[] $patterns PCRE patterns
     */
    protected function matchesAny(array $patterns, string $value): bool {
        foreach ($patterns as $pattern) {
            if ($this->matchesPattern($pattern, $value)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Flattens an array of parameters to a list of scalar string values,
     * recursing into nested arrays.
     *
     * @return string[]
     */
    protected function flattenValues(array $params): array {
        $values = [];

        array_walk_recursive($params, static function ($v) use (&$values): void {
            if (is_scalar($v)) {
                $values[] = (string) $v;
            }
        });

        return $values;
    }

    /** Builds a block result using this rule's ID. */
    protected function block(string $reason, string $severity = 'high'): RuleResult {
        return RuleResult::block($this->getId(), $reason, $severity);
    }

    protected function logOnly(string $reason): RuleResult {
        return RuleResult::logOnly($this->getId(), $reason);
    }
}
