<?php
declare(strict_types=1);

namespace DPXL\Shield\Firewall\Rules;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

use DPXL\Shield\Firewall\Request;
use DPXL\Shield\Firewall\RuleResult;

class SqlInjectionRule extends AbstractRule {

    // sqli-001: GET/POST parameters
    // sqli-002: Cookie values
    private const PATTERNS = [
        // UNION-based extraction
        '/(?:union\s+(?:all\s+)?select)/i',
        // Classic tautologies
        '/\bor\s+[\'"]?1[\'"]?\s*=\s*[\'"]?1/i',
        '/\band\s+[\'"]?1[\'"]?\s*=\s*[\'"]?1/i',
        // Comment-based termination
        '/[\'"];?\s*(?:--|#|\/\*)/i',
        // Destructive / schema queries
        '/\b(?:drop|truncate|alter)\s+(?:table|database)\b/i',
        '/\binsert\s+into\b/i',
        '/\bdelete\s+from\b/i',
        '/\bupdate\s+\w+\s+set\b/i',
        // Data extraction
        '/\bselect\s+.+\s+from\b/i',
        '/\binformation_schema\b/i',
        '/\bload_file\s*\(/i',
        '/\binto\s+(?:outfile|dumpfile)\b/i',
        // Stacked queries
        '/;\s*(?:select|insert|update|delete|drop|create|alter|exec)\b/i',
        // Hex / char encoding evasion
        '/\b(?:char|nchar|varchar)\s*\(\s*\d+/i',
        '/0x[0-9a-f]{4,}/i',
        // Benchmark / sleep (time-based blind)
        '/\b(?:benchmark|sleep)\s*\(\s*\d+/i',
        '/\bwaitfor\s+delay\b/i',
    ];

    public function getId(): string {
        return 'sqli-001';
    }

    public function getPriority(): int {
        return 10;
    }

    public function evaluate(Request $request): RuleResult {
        $targets = array_merge(
            $this->flattenValues($request->get),
            $this->flattenValues($request->post),
            $this->flattenValues($request->cookies),
        );

        foreach ($targets as $value) {
            if ($this->matchesAny(self::PATTERNS, $value)) {
                return $this->block('SQL Injection attempt detected', 'high');
            }
        }

        return RuleResult::pass();
    }
}
