<?php
declare(strict_types=1);

namespace DPXL\Shield\Firewall\Rules;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

use DPXL\Shield\Firewall\Request;
use DPXL\Shield\Firewall\RuleResult;

class LfiRule extends AbstractRule {

    // lfi-001: path traversal
    private const PATTERNS = [
        // Classic traversal sequences
        '/\.\.\//',
        '/\.\.\\\\/',
        // URL-encoded traversal
        '/%2e%2e%2f/i',
        '/%2e%2e\//i',
        '/%252e%252e%252f/i',   // double-encoded
        // Null byte injection
        '/\x00/',
        '/%00/',
        // Accessing sensitive files directly
        '/(?:^|\/)(?:etc\/passwd|etc\/shadow|proc\/self\/environ|windows\/win\.ini|boot\.ini)/i',
        // PHP wrappers that enable LFI
        '/(?:php|zip|phar|data|expect|input|glob|ogg|rar):\/\//i',
    ];

    public function getId(): string {
        return 'lfi-001';
    }

    public function getPriority(): int {
        return 12;
    }

    public function evaluate(Request $request): RuleResult {
        $targets = array_merge(
            [$request->uri, $request->queryString],
            $this->flattenValues($request->get),
            $this->flattenValues($request->post),
        );

        foreach ($targets as $value) {
            if ($this->matchesAny(self::PATTERNS, $value)) {
                return $this->block('Local File Inclusion / Path Traversal attempt', 'high');
            }
        }

        return RuleResult::pass();
    }
}
