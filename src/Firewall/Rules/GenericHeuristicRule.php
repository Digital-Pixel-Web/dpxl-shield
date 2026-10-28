<?php
declare(strict_types=1);

namespace DPXL\Shield\Firewall\Rules;

use DPXL\Shield\Firewall\Request;
use DPXL\Shield\Firewall\RuleResult;

class GenericHeuristicRule extends AbstractRule {

    // generic-001: eval+base64 / obfuscated PHP execution
    private const PATTERNS_OBFUSCATION = [
        '/eval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode|hex2bin)\s*\(/i',
        '/assert\s*\(\s*(?:base64_decode|gzinflate)\s*\(/i',
        '/preg_replace\s*\(\s*["\'].*\/e["\'\s]/i',  // /e modifier (code execution)
        '/(?:call_user_func|call_user_func_array)\s*\(\s*\$_/i',
    ];

    // generic-002: shell execution functions
    private const PATTERNS_SHELL = [
        '/\b(?:system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\(\s*(?:\$_|\$[a-z]/i',
    ];

    // generic-003: anomalous headers
    private const MAX_HEADER_LENGTH = 4096;

    public function getId(): string {
        return 'generic-001';
    }

    public function getPriority(): int {
        return 5;   // Highest priority — most critical patterns.
    }

    public function evaluate(Request $request): RuleResult {
        // generic-001: obfuscated code execution in any input
        $allValues = array_merge(
            $this->flattenValues($request->get),
            $this->flattenValues($request->post),
            $this->flattenValues($request->cookies),
            [$request->rawBody],
        );

        foreach ($allValues as $value) {
            if ($this->matchesAny(self::PATTERNS_OBFUSCATION, $value)) {
                return $this->block('Obfuscated PHP code execution attempt', 'critical');
            }
        }

        // generic-002: shell execution functions in input
        foreach ($allValues as $value) {
            if ($this->matchesAny(self::PATTERNS_SHELL, $value)) {
                return $this->block('Remote code execution attempt via shell functions', 'critical');
            }
        }

        // generic-003: anomalous headers (oversized or invalid encoding)
        if (
            strlen($request->userAgent) > self::MAX_HEADER_LENGTH
            || strlen($request->referer) > self::MAX_HEADER_LENGTH
        ) {
            return $this->block('Anomalous HTTP header length', 'medium');
        }

        // Check for binary / null-byte injection in headers.
        if (
            str_contains($request->userAgent, "\x00")
            || str_contains($request->referer, "\x00")
        ) {
            return $this->block('Null-byte injection in HTTP headers', 'high');
        }

        return RuleResult::pass();
    }
}
