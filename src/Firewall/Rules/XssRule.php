<?php
declare(strict_types=1);

namespace DPXL\Shield\Firewall\Rules;

use DPXL\Shield\Firewall\Request;
use DPXL\Shield\Firewall\RuleResult;

class XssRule extends AbstractRule {

    // xss-001: reflected XSS in parameters
    // xss-002: XSS via User-Agent / Referer headers
    private const PATTERNS = [
        // Script tags
        '/<\s*script\b[^>]*>/i',
        '/<\/\s*script\s*>/i',
        // Event handlers
        '/\bon\w+\s*=\s*["\']?\s*(?:javascript|vbscript|expression|\w+\s*\()/i',
        // javascript: URI
        '/javascript\s*:/i',
        '/vbscript\s*:/i',
        // eval() with encoded content
        '/eval\s*\(\s*(?:unescape|decodeuri|atob|String\.fromCharCode)/i',
        // Data URI with script
        '/data\s*:\s*(?:text\/html|text\/javascript|application\/javascript)/i',
        // SVG/embed script vectors
        '/<\s*(?:svg|object|embed|iframe|link|base|meta)\b[^>]*(?:on\w+|href\s*=\s*["\']?\s*javascript)/i',
        // DOM clobbering
        '/document\s*\.\s*(?:write|cookie|location|referrer)/i',
        // Expression() — IE legacy
        '/expression\s*\(/i',
        // HTML entities that decode to script chars (encoded attack)
        '/&#\s*(?:0*60|x0*3c)\s*;?\s*script/i',
    ];

    public function getId(): string {
        return 'xss-001';
    }

    public function getPriority(): int {
        return 15;
    }

    public function evaluate(Request $request): RuleResult {
        // xss-001: parameters
        $paramTargets = array_merge(
            $this->flattenValues($request->get),
            $this->flattenValues($request->post),
        );

        foreach ($paramTargets as $value) {
            if ($this->matchesAny(self::PATTERNS, $value)) {
                return $this->block('XSS attempt in request parameters', 'high');
            }
        }

        // xss-002: headers
        foreach ([$request->userAgent, $request->referer] as $header) {
            if ($this->matchesAny(self::PATTERNS, $header)) {
                return $this->block('XSS attempt in HTTP headers', 'medium');
            }
        }

        return RuleResult::pass();
    }
}
