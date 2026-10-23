<?php
declare(strict_types=1);

namespace DPXL\Shield\Firewall\Rules;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

use DPXL\Shield\Firewall\Request;
use DPXL\Shield\Firewall\RuleResult;

class RfiRule extends AbstractRule {

    // rfi-001: remote file inclusion
    private const PATTERNS = [
        // Parameter value that is a full external URL pointing to a PHP-capable resource
        '/(?:https?|ftp):\/\/[^\/]+\/.*(?:\.php|\.php\?|\.txt|=)/i',
        // IP-literal URLs (evades hostname checks)
        '/(?:https?):\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i',
        // Encoded schemes
        '/%68%74%74%70/i',  // http encoded
        // Common RFI tool markers
        '/RemoteFileInclusion/i',
        '/rfidemo/i',
    ];

    public function getId(): string {
        return 'rfi-001';
    }

    public function getPriority(): int {
        return 11;
    }

    public function evaluate(Request $request): RuleResult {
        $targets = array_merge(
            $this->flattenValues($request->get),
            $this->flattenValues($request->post),
        );

        foreach ($targets as $value) {
            if ($this->matchesAny(self::PATTERNS, $value)) {
                return $this->block('Remote File Inclusion attempt', 'high');
            }
        }

        return RuleResult::pass();
    }
}
