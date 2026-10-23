<?php
declare(strict_types=1);

namespace DPXL\Shield\Firewall\Rules;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

use DPXL\Shield\Firewall\Request;
use DPXL\Shield\Firewall\RuleResult;

interface RuleInterface {

    /** Unique rule identifier, e.g. "sqli-001". */
    public function getId(): string;

    /** Lower number = higher priority (evaluated first). */
    public function getPriority(): int;

    /** Returns true when this rule should be evaluated for the given request. */
    public function isEnabled(): bool;

    public function evaluate(Request $request): RuleResult;
}
