<?php
declare(strict_types=1);

namespace DPXL\Shield\Firewall\Rules;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

use DPXL\Shield\Firewall\Request;
use DPXL\Shield\Firewall\RuleResult;

/**
 * A data-driven WAF rule loaded from the threat feed (data/waf-rules.active.json).
 *
 * Built-in PHP rules are the immutable protection floor; feed rules only ever
 * *add* coverage on top. To keep that guarantee, feed rules are **block-only**:
 * the engine stops on the first non-PASS decision, so allowing a feed rule to
 * emit LOG_ONLY / CHALLENGE could let a high-priority feed match short-circuit a
 * built-in BLOCK. Restricting the feed to `block` means the worst a bad/hostile
 * feed can do is add blocks (a false positive), never weaken the baseline.
 *
 * Instances are only ever created by {@see RuleRepository}, which validates the
 * regex and the shape before constructing — so evaluate() can trust its data.
 */
class JsonRule extends AbstractRule {

    /** Recognised targets → how the value(s) are pulled from the Request. */
    public const TARGETS = ['get', 'post', 'cookie', 'body', 'user_agent', 'referer', 'uri', 'query'];

    /** @var string */
    private $id;

    /** @var int */
    private $priority;

    /** @var list<string> */
    private $targets;

    /** @var string */
    private $pattern;

    /** @var string */
    private $severity;

    /**
     * @param list<string> $targets Lower-case entries from {@see self::TARGETS}.
     */
    public function __construct(
        string $id,
        int $priority,
        array $targets,
        string $pattern,
        string $severity,
        bool $enabled = true
    ) {
        $this->id       = $id;
        $this->priority = $priority;
        $this->targets  = $targets;
        $this->pattern  = $pattern;
        $this->severity = $severity;
        $this->enabled  = $enabled;
    }

    public function getId(): string {
        return $this->id;
    }

    public function getPriority(): int {
        return $this->priority;
    }

    public function evaluate(Request $request): RuleResult {
        foreach ($this->collectValues($request) as $value) {
            if ($this->matchesPattern($this->pattern, $value)) {
                return $this->block('WAF feed rule matched: ' . $this->id, $this->severity);
            }
        }

        return RuleResult::pass();
    }

    /**
     * Flattens the request values for this rule's declared targets.
     *
     * @return list<string>
     */
    private function collectValues(Request $request): array {
        $values = [];

        foreach ($this->targets as $target) {
            switch ($target) {
                case 'get':
                    $values = array_merge($values, $this->flattenValues($request->get));
                    break;
                case 'post':
                    $values = array_merge($values, $this->flattenValues($request->post));
                    break;
                case 'cookie':
                    $values = array_merge($values, $this->flattenValues($request->cookies));
                    break;
                case 'body':
                    $values[] = $request->rawBody;
                    break;
                case 'user_agent':
                    $values[] = $request->userAgent;
                    break;
                case 'referer':
                    $values[] = $request->referer;
                    break;
                case 'uri':
                    $values[] = $request->uri;
                    break;
                case 'query':
                    $values[] = $request->queryString;
                    break;
            }
        }

        return $values;
    }
}
