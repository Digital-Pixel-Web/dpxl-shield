<?php
declare(strict_types=1);

namespace DPXL\Shield\Integrations;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

/**
 * An alert on its way out to a webhook.
 *
 * The dispatcher queues these during the request and delivers them on shutdown,
 * so the data has to survive past the point where the alert was raised — hence
 * a value object rather than four loose arguments.
 */
final class Event {

    /** @var string */
    private $level;

    /** @var string */
    private $type;

    /** @var string */
    private $description;

    /** @var array<string,mixed> */
    private $context;

    /** @var int */
    private $timestamp;

    /**
     * @param array<string,mixed> $context
     */
    public function __construct(
        string $level,
        string $type,
        string $description,
        array $context = [],
        ?int $timestamp = null
    ) {
        $this->level       = Severity::isValid($level) ? $level : Severity::INFO;
        $this->type        = $type;
        $this->description = $description;
        $this->context     = $context;
        $this->timestamp   = $timestamp !== null ? $timestamp : time();
    }

    public function level(): string {
        return $this->level;
    }

    public function type(): string {
        return $this->type;
    }

    public function description(): string {
        return $this->description;
    }

    /** @return array<string,mixed> */
    public function context(): array {
        return $this->context;
    }

    public function timestamp(): int {
        return $this->timestamp;
    }
}
