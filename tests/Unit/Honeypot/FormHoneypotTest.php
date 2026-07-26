<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Honeypot;

use DPXL\Shield\Honeypot\FormHoneypot;
use PHPUnit\Framework\TestCase;

/**
 * The honeypot rule: an invisible field that only automated submitters fill.
 * A human never sees or completes it, so a non-empty value means a bot.
 */
class FormHoneypotTest extends TestCase {

    private const FIELD = 'dpxl_website_url';

    public function testFilledFieldTripsTheHoneypot(): void {
        $this->assertTrue(FormHoneypot::isTriggered([self::FIELD => 'http://spam.example']));
    }

    public function testEmptyFieldDoesNotTrip(): void {
        // A real human leaves the invisible field untouched (empty).
        $this->assertFalse(FormHoneypot::isTriggered([self::FIELD => '']));
    }

    public function testMissingFieldDoesNotTrip(): void {
        $this->assertFalse(FormHoneypot::isTriggered([]));
        $this->assertFalse(FormHoneypot::isTriggered(['some_other_field' => 'value']));
    }

    public function testWhitespaceOrZeroCountsAsFilled(): void {
        // Any non-empty string is a fill — bots often echo junk.
        $this->assertTrue(FormHoneypot::isTriggered([self::FIELD => '0']));
        $this->assertTrue(FormHoneypot::isTriggered([self::FIELD => ' ']));
    }
}
