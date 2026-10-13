<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Alerts;

use DPXL\Shield\Alerts\EmailChannel;
use PHPUnit\Framework\TestCase;

/**
 * Detail rows are built by casting context values to string. `(string) []` is
 * the word "Array", so an alert carrying one entry per check rendered as
 * "Array, Array, Array" and told the reader nothing.
 */
class EmailChannelStringifyTest extends TestCase {

    /** @param mixed $value */
    private function stringify($value): string {
        $method = new \ReflectionMethod(EmailChannel::class, 'stringify');
        $method->setAccessible(true);

        return $method->invoke(null, $value);
    }

    public function testScalarsAreUnchanged(): void {
        $this->assertSame('plugin.php', $this->stringify('plugin.php'));
        $this->assertSame('42', $this->stringify(42));
    }

    public function testFlatListIsJoined(): void {
        $this->assertSame('a, b, c', $this->stringify(['a', 'b', 'c']));
    }

    /** The actual reputation-alert payload: never the literal "Array". */
    public function testNestedResultsRenderReadably(): void {
        $rendered = $this->stringify([
            'spamhaus_dbl' => ['listed' => false, 'detail' => 'Check unavailable'],
            'spamhaus_zen' => ['listed' => true, 'detail' => 'Listed in Spamhaus ZEN'],
        ]);

        $this->assertStringNotContainsString('Array', $rendered);
        $this->assertStringContainsString('spamhaus_dbl', $rendered);
        $this->assertStringContainsString('Check unavailable', $rendered);
        $this->assertStringContainsString('Listed in Spamhaus ZEN', $rendered);
    }

    public function testBooleansReadAsWords(): void {
        $this->assertSame('yes', $this->stringify(true));
        $this->assertSame('no', $this->stringify(false));
    }

    public function testAssociativeKeysArePreserved(): void {
        $this->assertSame('ip: 203.0.113.1', $this->stringify(['ip' => '203.0.113.1']));
    }
}
