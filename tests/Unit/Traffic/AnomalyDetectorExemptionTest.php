<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Traffic;

use Brain\Monkey;
use Brain\Monkey\Functions;
use DPXL\Shield\Traffic\AnomalyDetector;
use PHPUnit\Framework\TestCase;

/**
 * The behavioural detector blocks an IP for 30 minutes. On a live install it
 * locked the site's own administrator out six times, because working in
 * wp-admin crosses 50 unique URLs a minute without trying — every admin-ajax
 * call carries its own query string and counts as a distinct URL.
 *
 * Blocking the person who owns the site is a worse outcome than missing a
 * crawl by someone who can already install plugins.
 */
class AnomalyDetectorExemptionTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();
    }

    protected function tearDown(): void {
        Monkey\tearDown();
        parent::tearDown();
    }

    private function isExempt(): bool {
        $m = new \ReflectionMethod(AnomalyDetector::class, 'isExempt');
        $m->setAccessible(true);

        return (bool) $m->invoke(new AnomalyDetector());
    }

    public function testAdministratorIsExempt(): void {
        Functions\when('current_user_can')->alias(fn($cap) => $cap === 'manage_options');

        $this->assertTrue($this->isExempt());
    }

    public function testAnonymousVisitorIsNotExempt(): void {
        Functions\when('current_user_can')->justReturn(false);

        $this->assertFalse($this->isExempt());
    }

    /** A subscriber or customer is still subject to behavioural blocking. */
    public function testNonAdminLoggedInUserIsNotExempt(): void {
        Functions\when('current_user_can')->alias(fn($cap) => $cap === 'read');

        $this->assertFalse($this->isExempt());
    }
}
