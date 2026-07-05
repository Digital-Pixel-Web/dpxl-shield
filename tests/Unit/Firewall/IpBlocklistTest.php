<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Firewall;

use Brain\Monkey;
use Brain\Monkey\Functions;
use DPXL\Shield\Firewall\IpBlocklist;
use PHPUnit\Framework\TestCase;

/**
 * Tests for IpBlocklist — static API.
 *
 * Key v1.0.19 guard: blockIp() must return false (not crash) when $wpdb is
 * null, which happens when the Extended Protection WAF runs pre-WordPress.
 */
class IpBlocklistTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();

        Functions\stubs([
            'get_transient'    => false,
            'set_transient'    => true,
            'delete_transient' => true,
            'current_time'     => fn($type) => '2026-01-01 00:00:00',
        ]);
    }

    protected function tearDown(): void {
        // Reset in-process static cache between tests.
        $ref = new \ReflectionProperty(IpBlocklist::class, 'cache');
        $ref->setAccessible(true);
        $ref->setValue(null, null);

        Monkey\tearDown();
        parent::tearDown();
    }

    // ── blockIp() null-wpdb guard (v1.0.19 critical fix) ──────────────────

    /**
     * Pre-WordPress (Extended Protection) context: $wpdb is not set.
     * blockIp() must return false without throwing a fatal error.
     */
    public function testBlockIpReturnsFalseWhenWpdbIsNull(): void {
        global $wpdb;
        $wpdb = null;

        $result = IpBlocklist::blockIp('1.2.3.4', 'xss attempt', 'auto_waf', 3600);

        $this->assertFalse($result, 'blockIp() must return false, not crash, when $wpdb is null');
    }

    /**
     * Verify no TypeError / fatal is thrown — the test itself failing with an
     * exception would confirm the guard is missing.
     */
    public function testBlockIpDoesNotThrowWhenWpdbIsNull(): void {
        global $wpdb;
        $wpdb = null;

        $this->expectNotToPerformAssertions();

        IpBlocklist::blockIp('203.0.113.5', 'rate limit', 'auto_rate', 600);
    }

    // ── isBlocked() — cache injection ─────────────────────────────────────

    public function testExactIpBlockedViaCache(): void {
        $ref = new \ReflectionProperty(IpBlocklist::class, 'cache');
        $ref->setAccessible(true);
        $ref->setValue(null, ['exact' => ['10.0.0.1', '10.0.0.2'], 'cidr' => []]);

        $this->assertTrue(IpBlocklist::isBlocked('10.0.0.1'));
        $this->assertTrue(IpBlocklist::isBlocked('10.0.0.2'));
        $this->assertFalse(IpBlocklist::isBlocked('10.0.0.3'));
    }

    public function testUnknownIpNotBlocked(): void {
        $ref = new \ReflectionProperty(IpBlocklist::class, 'cache');
        $ref->setAccessible(true);
        $ref->setValue(null, ['exact' => [], 'cidr' => []]);

        $this->assertFalse(IpBlocklist::isBlocked('99.99.99.99'));
    }

    // ── CIDR matching ──────────────────────────────────────────────────────

    public function testCidrRangeMatchesViaCache(): void {
        $ref = new \ReflectionProperty(IpBlocklist::class, 'cache');
        $ref->setAccessible(true);
        $ref->setValue(null, ['exact' => [], 'cidr' => ['203.0.113.0/24']]);

        $this->assertTrue(IpBlocklist::isBlocked('203.0.113.55'));
        $this->assertFalse(IpBlocklist::isBlocked('203.0.112.55'));
    }

    public function testCidrEdgeCases(): void {
        $ref = new \ReflectionProperty(IpBlocklist::class, 'cache');
        $ref->setAccessible(true);
        $ref->setValue(null, ['exact' => [], 'cidr' => ['10.0.0.0/8']]);

        $this->assertTrue(IpBlocklist::isBlocked('10.255.255.1'));
        $this->assertFalse(IpBlocklist::isBlocked('11.0.0.1'));
    }

    // ── isBlocked() pre-WordPress (no $wpdb) ──────────────────────────────

    public function testIsBlockedDoesNotCrashWhenWpdbIsNull(): void {
        global $wpdb;
        $wpdb = null;

        // get_transient is stubbed to return false, so loadFromDatabase() runs.
        // loadFromDatabase() checks function_exists('get_transient') — it exists
        // (Brain\Monkey stubbed it), so it will try to use $wpdb. With our guard
        // this should not crash but return an empty list.
        $this->expectNotToPerformAssertions();

        IpBlocklist::isBlocked('1.1.1.1');
    }
}
