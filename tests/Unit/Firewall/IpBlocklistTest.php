<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Firewall;

use Brain\Monkey;
use Brain\Monkey\Functions;
use DPXL\Shield\Firewall\IpBlocklist;
use PHPUnit\Framework\TestCase;

class IpBlocklistTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();

        Functions\stubs([
            'get_option'          => fn($key, $default = false) => $default,
            'update_option'       => true,
            'current_time'        => fn($type) => $type === 'timestamp' ? time() : date('Y-m-d H:i:s'),
            'sanitize_text_field' => fn($v) => $v,
            'absint'              => fn($v) => abs((int) $v),
        ]);
    }

    protected function tearDown(): void {
        Monkey\tearDown();
        parent::tearDown();
    }

    public function testExactIpIsBlocked(): void {
        $blocklist = new IpBlocklist();
        $blocklist->blockIp('192.168.1.100', 3600, 'test');

        $this->assertTrue($blocklist->isBlocked('192.168.1.100'));
    }

    public function testUnknownIpIsNotBlocked(): void {
        $blocklist = new IpBlocklist();

        $this->assertFalse($blocklist->isBlocked('10.0.0.1'));
    }

    public function testCidrRangeMatches(): void {
        $blocklist = new IpBlocklist();
        $blocklist->blockRange('203.0.113.0/24', 3600, 'test');

        $this->assertTrue($blocklist->isBlocked('203.0.113.55'));
        $this->assertFalse($blocklist->isBlocked('203.0.112.55'));
    }

    public function testIpv6ExactMatch(): void {
        $blocklist = new IpBlocklist();
        $blocklist->blockIp('2001:db8::1', 3600, 'test');

        $this->assertTrue($blocklist->isBlocked('2001:db8::1'));
        $this->assertFalse($blocklist->isBlocked('2001:db8::2'));
    }

    public function testUnblockRemovesEntry(): void {
        $blocklist = new IpBlocklist();
        $blocklist->blockIp('1.2.3.4', 3600, 'test');
        $this->assertTrue($blocklist->isBlocked('1.2.3.4'));

        $blocklist->unblock('1.2.3.4');
        $this->assertFalse($blocklist->isBlocked('1.2.3.4'));
    }

    public function testLocalhostIsNeverBlocked(): void {
        $blocklist = new IpBlocklist();
        // Even if someone tries to block 127.0.0.1, it should be ignored.
        $blocklist->blockIp('127.0.0.1', 3600, 'test');

        $this->assertFalse($blocklist->isBlocked('127.0.0.1'));
    }
}
