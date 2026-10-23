<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Core;

use DPXL\Shield\Core\ClientIp;
use PHPUnit\Framework\TestCase;

/**
 * Locks the spoof-resistant client IP. A forwarding header is believed only
 * when the connection comes from a proxy that has a reason to set it; otherwise
 * a client could choose its own IP — dodging every lockout — or name someone
 * else's and get it banned.
 */
class ClientIpTest extends TestCase {

    public function testDirectConnectionIgnoresForgedHeaders(): void {
        $server = [
            'REMOTE_ADDR'           => '203.0.113.10',
            'HTTP_X_FORWARDED_FOR'  => '198.51.100.7',
            'HTTP_X_REAL_IP'        => '198.51.100.8',
            'HTTP_CF_CONNECTING_IP' => '198.51.100.9',
        ];

        $this->assertSame('203.0.113.10', ClientIp::resolve($server));
    }

    public function testCloudflareHeaderTrustedFromCloudflareEdge(): void {
        $server = ['REMOTE_ADDR' => '173.245.48.5', 'HTTP_CF_CONNECTING_IP' => '198.51.100.9'];

        $this->assertSame('198.51.100.9', ClientIp::resolve($server));
    }

    public function testCloudflareHeaderTrustedFromCloudflareIpv6Edge(): void {
        $server = ['REMOTE_ADDR' => '2606:4700:10::1', 'HTTP_CF_CONNECTING_IP' => '2001:db8::5'];

        $this->assertSame('2001:db8::5', ClientIp::resolve($server));
    }

    public function testForwardedForTrustedFromLocalProxy(): void {
        $server = ['REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_FORWARDED_FOR' => '198.51.100.7'];

        $this->assertSame('198.51.100.7', ClientIp::resolve($server));
    }

    /** The left-most entry is whatever the client sent; the proxy appends the real peer. */
    public function testForwardedForTakesRightMostUntrustedHop(): void {
        $server = ['REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => '1.2.3.4, 198.51.100.7'];

        $this->assertSame('198.51.100.7', ClientIp::resolve($server));
    }

    public function testConfiguredProxyIsTrusted(): void {
        $server = ['REMOTE_ADDR' => '192.0.2.50', 'HTTP_X_FORWARDED_FOR' => '198.51.100.7'];

        $this->assertSame('192.0.2.50', ClientIp::resolve($server));
        $this->assertSame('198.51.100.7', ClientIp::resolve($server, ['192.0.2.0/24']));
    }

    public function testInvalidRemoteAddr(): void {
        $this->assertSame('0.0.0.0', ClientIp::resolve(['REMOTE_ADDR' => 'nonsense']));
        $this->assertSame('0.0.0.0', ClientIp::resolve([]));
    }

    public function testRangeMatching(): void {
        $this->assertTrue(ClientIp::inRange('192.168.1.77', '192.168.1.0/24'));
        $this->assertFalse(ClientIp::inRange('192.168.2.1', '192.168.1.0/24'));
        $this->assertTrue(ClientIp::inRange('2001:db8::1', '2001:db8::/32'));
        $this->assertFalse(ClientIp::inRange('2001:db9::1', '2001:db8::/32'));
        $this->assertTrue(ClientIp::inRange('10.1.2.3', '10.1.2.3'));
        $this->assertFalse(ClientIp::inRange('10.1.2.3', '2001:db8::/32'));
        $this->assertFalse(ClientIp::inRange('10.1.2.3', '10.0.0.0/abc'));
    }
}
