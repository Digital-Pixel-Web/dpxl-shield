<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\LoginSecurity;

use DPXL\Shield\LoginSecurity\LoginAudit;
use PHPUnit\Framework\TestCase;

/**
 * Pins the "is this a new place?" comparison to the network, not the address.
 *
 * Residential IPv6 rotates its interface identifier every few hours, so
 * comparing whole addresses alerted on nearly every login from the same
 * router. If this regresses, the new-admin-IP alert turns back into noise.
 */
class LoginAuditNetworkIdTest extends TestCase {

    /**
     * Eight consecutive logins from one unchanged home connection, as recorded
     * on a live site. All eight must read as the same network.
     */
    public function testRotatingIpv6InterfaceIdsCollapseToOneNetwork(): void {
        $rotated = [
            '2804:d45:b005:1800:dcd6:a6ff:45ec:ac02',
            '2804:d45:b005:1800:2c8f:238b:800a:d0db',
            '2804:d45:b005:1800:1913:502b:1b16:7002',
            '2804:d45:b005:1800:482d:b6f1:bd96:ba48',
            '2804:d45:b005:1800:b9f1:fc31:6511:caf2',
            '2804:d45:b005:1800:28ee:6ae5:3879:9479',
            '2804:d45:b005:1800:5184:5822:9ac7:e662',
            '2804:d45:b005:1800:18cd:797a:40d4:d9cb',
        ];

        $networks = array_unique(array_map([LoginAudit::class, 'networkId'], $rotated));

        $this->assertCount(1, $networks);
        $this->assertSame('2804:d45:b005:1800::/64', reset($networks));
    }

    public function testDifferentPrefixIsADifferentNetwork(): void {
        $this->assertNotSame(
            LoginAudit::networkId('2804:d45:b005:1800:dcd6:a6ff:45ec:ac02'),
            LoginAudit::networkId('2804:d45:b005:1900:dcd6:a6ff:45ec:ac02')
        );
    }

    public function testIpv4IsComparedWhole(): void {
        $this->assertSame('203.0.113.45', LoginAudit::networkId('203.0.113.45'));
        $this->assertNotSame(
            LoginAudit::networkId('203.0.113.45'),
            LoginAudit::networkId('203.0.113.46')
        );
    }

    /**
     * ::ffff:x IPv4-mapped addresses are 16 bytes. Truncating them to /64 would
     * collapse every IPv4 client behind a proxy into one bucket and silence the
     * alert entirely.
     */
    public function testIpv4MappedAddressesAreNotTruncated(): void {
        $this->assertSame('::ffff:203.0.113.45', LoginAudit::networkId('::ffff:203.0.113.45'));
        $this->assertNotSame(
            LoginAudit::networkId('::ffff:203.0.113.45'),
            LoginAudit::networkId('::ffff:198.51.100.7')
        );
    }

    public function testUnparseableInputIsReturnedUnchanged(): void {
        $this->assertSame('0.0.0.0', LoginAudit::networkId('0.0.0.0'));
        $this->assertSame('not-an-ip', LoginAudit::networkId('not-an-ip'));
        $this->assertSame('', LoginAudit::networkId(''));
    }
}
