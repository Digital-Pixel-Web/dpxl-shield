<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Alerts;

use Brain\Monkey;
use Brain\Monkey\Functions;
use DPXL\Shield\Alerts\EmailChannel;
use PHPUnit\Framework\TestCase;

/**
 * The "quem / de onde" block.
 *
 * What started it: an alert showed
 * "Endereço IP: 2804:d45:b005:1800:dcd6:a6ff:45ec:ac02" and nothing else, and
 * the reader asked what that was. An address alone answers no question anyone
 * has — these tests pin the context that goes around it, and pin that building
 * it never reaches the network.
 */
class AlertIdentityTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();

        // No cached WHOIS for any address: the path the first alert from a new
        // address always takes.
        Functions\when('get_transient')->justReturn(false);
        Functions\when('get_option')->justReturn('');
    }

    protected function tearDown(): void {
        Monkey\tearDown();
        parent::tearDown();
    }

    /** @param mixed ...$args */
    private function invoke(string $method, ...$args) {
        $ref = new \ReflectionMethod(EmailChannel::class, $method);
        $ref->setAccessible(true);

        return $ref->isStatic()
            ? $ref->invokeArgs(null, $args)
            : $ref->invokeArgs(new EmailChannel(), $args);
    }

    /**
     * A rotating residential IPv6 is the case that produced the complaint. The
     * address changes every day; the /64 network is the thing the alert is
     * actually about, and is what the plugin compares against since 1.6.3.
     */
    public function testIpv6ReportsTheNetworkItBelongsTo(): void {
        $this->assertSame(
            'IPv6 · rede 2804:d45:b005:1800::/64',
            $this->invoke('describeAddress', '2804:d45:b005:1800:dcd6:a6ff:45ec:ac02')
        );
    }

    public function testIpv4IsLabelledPlainly(): void {
        $this->assertSame('IPv4', $this->invoke('describeAddress', '203.0.113.9'));
    }

    /**
     * An IPv4-mapped v6 address is IPv4 wearing a v6 hat; truncating it to /64
     * would collapse every such address into one bucket.
     */
    public function testIpv4MappedAddressIsNotTruncatedToANetwork(): void {
        $this->assertSame('IPv6', $this->invoke('describeAddress', '::ffff:203.0.113.9'));
    }

    /**
     * Unknown origin is reported as unknown, with the way to find out. A blank
     * row would read as "checked, nothing there".
     */
    public function testUnknownOriginSaysSoAndPointsAtTheTool(): void {
        $origin = $this->invoke('describeOrigin', '10.0.0.1');

        $this->assertSame('Não identificada', $origin['value']);
        $this->assertStringContainsString('Consulta Whois', $origin['note']);
    }

    /**
     * The organisation comes from the Whois tool's cache when it has one.
     *
     * Asserted across both lines of the row rather than on one of them: which
     * line carries the provider depends on whether GeoLite2 also resolved the
     * country, and the database is not in the repository, so it is present on a
     * developer's machine and absent in a clean checkout.
     */
    public function testCachedWhoisSuppliesTheProvider(): void {
        Functions\when('get_transient')->justReturn([
            'org' => 'Claro NXT Telecomunicacoes',
            'asn' => 'AS28573',
        ]);

        $origin = $this->invoke('describeOrigin', '203.0.113.9');
        $shown  = $origin['value'] . ' — ' . $origin['note'];

        $this->assertStringContainsString('Claro NXT Telecomunicacoes', $shown);
        $this->assertStringContainsString('AS28573', $shown);
        $this->assertStringNotContainsString('Não identificada', $origin['value']);
    }

    public function testIdentityRowsCoverAccountOriginAndAddress(): void {
        $rows = $this->invoke('buildIdentityRows', [
            'username' => 'digitalpixel',
            'ip'       => '2804:d45:b005:1800:dcd6:a6ff:45ec:ac02',
            'user_id'  => 1,
        ]);

        $labels = array_column($rows, 'label');

        $this->assertSame(['Conta', 'Origem', 'Endereço'], $labels);
        $this->assertSame('digitalpixel', $rows[0]['value']);
        $this->assertSame('ID 1', $rows[0]['note']);
    }

    /** An event with no actor (a scan finishing) gets no identity block. */
    public function testContextWithoutAnActorProducesNoRows(): void {
        $this->assertSame([], $this->invoke('buildIdentityRows', ['scan_id' => 'abc-123']));
    }

    /** A malformed address is dropped rather than decorated with guesses. */
    public function testInvalidAddressIsIgnored(): void {
        $rows = $this->invoke('buildIdentityRows', ['username' => 'admin', 'ip' => 'not-an-ip']);

        $this->assertSame(['Conta'], array_column($rows, 'label'));
    }

    /**
     * Severity stays out of the subject for routine events, so the inbox list
     * does not shout. `critical` is the one exception, and only holds while
     * critical stays rare.
     */
    public function testOnlyCriticalShoutsInTheSubject(): void {
        Functions\when('get_option')->justReturn('Digital Pixel');

        $this->assertSame(
            '[DPXL Shield] Login de administrador de um endereço novo — Digital Pixel',
            $this->invoke('buildSubject', 'medium', 'new_admin_ip_login')
        );

        $this->assertSame(
            '[DPXL Shield · CRÍTICO] Os arquivos do DPXL Shield foram alterados — Digital Pixel',
            $this->invoke('buildSubject', 'critical', 'plugin_tampered')
        );
    }

    /**
     * The dispatcher's English description is not thrown away — it moves to the
     * technical block, under the part a human reads.
     */
    public function testTechnicalRowsKeepTheRawRecord(): void {
        Functions\when('wp_date')->justReturn('13/10/2026 13:23');

        $rows = $this->invoke(
            'buildDetailRows',
            'new_admin_ip_login',
            "Admin 'digitalpixel' logged in from a new IP: 2804:d45::1",
            ['username' => 'digitalpixel', 'ip' => '2804:d45::1']
        );

        $this->assertArrayHasKey('Quando', $rows);
        $this->assertArrayHasKey('Endereço IP', $rows);
        $this->assertSame('new_admin_ip_login', $rows['Evento']);
        $this->assertStringContainsString('logged in from a new IP', $rows['Detalhe do evento']);
    }
}
