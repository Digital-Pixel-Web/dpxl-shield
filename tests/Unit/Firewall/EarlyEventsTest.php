<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Firewall;

use DPXL\Shield\Firewall\EarlyEvents;
use DPXL\Shield\Firewall\Request;
use PHPUnit\Framework\TestCase;

/**
 * Extended Protection queues its bans and blocks for WordPress to store.
 */
class EarlyEventsTest extends TestCase {

    protected function setUp(): void {
        @unlink(EarlyEvents::path());
    }

    protected function tearDown(): void {
        @unlink(EarlyEvents::path());
    }

    public function testBanAndBlockRoundTrip(): void {
        $_SERVER = ['REQUEST_URI' => '/?id=1%27%20or%201=1', 'REQUEST_METHOD' => 'GET', 'REMOTE_ADDR' => '203.0.113.7', 'HTTP_USER_AGENT' => 'sqlmap'];
        $_GET = $_POST = $_COOKIE = [];

        EarlyEvents::queueBan('203.0.113.7', 'SQL injection', 'auto_waf', 3600);
        EarlyEvents::queueBlock(new Request(), 'sqli-001');

        $events = EarlyEvents::drain();

        $this->assertCount(2, $events);
        $this->assertSame('ban', $events[0]['kind']);
        $this->assertSame(3600, $events[0]['duration']);
        $this->assertSame('block', $events[1]['kind']);
        $this->assertSame('sqli-001', $events[1]['rule']);
        $this->assertSame('sqlmap', $events[1]['ua']);

        // Drained events are gone.
        $this->assertSame([], EarlyEvents::drain());
    }

    public function testFileIsNotServedAsData(): void {
        EarlyEvents::queueBan('203.0.113.8', 'x', 'auto_rate', 600);

        $this->assertStringStartsWith('<?php exit; ?>', (string) file_get_contents(EarlyEvents::path()));
    }

    public function testInvalidLinesAreIgnored(): void {
        EarlyEvents::queueBan('203.0.113.9', 'x', 'auto_rate', 600);
        file_put_contents(EarlyEvents::path(), "{\"kind\":\"ban\",\"ip\":\"not-an-ip\"}\ngarbage\n", FILE_APPEND);

        $events = EarlyEvents::drain();

        $this->assertCount(1, $events);
        $this->assertSame('203.0.113.9', $events[0]['ip']);
    }

    public function testLongFieldsAreTruncated(): void {
        EarlyEvents::queueBan('203.0.113.10', str_repeat('a', 5000), 'auto_waf', 3600);

        $this->assertSame(500, strlen(EarlyEvents::drain()[0]['reason']));
    }
}
