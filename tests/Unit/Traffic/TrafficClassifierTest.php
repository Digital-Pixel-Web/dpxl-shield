<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Traffic;

use DPXL\Shield\Traffic\TrafficClassifier;
use PHPUnit\Framework\TestCase;

/**
 * TrafficClassifier::classify(wafAction, userAgent, ip, statusCode) → type
 * where type ∈ {blocked, bot, suspicious, human, unknown}.
 * wafAction is the raw traffic-log value ('block' | 'log_only' | 'pass').
 */
class TrafficClassifierTest extends TestCase {

    private TrafficClassifier $classifier;

    protected function setUp(): void {
        parent::setUp();
        $this->classifier = new TrafficClassifier();
    }

    public function testBlockedActionClassifiedAsBlocked(): void {
        $this->assertSame('blocked', $this->classifier->classify('block', 'Mozilla/5.0', '1.2.3.4', 200));
    }

    public function testGooglebotClassifiedAsBot(): void {
        $ua = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
        $this->assertSame('bot', $this->classifier->classify('pass', $ua, '66.249.66.1', 200));
    }

    public function testCurlClassifiedAsBot(): void {
        $this->assertSame('bot', $this->classifier->classify('pass', 'curl/7.68.0', '10.0.0.1', 200));
    }

    public function testWgetClassifiedAsBot(): void {
        $this->assertSame('bot', $this->classifier->classify('pass', 'Wget/1.20.3', '192.0.2.1', 200));
    }

    public function testAhrefsClassifiedAsBot(): void {
        $ua = 'Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)';
        $this->assertSame('bot', $this->classifier->classify('pass', $ua, '54.36.148.1', 200));
    }

    public function testNormalBrowserClassifiedAsHuman(): void {
        $ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';
        $this->assertSame('human', $this->classifier->classify('pass', $ua, '203.0.113.5', 200));
    }

    /**
     * An empty User-Agent is suspicious, not a bot. Browsers and well-behaved
     * crawlers all identify themselves; omitting the header is anomalous, so it
     * must not be filed next to Googlebot.
     */
    public function testEmptyUserAgentClassifiedAsSuspicious(): void {
        $this->assertSame('suspicious', $this->classifier->classify('pass', '', '10.0.0.1', 200));
        $this->assertSame('suspicious', $this->classifier->classify('pass', '   ', '10.0.0.1', 200));
    }

    /** A missing UA must not set the is_bot flag either — it is not a crawler. */
    public function testEmptyUserAgentIsNotFlaggedAsBot(): void {
        $this->assertFalse($this->classifier->isBot(''));
        $this->assertTrue($this->classifier->isBot('curl/7.68.0'));
    }

    /** A blocked request stays 'blocked' even with no User-Agent. */
    public function testBlockedWinsOverEmptyUserAgent(): void {
        $this->assertSame('blocked', $this->classifier->classify('block', '', '10.0.0.1', 200));
    }

    public function test404ForNonBrowserClassifiedAsSuspicious(): void {
        // log_only OR status 403 → suspicious. A 404 with an unknown, non-bot
        // agent falls through to 'unknown'; a 403 is the suspicious trigger.
        $this->assertSame('suspicious', $this->classifier->classify('log_only', 'SomeAgent/1.0', '10.0.0.1', 200));
        $this->assertSame('suspicious', $this->classifier->classify('pass', 'SomeAgent/1.0', '10.0.0.1', 403));
    }
}
