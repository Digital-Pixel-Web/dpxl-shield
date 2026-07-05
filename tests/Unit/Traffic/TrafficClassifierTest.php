<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Traffic;

use Brain\Monkey;
use DPXL\Shield\Traffic\TrafficClassifier;
use DPXL\Shield\Firewall\RuleDecision;
use PHPUnit\Framework\TestCase;

class TrafficClassifierTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();
    }

    protected function tearDown(): void {
        Monkey\tearDown();
        parent::tearDown();
    }

    public function testBlockedDecisionClassifiedAsBlocked(): void {
        $type = TrafficClassifier::classify(RuleDecision::BLOCK, 'Mozilla/5.0', '1.2.3.4', 200);

        $this->assertSame('blocked', $type);
    }

    public function testGooglebotClassifiedAsBot(): void {
        $type = TrafficClassifier::classify(
            RuleDecision::PASS,
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            '66.249.66.1',
            200
        );

        $this->assertSame('bot', $type);
    }

    public function testCurlClassifiedAsBot(): void {
        $type = TrafficClassifier::classify(RuleDecision::PASS, 'curl/7.68.0', '10.0.0.1', 200);

        $this->assertSame('bot', $type);
    }

    public function testNormalBrowserClassifiedAsHuman(): void {
        $type = TrafficClassifier::classify(
            RuleDecision::PASS,
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            '203.0.113.5',
            200
        );

        $this->assertSame('human', $type);
    }

    public function testEmptyUserAgentClassifiedAsSuspicious(): void {
        $type = TrafficClassifier::classify(RuleDecision::PASS, '', '10.0.0.1', 200);

        $this->assertSame('suspicious', $type);
    }

    public function test404ResponseClassifiedAsSuspicious(): void {
        $type = TrafficClassifier::classify(
            RuleDecision::PASS,
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            '10.0.0.1',
            404
        );

        $this->assertSame('suspicious', $type);
    }

    public function testWgetClassifiedAsBot(): void {
        $type = TrafficClassifier::classify(RuleDecision::PASS, 'Wget/1.20.3', '192.0.2.1', 200);

        $this->assertSame('bot', $type);
    }

    public function testAhrefsClassifiedAsBot(): void {
        $type = TrafficClassifier::classify(
            RuleDecision::PASS,
            'Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)',
            '54.36.148.1',
            200
        );

        $this->assertSame('bot', $type);
    }
}
