<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Firewall;

use Brain\Monkey;
use Brain\Monkey\Functions;
use DPXL\Shield\Firewall\FirewallEngine;
use DPXL\Shield\Firewall\Request;
use DPXL\Shield\Firewall\RuleDecision;
use PHPUnit\Framework\TestCase;

class FirewallEngineTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();

        // Stub WordPress functions used inside FirewallEngine / pipeline steps.
        Functions\stubs([
            'get_option'         => false,
            'absint'             => fn($v) => abs((int) $v),
            'sanitize_text_field' => fn($v) => $v,
            'apply_filters'      => fn($tag, $value, ...$args) => $value,
        ]);
    }

    protected function tearDown(): void {
        Monkey\tearDown();
        parent::tearDown();
    }

    private function makeEngine(): FirewallEngine {
        $configFile    = DPXL_SHIELD_PATH . 'data/early-config.php';
        $blockedIpsFile = DPXL_SHIELD_PATH . 'data/blocked-ips.php';
        return new FirewallEngine($configFile, $blockedIpsFile);
    }

    private function makeRequest(array $overrides = []): Request {
        $_SERVER = array_merge([
            'REMOTE_ADDR'    => $overrides['ip'] ?? '1.2.3.4',
            'REQUEST_METHOD' => $overrides['method'] ?? 'GET',
            'REQUEST_URI'    => $overrides['uri'] ?? '/',
            'HTTP_USER_AGENT' => $overrides['ua'] ?? 'Mozilla/5.0',
            'HTTP_HOST'      => 'example.com',
            'HTTPS'          => 'on',
        ], $overrides['server'] ?? []);
        return new Request();
    }

    public function testCleanRequestPasses(): void {
        $engine  = $this->makeEngine();
        $request = $this->makeRequest(['ip' => '10.0.0.1', 'uri' => '/']);
        $result  = $engine->evaluate($request);

        $this->assertSame(RuleDecision::PASS, $result->decision);
    }

    public function testSqlInjectionInUriBlocked(): void {
        $engine  = $this->makeEngine();
        $request = $this->makeRequest(['uri' => "/?id=1' UNION SELECT 1,2,3--"]);
        $result  = $engine->evaluate($request);

        $this->assertSame(RuleDecision::BLOCK, $result->decision);
    }

    public function testXssInQueryStringBlocked(): void {
        $engine  = $this->makeEngine();
        $request = $this->makeRequest(['uri' => '/?s=<script>alert(1)</script>']);
        $result  = $engine->evaluate($request);

        $this->assertSame(RuleDecision::BLOCK, $result->decision);
    }

    public function testPathTraversalBlocked(): void {
        $engine  = $this->makeEngine();
        $request = $this->makeRequest(['uri' => '/../../etc/passwd']);
        $result  = $engine->evaluate($request);

        $this->assertSame(RuleDecision::BLOCK, $result->decision);
    }

    public function testAdminUriPassesWithoutCredentials(): void {
        $engine  = $this->makeEngine();
        $request = $this->makeRequest(['uri' => '/wp-admin/']);
        $result  = $engine->evaluate($request);

        // Admin URIs are not blocked by the WAF rules themselves (brute force is a separate module).
        $this->assertSame(RuleDecision::PASS, $result->decision);
    }
}
