<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Firewall;

use Brain\Monkey;
use Brain\Monkey\Functions;
use DPXL\Shield\Firewall\Decision;
use DPXL\Shield\Firewall\FirewallEngine;
use DPXL\Shield\Firewall\IpBlocklist;
use DPXL\Shield\Firewall\Request;
use PHPUnit\Framework\TestCase;

class FirewallEngineTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();

        // Simulate the pre-WordPress (Extended Protection) context: the WAF runs
        // via auto_prepend_file before WordPress finishes loading, so $wpdb is
        // null. WP functions may already be *defined* (Brain\Monkey can't
        // undefine them across tests), so every DB-backed blocker must be
        // null-$wpdb-safe — which the guards in IpBlocklist / CountryBlocker /
        // CustomPatternBlocker (v1.0.19) provide. Options read through get_option
        // return their defaults here.
        Functions\stubs([
            'get_option'          => fn($key, $default = false) => $default,
            'absint'              => fn($v) => abs((int) $v),
            'sanitize_text_field' => fn($v) => $v,
            'apply_filters'       => fn($tag, $value, ...$args) => $value,
            'get_transient'       => false,
            'set_transient'       => true,
            'delete_transient'    => true,
            'current_time'        => fn($type) => '2026-01-01 00:00:00',
        ]);

        global $wpdb;
        $wpdb = null;
    }

    protected function tearDown(): void {
        // Reset IpBlocklist in-process cache between tests.
        $ref = new \ReflectionProperty(IpBlocklist::class, 'cache');
        $ref->setAccessible(true);
        $ref->setValue(null, null);

        Monkey\tearDown();
        parent::tearDown();
    }

    private function makeEngine(): FirewallEngine {
        $configFile    = DPXL_SHIELD_PATH . 'data/early-config.php';
        $blockedIpsFile = DPXL_SHIELD_PATH . 'data/blocked-ips.php';
        return new FirewallEngine($configFile, $blockedIpsFile);
    }

    private function makeRequest(array $overrides = []): Request {
        $uri = $overrides['uri'] ?? '/';

        $_SERVER = array_merge([
            'REMOTE_ADDR'    => $overrides['ip'] ?? '1.2.3.4',
            'REQUEST_METHOD' => $overrides['method'] ?? 'GET',
            'REQUEST_URI'    => $uri,
            'HTTP_USER_AGENT' => $overrides['ua'] ?? 'Mozilla/5.0',
            'HTTP_HOST'      => 'example.com',
            'HTTPS'          => 'on',
        ], $overrides['server'] ?? []);

        // Populate $_GET / QUERY_STRING from the URI so rules that scan request
        // parameters (SQLi, XSS) see the payload — as a real web request would.
        $_GET = [];
        $_SERVER['QUERY_STRING'] = '';

        if (($pos = strpos($uri, '?')) !== false) {
            $query = substr($uri, $pos + 1);
            $_SERVER['QUERY_STRING'] = $query;
            parse_str($query, $_GET);
        }

        return new Request();
    }

    public function testCleanRequestPasses(): void {
        $engine  = $this->makeEngine();
        $request = $this->makeRequest(['ip' => '10.0.0.1', 'uri' => '/']);
        $result  = $engine->evaluate($request);

        $this->assertSame(Decision::PASS, $result->decision);
    }

    public function testSqlInjectionInUriBlocked(): void {
        $engine  = $this->makeEngine();
        $request = $this->makeRequest(['uri' => "/?id=1' UNION SELECT 1,2,3--"]);
        $result  = $engine->evaluate($request);

        $this->assertSame(Decision::BLOCK, $result->decision);
    }

    public function testXssInQueryStringBlocked(): void {
        $engine  = $this->makeEngine();
        $request = $this->makeRequest(['uri' => '/?s=<script>alert(1)</script>']);
        $result  = $engine->evaluate($request);

        $this->assertSame(Decision::BLOCK, $result->decision);
    }

    public function testPathTraversalBlocked(): void {
        $engine  = $this->makeEngine();
        $request = $this->makeRequest(['uri' => '/../../etc/passwd']);
        $result  = $engine->evaluate($request);

        $this->assertSame(Decision::BLOCK, $result->decision);
    }

    public function testAdminUriPassesWithoutCredentials(): void {
        $engine  = $this->makeEngine();
        $request = $this->makeRequest(['uri' => '/wp-admin/']);
        $result  = $engine->evaluate($request);

        // Admin URIs are not blocked by the WAF rules themselves (brute force is a separate module).
        $this->assertSame(Decision::PASS, $result->decision);
    }

    /**
     * v1.0.19 regression: when the rule engine blocks a request pre-WordPress
     * ($wpdb = null), IpBlocklist::blockIp() must not throw a fatal error.
     * The block decision must still be returned — only the auto-block write is skipped.
     */
    public function testXssBlockDoesNotCrashWhenWpdbIsNull(): void {
        // $wpdb = null is set in setUp() — simulates Extended Protection context.
        $engine  = $this->makeEngine();
        $request = $this->makeRequest(['uri' => '/?s=<script>alert(document.cookie)</script>']);
        $result  = $engine->evaluate($request);

        // The rule engine must still return BLOCK (WAF works).
        $this->assertSame(Decision::BLOCK, $result->decision);
    }
}
