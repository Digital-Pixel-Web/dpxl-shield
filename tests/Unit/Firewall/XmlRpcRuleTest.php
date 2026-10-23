<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Firewall;

use DPXL\Shield\Firewall\Request;
use DPXL\Shield\Firewall\Rules\WordPressRule;
use PHPUnit\Framework\TestCase;

/**
 * XML-RPC is blocked only for system.multicall (hundreds of guesses in one
 * request). Blocking every POST broke Jetpack, the mobile apps and pingbacks.
 */
class XmlRpcRuleTest extends TestCase {

    private function request(string $uri, string $method): Request {
        $_SERVER = ['REQUEST_URI' => $uri, 'REQUEST_METHOD' => $method, 'REMOTE_ADDR' => '203.0.113.5'];
        $_GET = $_POST = $_COOKIE = [];

        return new Request();
    }

    public function testMulticallIsBlocked(): void {
        $request = $this->request('/xmlrpc.php', 'POST');
        $request->rawBody = '<methodCall><methodName>system.multicall</methodName></methodCall>';

        $this->assertSame('block', (new WordPressRule())->evaluate($request)->decision);
    }

    public function testOrdinaryCallPasses(): void {
        $request = $this->request('/xmlrpc.php', 'POST');
        $request->rawBody = '<methodCall><methodName>wp.getUsersBlogs</methodName></methodCall>';

        $this->assertSame('pass', (new WordPressRule())->evaluate($request)->decision);
    }

    public function testQueryStringMentionDoesNotCount(): void {
        $request = $this->request('/?x=xmlrpc.php', 'POST');
        $request->rawBody = 'system.multicall';

        $this->assertSame('pass', (new WordPressRule())->evaluate($request)->decision);
    }
}
