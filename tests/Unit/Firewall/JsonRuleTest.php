<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Firewall;

use DPXL\Shield\Firewall\Decision;
use DPXL\Shield\Firewall\Request;
use DPXL\Shield\Firewall\Rules\JsonRule;
use PHPUnit\Framework\TestCase;

/**
 * Data-driven feed rule. Locks two things: it matches its pattern only against
 * the targets it declares (so a rule scoped to GET never inspects POST), and a
 * match always yields a BLOCK — feed rules are block-only by design so they can
 * never short-circuit a built-in block with a softer decision.
 */
class JsonRuleTest extends TestCase {

    protected function tearDown(): void {
        $_GET = $_POST = $_COOKIE = $_SERVER = [];
        parent::tearDown();
    }

    /** @param array<string,mixed> $parts */
    private function request(array $parts): Request {
        $_GET    = $parts['get']    ?? [];
        $_POST   = $parts['post']   ?? [];
        $_COOKIE = $parts['cookie'] ?? [];
        $_SERVER = [
            'REMOTE_ADDR'     => '1.2.3.4',
            'REQUEST_METHOD'  => 'GET',
            'REQUEST_URI'     => $parts['uri'] ?? '/',
            'QUERY_STRING'    => $parts['query'] ?? '',
            'HTTP_USER_AGENT' => $parts['ua'] ?? '',
            'HTTP_REFERER'    => $parts['referer'] ?? '',
            'HTTP_HOST'       => 'example.com',
        ];

        return new Request();
    }

    public function testMatchInDeclaredTargetBlocks(): void {
        $rule = new JsonRule('feed-sqli-1', 10, ['get'], '/union\s+select/i', 'high');

        $result = $rule->evaluate($this->request(['get' => ['q' => 'a UNION SELECT b']]));

        $this->assertSame(Decision::BLOCK, $result->decision);
        $this->assertSame('feed-sqli-1', $result->ruleId);
        $this->assertSame('high', $result->severity);
    }

    public function testCleanRequestPasses(): void {
        $rule = new JsonRule('feed-sqli-1', 10, ['get'], '/union\s+select/i', 'high');

        $result = $rule->evaluate($this->request(['get' => ['q' => 'hello world']]));

        $this->assertSame(Decision::PASS, $result->decision);
    }

    public function testOnlyInspectsDeclaredTargets(): void {
        // Rule scoped to GET must ignore an identical payload arriving via POST.
        $rule = new JsonRule('feed-sqli-1', 10, ['get'], '/union\s+select/i', 'high');

        $result = $rule->evaluate($this->request(['post' => ['q' => 'a UNION SELECT b']]));

        $this->assertSame(Decision::PASS, $result->decision);
    }

    public function testUserAgentAndRefererTargets(): void {
        $rule = new JsonRule('feed-bot-1', 20, ['user_agent', 'referer'], '/sqlmap/i', 'medium');

        $this->assertSame(Decision::BLOCK, $rule->evaluate($this->request(['ua' => 'sqlmap/1.0']))->decision);
        $this->assertSame(Decision::BLOCK, $rule->evaluate($this->request(['referer' => 'http://sqlmap.test']))->decision);
        $this->assertSame(Decision::PASS,  $rule->evaluate($this->request(['ua' => 'Mozilla/5.0']))->decision);
    }

    public function testEnabledFlagIsHonoured(): void {
        $on  = new JsonRule('feed-x', 30, ['get'], '/x/', 'low', true);
        $off = new JsonRule('feed-x', 30, ['get'], '/x/', 'low', false);

        $this->assertTrue($on->isEnabled());
        $this->assertFalse($off->isEnabled());
    }
}
