<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Firewall;

use Brain\Monkey;
use Brain\Monkey\Functions;
use DPXL\Shield\Bootstrap\Loader;
use DPXL\Shield\Firewall\Decision;
use DPXL\Shield\Firewall\EarlyBlockLog;
use DPXL\Shield\Firewall\FirewallEngine;
use DPXL\Shield\Firewall\IpBlocklist;
use DPXL\Shield\Firewall\Request;
use DPXL\Shield\Firewall\RuleResult;
use DPXL\Shield\Firewall\Rules\RfiRule;
use PHPUnit\Framework\TestCase;

/**
 * Regression for the 1.12.0 incident: an Elementor form submitted from a page
 * opened with UTM parameters was answered with 403 by rfi-001 before WordPress
 * loaded, left no trace in Live Traffic, and (inside WordPress) banned the
 * visitor for an hour. Runs the whole engine, every rule included.
 */
class RfiFalsePositiveRegressionTest extends TestCase {

    /** @var array<string,int> */
    private array $transients = [];

    private string $tmpDir = '';

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();

        $this->transients = [];
        $transients       = &$this->transients;

        Functions\stubs([
            'get_option'          => fn($key, $default = false) => $default,
            'absint'              => fn($v) => abs((int) $v),
            'sanitize_text_field' => fn($v) => $v,
            'apply_filters'       => fn($tag, $value, ...$args) => $value,
            'get_transient'       => function ($key) use (&$transients) { return $transients[$key] ?? false; },
            'set_transient'       => function ($key, $value) use (&$transients) { $transients[$key] = $value; return true; },
            'delete_transient'    => function ($key) use (&$transients) { unset($transients[$key]); return true; },
            'current_time'        => fn($type) => '2026-01-01 00:00:00',
        ]);

        global $wpdb;
        $wpdb = null;

        RfiRule::setSiteHosts([]);
    }

    protected function tearDown(): void {
        $ref = new \ReflectionProperty(IpBlocklist::class, 'cache');
        $ref->setAccessible(true);
        $ref->setValue(null, null);

        if ($this->tmpDir !== '') {
            array_map('unlink', glob($this->tmpDir . '/*') ?: []);
            @rmdir($this->tmpDir);
        }

        RfiRule::setSiteHosts([]);
        $_GET = $_POST = $_COOKIE = [];
        Monkey\tearDown();
        parent::tearDown();
    }

    private function engine(): FirewallEngine {
        return new FirewallEngine(DPXL_SHIELD_PATH . 'data/early-config.php', DPXL_SHIELD_PATH . 'data/blocked-ips.php');
    }

    /** @param array<string,mixed> $post */
    private function post(string $uri, array $post): Request {
        $_SERVER = [
            'REMOTE_ADDR'     => '198.51.100.20',
            'REQUEST_METHOD'  => 'POST',
            'REQUEST_URI'     => $uri,
            'QUERY_STRING'    => '',
            'HTTP_USER_AGENT' => 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)',
            'HTTP_HOST'       => 'exemplo.com.br',
            'HTTP_REFERER'    => 'https://exemplo.com.br/lp-fevereiro-2027/?utm_source=ig',
            'HTTPS'           => 'on',
        ];
        $_GET    = [];
        $_POST   = $post;
        $_COOKIE = [];

        return new Request();
    }

    /** What pro-elements/assets/js/form.*.bundle.js posts on every submit. */
    private function elementorSubmission(string $referrer): array {
        return [
            'post_id'       => '42',
            'form_id'       => '3f1a2b7',
            'referer_title' => 'LP Fevereiro 2027',
            'queried_id'    => '42',
            'form_fields'   => [
                'name'  => 'Maria Silva',
                'email' => 'maria@example.com',
                'phone' => '(31) 99999-0000',
            ],
            'action'   => 'elementor_pro_forms_send_form',
            'referrer' => $referrer,
        ];
    }

    public function testElementorFormWithUtmReferrerPasses(): void {
        $request = $this->post('/wp-admin/admin-ajax.php', $this->elementorSubmission(
            'https://exemplo.com.br/?utm_source=ig&utm_medium=paid_social&fbclid=abc'
        ));

        $result = $this->engine()->evaluate($request);

        $this->assertSame(Decision::PASS, $result->decision, $result->ruleId . ' ' . $result->reason);
    }

    public function testElementorFormFromFacebookLinkShimPasses(): void {
        $request = $this->post('/wp-admin/admin-ajax.php', $this->elementorSubmission(
            'https://l.facebook.com/l.php?u=https%3A%2F%2Fexemplo.com.br%2F%3Futm_source%3Dfb&h=AT0abc'
        ));

        $this->assertSame(Decision::PASS, $this->engine()->evaluate($request)->decision);
    }

    public function testElementorFormWithUtmPassesWithConfiguredHosts(): void {
        RfiRule::setSiteHosts(['https://exemplo.com.br']);

        $request = $this->post('/wp-admin/admin-ajax.php', $this->elementorSubmission(
            'https://exemplo.com.br/lp-fevereiro-2027/?utm_source=chatgpt.com'
        ));

        $this->assertSame(Decision::PASS, $this->engine()->evaluate($request)->decision);
    }

    public function testRemoteTxtShellStillBlocks(): void {
        $result = $this->engine()->evaluate($this->post('/', ['file' => 'http://evil.com/shell.txt']));

        $this->assertSame(Decision::BLOCK, $result->decision);
        $this->assertSame('rfi-001', $result->ruleId);
        $this->assertSame('file', $result->field);
    }

    public function testIpLiteralPhpStillBlocks(): void {
        $result = $this->engine()->evaluate($this->post('/', ['page' => 'http://1.2.3.4/x.php']));

        $this->assertSame(Decision::BLOCK, $result->decision);
        $this->assertSame('rfi-001', $result->ruleId);
        $this->assertSame('page', $result->field);
    }

    // ── Auto-ban ─────────────────────────────────────────────────────────────

    public function testOneHighSeverityBlockDoesNotBan(): void {
        $this->assertFalse(FirewallEngine::shouldAutoBan('198.51.100.20', RuleResult::block('rfi-001', 'x', 'high')));
    }

    public function testRepeatedBlocksBan(): void {
        $hit = RuleResult::block('rfi-001', 'x', 'high');

        $verdicts = [];

        for ($i = 0; $i < FirewallEngine::STRIKE_LIMIT; $i++) {
            $verdicts[] = FirewallEngine::shouldAutoBan('198.51.100.21', $hit);
        }

        $this->assertSame([false, false, true], $verdicts);
    }

    public function testCriticalBlockBansAtOnce(): void {
        $this->assertTrue(FirewallEngine::shouldAutoBan('198.51.100.22', RuleResult::block('generic-001', 'x', 'critical')));
    }

    // ── Pre-WordPress block log and 403 reference ───────────────────────────

    public function testEarlyBlocksAreRecordedWithRuleAndField(): void {
        $this->tmpDir = sys_get_temp_dir() . '/dpxl-early-' . bin2hex(random_bytes(4));
        mkdir($this->tmpDir);

        $request = $this->post('/lp/?x=<?php system(1); ?>', ['file' => 'http://evil.com/shell.txt']);
        $result  = RuleResult::block('rfi-001', 'Remote File Inclusion attempt', 'high', 'file');

        $this->assertTrue(EarlyBlockLog::record($this->tmpDir, $request, $result));
        $this->assertTrue(EarlyBlockLog::record($this->tmpDir, $request, $result));

        $path = $this->tmpDir . '/' . EarlyBlockLog::FILENAME;
        $raw  = (string) file_get_contents($path);

        $this->assertStringStartsWith('<?php exit; ?>', $raw);
        $this->assertSame(1, substr_count($raw, '<?'), 'request data must never produce a PHP open tag');

        $entries = EarlyBlockLog::readEntries($path);

        $this->assertCount(2, $entries);
        $this->assertSame('rfi-001', $entries[0]['rule']);
        $this->assertSame('file', $entries[0]['field']);
        $this->assertSame('/lp/?x=<?php system(1); ?>', $entries[0]['uri']);
        $this->assertSame('198.51.100.20', $entries[0]['ip']);
    }

    public function testRuleReferenceIsHeaderSafe(): void {
        $this->assertSame('rfi-001', Loader::ruleReference('rfi-001'));
        $this->assertSame('evilX-Injected1', Loader::ruleReference("evil\r\nX-Injected: 1"));
    }
}
