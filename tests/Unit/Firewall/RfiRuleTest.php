<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Firewall;

use DPXL\Shield\Firewall\Decision;
use DPXL\Shield\Firewall\Request;
use DPXL\Shield\Firewall\Rules\RfiRule;
use PHPUnit\Framework\TestCase;

/**
 * rfi-001 must catch remote file inclusion without catching ordinary URLs.
 *
 * The old pattern matched any URL with an "=" in it, in any field. Every
 * Elementor form posts `referrer` = the page address, so visitors arriving
 * from ads (?utm_source=…) got a 403 on submit, for a month, on a real site.
 */
class RfiRuleTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        RfiRule::setSiteHosts(['https://www.exemplo.com.br']);
    }

    protected function tearDown(): void {
        RfiRule::setSiteHosts([]);
        $_GET = $_POST = $_COOKIE = $_SERVER = [];
        parent::tearDown();
    }

    /** @param array<string,mixed> $get @param array<string,mixed> $post */
    private function request(array $get = [], array $post = [], string $host = 'exemplo.com.br'): Request {
        $_GET    = $get;
        $_POST   = $post;
        $_COOKIE = [];
        $_SERVER = [
            'REMOTE_ADDR'    => '1.2.3.4',
            'REQUEST_METHOD' => $post !== [] ? 'POST' : 'GET',
            'REQUEST_URI'    => '/',
            'HTTP_HOST'      => $host,
        ];

        return new Request();
    }

    /** @return array<string,array{0:array<string,mixed>}> */
    public function legitimateProvider(): array {
        return [
            'elementor referrer with UTM'         => [['referrer' => 'https://exemplo.com.br/lp-fevereiro-2027/?utm_source=ig&utm_medium=paid_social&fbclid=abc']],
            'own domain, www and port'            => [['page' => 'https://www.exemplo.com.br:443/contato/?a=1']],
            'own subdomain'                       => [['back' => 'https://lp.exemplo.com.br/x.php']],
            'facebook link shim in referrer'      => [['referrer' => 'https://l.facebook.com/l.php?u=https%3A%2F%2Fexemplo.com.br%2F&h=AT0']],
            'facebook link shim in custom field'  => [['form_fields' => ['origem' => 'https://l.facebook.com/l.php?u=https%3A%2F%2Fexemplo.com.br%2F&h=AT0']]],
            'google redirect in custom field'     => [['origem' => 'https://www.google.com/url?q=https://exemplo.com.br/&sa=D']],
            'foreign page with query'             => [['origem' => 'https://chatgpt.com/?utm_source=chatgpt.com']],
            'foreign php page with query'         => [['origem' => 'https://parceiro.com/pagina.php?id=10']],
            'redirect_to on another domain'       => [['redirect_to' => 'https://checkout.hotmart.com/pay.php']],
            'wp referer field'                    => [['_wp_http_referer' => '/contato/?utm_campaign=x']],
            'link inside a message'               => [['mensagem' => 'Vi no site https://outro.com/shell.txt e gostei']],
            'plain text'                          => [['nome' => 'Maria', 'email' => 'maria@example.com']],
            'image data URI in a signature field' => [['assinatura' => 'data:image/png;base64,iVBORw0KGgo=']],
        ];
    }

    /**
     * @dataProvider legitimateProvider
     * @param array<string,mixed> $post
     */
    public function testLegitimateValuesPass(array $post): void {
        $result = (new RfiRule())->evaluate($this->request([], $post));

        $this->assertSame(Decision::PASS, $result->decision, $result->reason);
    }

    /** @return array<string,array{0:array<string,mixed>,1:string}> */
    public function attackProvider(): array {
        return [
            'remote txt shell'             => [['file' => 'http://evil.com/shell.txt'], 'file'],
            'remote txt shell with ?'      => [['file' => 'http://evil.com/shell.txt?'], 'file'],
            'IP-literal php'               => [['page' => 'http://1.2.3.4/x.php'], 'page'],
            'IP-literal in referrer'       => [['referrer' => 'http://203.0.113.9/'], 'referrer'],
            'bare remote php'              => [['inc' => 'https://evil.com/c99.php'], 'inc'],
            'trailing ? truncation'        => [['template' => 'http://evil.com/shell?'], 'template'],
            'null byte truncation'         => [['template' => 'http://evil.com/shell%00'], 'template'],
            'ftp include'                  => [['mod' => 'ftp://evil.com/payload'], 'mod'],
            'user-info host trick'         => [['page' => 'http://exemplo.com.br@evil.com/shell.txt'], 'page'],
            'nested parameter'             => [['cfg' => ['path' => 'http://evil.com/inc.inc']], 'path'],
            'double-encoded scheme'        => [['p' => '%68%74%74%70://evil.com/'], 'p'],
            'leading whitespace'           => [['file' => "  http://evil.com/shell.txt"], 'file'],
        ];
    }

    /**
     * @dataProvider attackProvider
     * @param array<string,mixed> $get
     */
    public function testAttacksBlockAndNameTheField(array $get, string $field): void {
        $result = (new RfiRule())->evaluate($this->request($get));

        $this->assertSame(Decision::BLOCK, $result->decision);
        $this->assertSame('rfi-001', $result->ruleId);
        $this->assertSame($field, $result->field);
    }

    public function testAttacksAlsoBlockInPost(): void {
        $result = (new RfiRule())->evaluate($this->request([], ['file' => 'http://evil.com/shell.txt']));

        $this->assertSame(Decision::BLOCK, $result->decision);
    }

    public function testFallsBackToHostHeaderWithoutConfiguredHosts(): void {
        RfiRule::setSiteHosts([]);

        $ok = (new RfiRule())->evaluate($this->request(['page' => 'https://meusite.com/a.php'], [], 'meusite.com'));
        $ko = (new RfiRule())->evaluate($this->request(['page' => 'https://outro.com/a.php'], [], 'meusite.com'));

        $this->assertSame(Decision::PASS, $ok->decision);
        $this->assertSame(Decision::BLOCK, $ko->decision);
    }

    public function testConfiguredHostsWinOverAForgedHostHeader(): void {
        // Host: evil.com must not make evil.com "the site".
        $result = (new RfiRule())->evaluate($this->request(['file' => 'http://evil.com/shell.txt'], [], 'evil.com'));

        $this->assertSame(Decision::BLOCK, $result->decision);
    }

    public function testSiteHostsAreNormalised(): void {
        RfiRule::setSiteHosts(['https://WWW.Exemplo.com.br:8443/', 'exemplo.com.br', '']);

        $this->assertSame(['exemplo.com.br'], RfiRule::getSiteHosts());
    }
}
