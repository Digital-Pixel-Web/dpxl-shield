<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Alerts;

use Brain\Monkey;
use Brain\Monkey\Functions;
use DPXL\Shield\Alerts\PdfReport;
use PHPUnit\Framework\TestCase;

/**
 * The branded PDF report. These lock two things: the HTML carries the real
 * figures and brand marks, and Dompdf turns that HTML into an actual PDF
 * document (the magic-byte header). If Dompdf or a WordPress seam breaks, the
 * scheduled email would ship a corrupt or empty attachment.
 */
class PdfReportTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();

        Functions\stubs([
            '__'                 => fn($t, $d = null) => $t,
            'esc_html'           => fn($t) => htmlspecialchars((string) $t, ENT_QUOTES),
            'esc_html__'         => fn($t, $d = null) => htmlspecialchars((string) $t, ENT_QUOTES),
            '_n'                 => fn($s, $p, $n, $d = null) => (int) $n === 1 ? $s : $p,
            'number_format_i18n' => fn($n) => number_format((float) $n),
            'get_option'         => fn($k, $def = false) => [
                'blogname'    => 'EABH',
                'siteurl'     => 'https://eabh.com.br',
                'date_format' => 'd/m/Y',
                'time_format' => 'H:i',
            ][$k] ?? $def,
            'wp_parse_url'       => fn($url, $c = -1) => parse_url((string) $url, $c),
            'wp_date'            => fn($fmt, $ts = null) => gmdate($fmt, $ts ?? time()),
            'sanitize_file_name' => fn($n) => preg_replace('/[^A-Za-z0-9._-]/', '-', (string) $n),
            'trailingslashit'    => fn($p) => rtrim((string) $p, '/\\') . '/',
            'get_temp_dir'       => fn() => rtrim(sys_get_temp_dir(), '/') . '/',
        ]);
    }

    protected function tearDown(): void {
        Monkey\tearDown();
        parent::tearDown();
    }

    /** @return array<string,mixed> */
    private function sampleData(int $criticals = 0): array {
        return [
            'freq'           => 'weekly',
            'since'          => date('Y-m-d H:i:s', strtotime('-7 days')),
            'attacksBlocked' => 1234,
            'topIps'         => [['ip' => '203.0.113.7', 'hits' => 12]],
            'loginSuccess'   => 5,
            'loginFailed'    => 3,
            'scanIssues'     => 2,
            'criticalIssues' => $criticals,
            'updatesNeeded'  => 2,
            'vulnComponents' => [['file_path' => 'wp-content/plugins/foo/foo.php', 'details' => 'Foo Plugin 1.2 → 1.3 available', 'severity' => 'medium']],
            'topCountries'   => [['country' => 'RU', 'hits' => 40], ['country' => 'CN', 'hits' => 22]],
            'topFailedUsers' => [['user_login' => 'admin', 'hits' => 15]],
            'recentAttacks'  => [['timestamp' => '2026-07-27 10:00:00', 'ip' => '198.51.100.9', 'waf_rule_id' => 'sqli-001']],
            'modifiedFiles'  => [['file_path' => 'wp-includes/functions.php', 'scanned_at' => '2026-07-27 09:00:00', 'issue_type' => 'modified_core']],
        ];
    }

    public function testHtmlCarriesBrandAndFigures(): void {
        $html = (new PdfReport())->buildHtml($this->sampleData());

        $this->assertStringContainsString('DPXL', $html);
        $this->assertStringContainsString('SHIELD', $html);
        $this->assertStringContainsString('eabh.com.br', $html, 'Site host must appear in the header');
        $this->assertStringContainsString('1,234', $html, 'Attacks-blocked figure must be formatted and present');
        $this->assertStringContainsString('203.0.113.7', $html, 'Top blocked IP must be listed');
        $this->assertStringContainsString('#F68B00', $html, 'Digital Pixel orange must drive the brand accent');
    }

    public function testEnrichedSectionsRender(): void {
        $html = (new PdfReport())->buildHtml($this->sampleData());

        $this->assertStringContainsString('Foo Plugin 1.2', $html, 'Outdated component listed under Updates needed');
        $this->assertStringContainsString('RU', $html, 'Top blocked country listed');
        $this->assertStringContainsString('admin', $html, 'Top failed-login username listed');
        $this->assertStringContainsString('198.51.100.9', $html, 'Recent attack IP listed');
        $this->assertStringContainsString('wp-includes/functions.php', $html, 'Recently modified file listed');
    }

    public function testNoUpdatesShowsReassuringLine(): void {
        $data = $this->sampleData();
        $data['updatesNeeded'] = 0;
        $data['vulnComponents'] = [];

        $html = (new PdfReport())->buildHtml($data);

        $this->assertStringContainsString('up to date', $html, 'A clean install gets the positive "up to date" line');
    }

    public function testCriticalIssuesRaiseACallout(): void {
        $clean = (new PdfReport())->buildHtml($this->sampleData(0));
        $this->assertStringNotContainsString('class="callout"', $clean);

        $withCriticals = (new PdfReport())->buildHtml($this->sampleData(2));
        $this->assertStringContainsString('class="callout"', $withCriticals);
    }

    public function testRenderProducesAPdfDocument(): void {
        $pdf = (new PdfReport())->render($this->sampleData());

        $this->assertNotSame('', $pdf);
        $this->assertSame('%PDF', substr($pdf, 0, 4), 'Output must be a real PDF (magic bytes)');
    }

    public function testFilenameIsDatedAndSafe(): void {
        $name = (new PdfReport())->filename($this->sampleData());

        $this->assertStringStartsWith('dpxl-shield-relatorio-', $name);
        $this->assertStringEndsWith('.pdf', $name);
        $this->assertDoesNotMatchRegularExpression('/[^A-Za-z0-9._-]/', $name, 'Filename must be filesystem-safe');
    }
}
