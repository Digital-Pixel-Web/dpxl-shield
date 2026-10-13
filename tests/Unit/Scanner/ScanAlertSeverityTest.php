<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Scanner;

use Brain\Monkey;
use Brain\Monkey\Actions;
use Brain\Monkey\Functions;
use DPXL\Shield\Scanner\ScanOrchestrator;
use PHPUnit\Framework\TestCase;

/**
 * Which findings make a finished scan send an email.
 *
 * finalize() fired `dpxl_shield_alert` only for severity 'critical'. The one
 * open threat on both staging installs was a high-severity malware signature,
 * so it was detected on every scan from July onwards and never produced a
 * single alert — the same blind spot the dashboard's health gauge had, one
 * screen over. Both now read critical *and* high.
 *
 * The level reported is the worst severity actually present, so a scan that
 * found only high findings does not arrive in the inbox with a critical pill.
 */
class ScanAlertSeverityTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();

        Functions\when('current_time')->justReturn('2026-10-13 18:40:39');
        Functions\when('get_option')->justReturn('');
        Functions\when('update_option')->justReturn(true);
        Functions\when('wp_generate_uuid4')->justReturn('scan-now');
    }

    protected function tearDown(): void {
        Monkey\tearDown();
        parent::tearDown();
    }

    /**
     * Runs finalize() over a set of findings and returns the alert payload, or
     * null when no alert was fired.
     *
     * @param list<array<string,mixed>> $findings
     * @return array<string,mixed>|null
     */
    private function alertFor(array $findings): ?array {
        $fired = null;

        Actions\expectDone('dpxl_shield_alert')
            ->zeroOrMoreTimes()
            ->withAnyArgs()
            ->whenHappen(function (array $alert) use (&$fired): void {
                $fired = $alert;
            });

        $orchestrator = new ScanOrchestrator();

        $results = new \ReflectionProperty(ScanOrchestrator::class, 'results');
        $results->setAccessible(true);
        $results->setValue($orchestrator, $findings);

        $finalize = new \ReflectionMethod(ScanOrchestrator::class, 'finalize');
        $finalize->setAccessible(true);
        $finalize->invoke($orchestrator);

        return $fired;
    }

    /** @return array<string,mixed> */
    private function finding(string $type, string $severity): array {
        return [
            'file_path'  => '/srv/wp-content/plugins/x/a.php',
            'issue_type' => $type,
            'severity'   => $severity,
            'details'    => 'detalhe',
        ];
    }

    /** The staging installs' finding, and the alert that never went out. */
    public function testAHighSeverityThreatFiresTheAlert(): void {
        $alert = $this->alertFor([$this->finding('malware_signature', 'high')]);

        $this->assertNotNull($alert, 'A high-severity malware signature must reach the owner.');
        $this->assertSame('high', $alert['level'], 'Nothing was critical, so the email must not claim it was.');
        $this->assertSame(1, $alert['context']['count']);
        $this->assertSame(0, $alert['context']['critical']);
    }

    public function testACriticalThreatStillFiresAtCriticalLevel(): void {
        $alert = $this->alertFor([
            $this->finding('modified_core', 'critical'),
            $this->finding('malware_signature', 'high'),
        ]);

        $this->assertNotNull($alert);
        $this->assertSame('critical', $alert['level'], 'The worst severity present decides the level.');
        $this->assertSame(2, $alert['context']['count']);
        $this->assertSame(1, $alert['context']['critical']);
    }

    /**
     * Medium stays silent, which is the point of stopping at high: these are
     * the findings 1.7.7 took off the badge, and an email for each of 34 WPML
     * cache files is the crying-wolf failure in its loudest form.
     */
    public function testAdvisoryFindingsFireNothing(): void {
        $alert = $this->alertFor([
            $this->finding('php_in_uploads', 'medium'),
            $this->finding('vulnerable_version', 'medium'),
            $this->finding('heuristic', 'high'),
            $this->finding('unknown', 'low'),
        ]);

        $this->assertNull($alert, 'None of these is a threat, so none of them is an email.');
    }

    /**
     * A medium malware signature is counted as a threat but is not what the
     * alert is for: the scanner is saying it is unsure, and an email claiming
     * the site is compromised must not rest on that.
     */
    public function testAMediumThreatDoesNotFireTheAlert(): void {
        $this->assertNull($this->alertFor([$this->finding('malware_signature', 'medium')]));
    }
}
