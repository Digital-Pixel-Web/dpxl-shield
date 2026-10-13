<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Admin;

use Brain\Monkey;
use Brain\Monkey\Functions;
use DPXL\Shield\Admin\RestApi;
use PHPUnit\Framework\TestCase;

/**
 * The dashboard rings, and the rule that green has to be earned.
 *
 * Before 1.8.3 the three gauges were booleans dressed as percentages:
 * `firewall_ok` was `Options::get('firewall_enabled')` and nothing more, so a
 * site with Extended Protection off, no rules loaded and not one administrator
 * using two-factor still showed three green 100% rings. The ring now counts
 * checks that pass, and these tests pin the two properties that make it worth
 * trusting: it cannot reach 100% while something is off, and a check that could
 * not run never counts as one that passed.
 */
class ModuleCoverageTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();

        Functions\when('get_users')->justReturn([]);
    }

    protected function tearDown(): void {
        Monkey\tearDown();
        parent::tearDown();
    }

    /** @param mixed ...$args */
    private function invoke(string $method, ...$args) {
        $ref = new \ReflectionMethod(RestApi::class, $method);
        $ref->setAccessible(true);

        return $ref->isStatic() ? $ref->invokeArgs(null, $args) : $ref->invokeArgs(new RestApi(), $args);
    }

    /** @param array<string,mixed> $options */
    private function withOptions(array $options): void {
        Functions\when('get_option')->alias(static function (string $name, $default = null) use ($options) {
            return array_key_exists($name, $options) ? $options[$name] : $default;
        });
    }

    /** @return list<array<string,mixed>> */
    private function checks(string ...$states): array {
        $out = [];

        foreach ($states as $i => $state) {
            $out[] = ['label' => "falha {$i}", 'state' => $state, 'action' => ['label' => 'Abrir', 'query' => 'page=dpxl-shield']];
        }

        return $out;
    }

    public function testEverythingOnReadsAsAHundredPercent(): void {
        $summary = $this->invoke('summariseModule', $this->checks('ok', 'ok', 'ok'), 'ok');

        $this->assertSame('ok', $summary['state']);
        $this->assertSame(100, $summary['percent']);
        $this->assertSame('', $summary['headline']);
    }

    /**
     * The property that matters most: one thing switched off and the ring can
     * no longer claim everything is fine.
     */
    public function testOneCheckOffCannotReachAHundredPercent(): void {
        $summary = $this->invoke('summariseModule', $this->checks('ok', 'off', 'ok', 'ok'), 'ok');

        $this->assertSame('warning', $summary['state']);
        $this->assertSame(75, $summary['percent']);
        $this->assertLessThan(100, $summary['percent']);
    }

    /** The subtitle names the first unmet check, and carries its way out. */
    public function testHeadlineAndActionComeFromTheFirstUnmetCheck(): void {
        $checks = [
            ['label' => 'tudo certo', 'state' => 'ok', 'action' => null],
            ['label' => 'Proteção Estendida inativa', 'state' => 'off', 'action' => ['label' => 'Abrir o firewall', 'query' => 'page=dpxl-shield-firewall']],
            ['label' => 'outra coisa', 'state' => 'off', 'action' => null],
        ];

        $summary = $this->invoke('summariseModule', $checks, 'ok');

        $this->assertSame('Proteção Estendida inativa', $summary['headline']);
        $this->assertSame('page=dpxl-shield-firewall', $summary['action']['query']);
    }

    /**
     * "Could not check" is not "degraded" and is not "fine". It is its own
     * state — the same distinction ReputationChecker drew in 1.7.0 between a
     * refused query and a clean site.
     */
    public function testOnlyUnverifiedGapsReportAsUnverifiedNotWarning(): void {
        $summary = $this->invoke('summariseModule', $this->checks('ok', 'unverified'), 'ok');

        $this->assertSame('unverified', $summary['state']);
    }

    public function testSomethingOffOutweighsSomethingUnverified(): void {
        $summary = $this->invoke('summariseModule', $this->checks('off', 'unverified'), 'ok');

        $this->assertSame('warning', $summary['state']);
    }

    /** Open threats make the module critical however much else is configured. */
    public function testOpenThreatsMakeTheModuleCritical(): void {
        $summary = $this->invoke('summariseModule', $this->checks('ok', 'ok'), 'critical');

        $this->assertSame('critical', $summary['state']);
    }

    /**
     * A site nobody has scanned is not a protected site. It used to show a
     * green ring because `scan_ok` only asked whether any critical finding was
     * on record, and on a site that never scanned there is none.
     */
    public function testASiteThatWasNeverScannedIsUnverifiedNotOk(): void {
        $this->withOptions([]);

        $summary = $this->invoke('summariseModule', $this->invoke('scanChecks', 0), 'ok');

        $this->assertSame('unverified', $summary['state']);
        $this->assertStringContainsString('Nenhuma varredura', $summary['headline']);
    }

    /** A scan from months ago is also not a verified site. */
    public function testAStaleScanDoesNotCountAsVerified(): void {
        $this->withOptions([
            'dpxl_shield_last_scan_at' => gmdate('Y-m-d H:i:s', time() - (30 * DAY_IN_SECONDS)),
        ]);

        $checks = $this->invoke('scanChecks', 0);

        $this->assertSame('unverified', $checks[0]['state']);
    }

    public function testARecentScanWithNoThreatsCounts(): void {
        $this->withOptions([
            'dpxl_shield_last_scan_at'      => gmdate('Y-m-d H:i:s', time() - 3600),
            'dpxl_shield_reputation_cache'  => ['checked_at' => gmdate('c'), 'results' => [], 'unavailable' => []],
        ]);

        $summary = $this->invoke('summariseModule', $this->invoke('scanChecks', 0), 'ok');

        $this->assertSame('ok', $summary['state']);
        $this->assertSame(100, $summary['percent']);
    }

    /** A blocklist that refused the query is not a clean site. */
    public function testAReputationCheckThatCouldNotRunIsUnverified(): void {
        $this->withOptions([
            'dpxl_shield_last_scan_at'     => gmdate('Y-m-d H:i:s', time() - 3600),
            'dpxl_shield_reputation_cache' => [
                'checked_at'  => gmdate('c'),
                'results'     => [],
                'unavailable' => ['spamhaus_zen'],
            ],
        ]);

        $checks = $this->invoke('scanChecks', 0);

        $this->assertSame('unverified', $checks[2]['state']);
    }

    /**
     * The exact lie this phase set out to kill: brute force switched on, not
     * one administrator actually using two-factor, and the gauge read 100%.
     */
    public function testLoginIsNotCompleteWithoutAnAdministratorUsingTwoFactor(): void {
        $this->withOptions(['dpxl_shield_brute_force_enabled' => true]);
        Functions\when('get_users')->justReturn([]);

        $summary = $this->invoke('summariseModule', $this->invoke('loginChecks'), 'ok');

        $this->assertLessThan(100, $summary['percent']);
        $this->assertSame('warning', $summary['state']);
        $this->assertStringContainsString('duas etapas', $summary['headline']);
    }

    public function testLoginIsCompleteWhenAnAdministratorActuallyUsesTwoFactor(): void {
        $this->withOptions([
            'dpxl_shield_brute_force_enabled'       => true,
            'dpxl_shield_two_factor_required_roles' => ['administrator'],
        ]);
        Functions\when('get_users')->justReturn([1]);

        $summary = $this->invoke('summariseModule', $this->invoke('loginChecks'), 'ok');

        $this->assertSame('ok', $summary['state']);
        $this->assertSame(100, $summary['percent']);
    }
}
