<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Admin;

use Brain\Monkey;
use Brain\Monkey\Functions;
use DPXL\Shield\Admin\RestApi;
use PHPUnit\Framework\TestCase;

/**
 * The dashboard's "Resumo do Firewall" table.
 *
 * Through 1.7.3 the four per-type rows were hardcoded zeros in admin.js while the
 * Total row read real data from /dashboard, so the table contradicted itself the
 * moment anything was actually blocked: Total showed a number and every row
 * above it showed nothing. The counts now come from one grouped query, and what
 * matters is the invariant that made the old version wrong — the rows have to
 * account for the Total.
 */
class FirewallSummaryTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();

        Functions\when('__')->returnArg(1);
        Functions\when('_n')->alias(
            fn($single, $plural, $number) => $number === 1 ? $single : $plural
        );
        Functions\when('get_option')->justReturn(null);
    }

    protected function tearDown(): void {
        Monkey\tearDown();
        parent::tearDown();
    }

    /**
     * @param array<int,array<string,mixed>> $rows
     * @return array<string,mixed>
     */
    private function summarise(array $rows): array {
        $m = new \ReflectionMethod(RestApi::class, 'summariseBlocks');
        $m->setAccessible(true);

        return $m->invoke(new RestApi(), $rows);
    }

    /** One grouped row as the SQL returns it: counts arrive as strings. */
    private function row(string $ruleId, int $today, int $week, int $month): array {
        return [
            'rule_id' => $ruleId,
            'today'   => (string) $today,
            'week'    => (string) $week,
            'month'   => (string) $month,
        ];
    }

    public function testRowsAccountForTheTotal(): void {
        $result = $this->summarise([
            $this->row('sqli-001', 2, 5, 9),
            $this->row('xss-004', 1, 1, 3),
            $this->row('ip-blocklist', 4, 7, 7),
            $this->row('country-block', 0, 2, 6),
            $this->row('rate-limit', 3, 3, 3),
        ]);

        foreach (['today', 'week', 'month'] as $window) {
            $this->assertSame(
                $result['total'][$window],
                array_sum(array_column($result['rows'], $window)),
                "The per-type rows must add up to the Total for '{$window}'."
            );
        }

        $this->assertSame(['today' => 10, 'week' => 18, 'month' => 28], $result['total']);
        $this->assertNull($result['reason'], 'A table with data needs no empty-state reason.');
    }

    public function testWafRuleIdsAreFoldedTogether(): void {
        $result  = $this->summarise([
            $this->row('sqli-001', 2, 5, 9),
            $this->row('xss-004', 1, 1, 3),
            $this->row('', 1, 1, 1),
        ]);
        $byType = array_column($result['rows'], null, 'type');

        $this->assertArrayHasKey('waf', $byType);
        $this->assertCount(1, $result['rows'], 'Every WAF rule ID belongs to a single "Regras do WAF" row.');
        $this->assertSame(13, $byType['waf']['month']);
    }

    public function testBlockPathsEachGetTheirOwnRow(): void {
        $result = $this->summarise([
            $this->row('ip-blocklist', 1, 1, 1),
            $this->row('rate-limit', 1, 1, 1),
            $this->row('custom-pattern', 1, 1, 1),
            $this->row('country-block', 1, 1, 1),
            $this->row('country-allow', 1, 1, 1),
        ]);
        $byType = array_column($result['rows'], null, 'type');

        $this->assertSame(
            ['blocklist', 'rate-limit', 'custom-pattern', 'country'],
            array_keys($byType),
            'Both country rule IDs share one row; the other paths get their own.'
        );
        $this->assertSame(2, $byType['country']['month'], 'country-block and country-allow are both "por país".');
    }

    public function testTypesThatBlockedNothingAreLeftOut(): void {
        $result = $this->summarise([$this->row('ip-blocklist', 1, 1, 1)]);

        $this->assertSame(['blocklist'], array_column($result['rows'], 'type'));
        $this->assertSame(
            'Lista de bloqueio de IPs',
            $result['rows'][0]['label'],
            'Row labels are the pt-BR strings the panel renders.'
        );
    }

    public function testAnInstallWithNoBlocksGetsAReasonInsteadOfZeros(): void {
        $result = $this->summarise([]);

        $this->assertSame([], $result['rows'], 'No blocks means no rows — not a grid of zeros.');
        $this->assertSame(['today' => 0, 'week' => 0, 'month' => 0], $result['total']);
        $this->assertSame('Nenhum bloqueio registrado nas últimas 24 horas.', $result['reason']);
    }

    public function testDisabledFirewallIsNamedAsTheReason(): void {
        Functions\when('get_option')->alias(
            fn($name, $default = null) => $name === 'dpxl_shield_firewall_enabled' ? false : null
        );

        $this->assertSame(
            'O firewall está desativado, portanto nenhum bloqueio é registrado.',
            $this->summarise([])['reason']
        );
    }

    public function testDisabledTrafficLogIsNamedAsTheReason(): void {
        Functions\when('get_option')->alias(
            fn($name, $default = null) => $name === 'dpxl_shield_traffic_log_enabled' ? false : null
        );

        $this->assertSame(
            'O registro de tráfego está desativado, portanto os bloqueios não são contabilizados.',
            $this->summarise([])['reason']
        );
    }
}
