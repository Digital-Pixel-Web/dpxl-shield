<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Scanner;

use Brain\Monkey;
use Brain\Monkey\Functions;
use DPXL\Shield\Scanner\FileRepair;
use DPXL\Shield\Scanner\ScanOrchestrator;
use PHPUnit\Framework\TestCase;

/**
 * Two places that mistook "the last scan" for "what is open".
 *
 * Both follow from the same property of the 1.7.2 reconciliation: a finding that
 * is still open keeps its original row, so that row carries the scan_id of the
 * scan that detected it first, and the last scan inserts nothing for it.
 *
 *   - The hourly incremental scan reconciled like a full one. It opens only the
 *     files modified since the last scan, so every other open finding looked
 *     "gone" to it and was marked resolved — on the staging install that would
 *     have closed all 19 open threats, a months-old malware signature among
 *     them, the first time an incremental pass found anything at all. It never
 *     fired only because those passes kept coming back empty.
 *
 *   - "Repair all" selected by the last scan's id, so a modified core file that
 *     kept being re-detected was unreachable: its row belongs to an older scan.
 */
class FindingScopeTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();

        Functions\when('wp_normalize_path')->alias(fn($p) => str_replace('\\', '/', $p));
        Functions\when('wp_generate_uuid4')->justReturn('scan-now');
        Functions\when('get_option')->justReturn('');
        Functions\when('update_option')->justReturn(true);
    }

    protected function tearDown(): void {
        unset($GLOBALS['wpdb']);
        Monkey\tearDown();
        parent::tearDown();
    }

    /**
     * Runs persistResults() over a set of findings, against a table that already
     * holds $open rows.
     *
     * @param list<array<string,mixed>> $open
     * @param list<array<string,mixed>> $found
     */
    private function persist(array $open, array $found, bool $reconcile): FakeScanResultsTable {
        $GLOBALS['wpdb'] = $table = new FakeScanResultsTable($open);

        $orchestrator = new ScanOrchestrator();

        $results = new \ReflectionProperty(ScanOrchestrator::class, 'results');
        $results->setAccessible(true);
        $results->setValue($orchestrator, $found);

        $persist = new \ReflectionMethod(ScanOrchestrator::class, 'persistResults');
        $persist->setAccessible(true);
        $persist->invoke($orchestrator, $reconcile);

        return $table;
    }

    /** @return array<string,mixed> */
    private function finding(int $id, string $path, string $type = 'malware_signature', string $severity = 'high'): array {
        return [
            'id'           => $id,
            'file_path'    => $path,
            'issue_type'   => $type,
            'severity'     => $severity,
            'signature_id' => 'sig-1',
            'details'      => 'detalhe',
            'status'       => 'new',
        ];
    }

    // ── The incremental scan ───────────────────────────────────────────────

    public function testAnIncrementalPassDoesNotCloseFindingsItNeverLookedAt(): void {
        $open = [
            $this->finding(1, '/srv/wp-content/plugins/old/a.php'),
            $this->finding(2, '/srv/wp-content/themes/old/b.php'),
            $this->finding(3, '/srv/wp-includes/c.php'),
        ];

        // The pass opened one recently modified file and found something there.
        $table = $this->persist($open, [$this->finding(0, '/srv/wp-content/uploads/2026/10/new.php')], false);

        $this->assertSame([], $table->resolvedIds, 'An incremental pass has no opinion on files it never opened.');
        $this->assertCount(1, $table->inserted, 'The genuinely new finding is still recorded.');
        $this->assertSame('/srv/wp-content/uploads/2026/10/new.php', $table->inserted[0]['file_path']);
    }

    public function testAnIncrementalPassStillAvoidsRecordingAFindingTwice(): void {
        $existing = $this->finding(1, '/srv/wp-content/plugins/x/a.php');

        $table = $this->persist([$existing], [$existing], false);

        $this->assertSame([], $table->inserted, 'The finding is already open; a second row would be a duplicate.');
        $this->assertSame([], $table->resolvedIds);
    }

    // ── The full scan keeps reconciling ───────────────────────────────────

    public function testAFullScanStillClosesWhatItNoLongerSees(): void {
        $gone = $this->finding(1, '/srv/wp-content/plugins/cleaned/a.php');
        $kept = $this->finding(2, '/srv/wp-includes/b.php');

        $table = $this->persist([$gone, $kept], [$kept], true);

        $this->assertSame([1], $table->resolvedIds, 'A full pass looked everywhere, so absence means cleaned.');
        $this->assertSame([], $table->inserted);
    }

    public function testAFullScanStillCollapsesDuplicatesLeftByOlderScans(): void {
        $first     = $this->finding(1, '/srv/wp-includes/a.php');
        $duplicate = $this->finding(2, '/srv/wp-includes/a.php');

        $table = $this->persist([$first, $duplicate], [$first], true);

        $this->assertSame([2], $table->resolvedIds, 'One row per finding; the oldest is the one that stays.');
    }

    public function testAFullScanRecordsAFindingThatIsGenuinelyNew(): void {
        $table = $this->persist([], [$this->finding(0, '/srv/wp-content/uploads/2026/10/shell.php')], true);

        $this->assertCount(1, $table->inserted);
        $this->assertSame('scan-now', $table->inserted[0]['scan_id']);
        $this->assertSame('new', $table->inserted[0]['status']);
    }

    // ── Repair all ─────────────────────────────────────────────────────────

    public function testRepairAllLooksAtEveryOpenFindingNotJustTheLastScans(): void {
        Functions\when('get_option')->alias(
            fn($name, $default = null) => $name === 'dpxl_shield_last_scan_id' ? 'scan-10-nothing-new' : $default
        );

        $GLOBALS['wpdb'] = $table = new FakeScanResultsTable([]);

        (new FileRepair())->repairAll();

        $this->assertNotEmpty($table->executed);

        foreach ($table->executed as $sql) {
            $this->assertStringNotContainsString(
                'scan_id',
                $sql,
                "Repair all must reach a finding whose row belongs to an older scan: {$sql}"
            );
            $this->assertStringContainsString("status = 'new'", $sql, 'It repairs what is open.');
        }
    }
}

/**
 * Enough of wpdb to record what persistResults() and repairAll() did.
 *
 * Only the calls those two make are implemented: the open-rows SELECT, the
 * status updates and the inserts.
 */
class FakeScanResultsTable {

    /** @var string */
    public $prefix = 'wp_';

    /** @var string[] */
    public $executed = [];

    /** @var list<int> Row ids moved to 'resolved'. */
    public $resolvedIds = [];

    /** @var list<array<string,mixed>> */
    public $inserted = [];

    /** @var list<array<string,mixed>> */
    public $updated = [];

    /** @var list<array<string,mixed>> */
    private $rows;

    /** @param list<array<string,mixed>> $rows */
    public function __construct(array $rows) {
        $this->rows = $rows;
    }

    /** @param mixed ...$args */
    public function prepare(string $sql, ...$args): string {
        foreach ($args as $arg) {
            $replacement = is_int($arg) || is_float($arg) ? (string) $arg : "'" . (string) $arg . "'";
            $sql = preg_replace('/%[sdf]/', $replacement, $sql, 1) ?? $sql;
        }

        return $sql;
    }

    /** @return list<array<string,mixed>> */
    public function get_results(string $sql, $output = null): array {
        $this->executed[] = $sql;

        return $this->rows;
    }

    /**
     * @param array<string,mixed> $data
     * @param array<string,mixed> $where
     */
    public function update(string $table, array $data, array $where, $format = null, $whereFormat = null): int {
        $this->updated[] = ['data' => $data, 'where' => $where];

        if (($data['status'] ?? '') === 'resolved') {
            $this->resolvedIds[] = (int) $where['id'];
        }

        return 1;
    }

    /** @param array<string,mixed> $data */
    public function insert(string $table, array $data, $format = null): int {
        $this->inserted[] = $data;

        return 1;
    }
}
