<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Admin;

use Brain\Monkey;
use Brain\Monkey\Functions;
use DPXL\Shield\Admin\RestApi;
use DPXL\Shield\Scanner\ScanClassifier;
use PHPUnit\Framework\TestCase;

/**
 * The dashboard's problem badge against the scan screen's count.
 *
 * They disagreed, and the dashboard was the one telling the truth. /dashboard
 * counted every open threat; /scan/results defaulted to
 * scan_id = dpxl_shield_last_scan_id — a filter older than the reconciliation
 * 1.7.2 brought in, and incompatible with it. Reconciliation keeps the
 * *original* row of a finding that is still open, so that row carries the
 * scan_id of the scan that saw it first; the last scan inserts nothing for a
 * finding that was already there. The filter therefore listed only findings
 * detected for the first time and went blind to everything that persisted,
 * which is exactly the set nobody has fixed.
 *
 * On the staging install, with 19 open threats, the panel read 19 and the scan
 * screen read 0. The dataset below is that install: 19 open threats spread over
 * seven older scans, a last_scan_id that appears on no row at all, and the same
 * install reporting dpxl_shield_last_scan_issue_count = 19 — the last scan did
 * re-detect all 19, it just had nothing to insert.
 *
 * Both endpoints build SQL, so the fake wpdb below evaluates their WHERE clauses
 * against one shared set of rows. That is the point: the two numbers are not
 * compared as constants, they are folded from the same rows, so they cannot
 * drift apart again without this failing.
 */
class ScanThreatCountTest extends TestCase {

    private const LAST_SCAN_ID = 'scan-10-nothing-new';

    /** @var FakeScanWpdb */
    private $wpdb;

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();

        Functions\when('__')->returnArg(1);
        Functions\when('_n')->alias(fn($single, $plural, $number) => $number === 1 ? $single : $plural);
        Functions\when('sanitize_key')->returnArg(1);
        Functions\when('sanitize_text_field')->returnArg(1);
        Functions\when('current_time')->justReturn('2026-10-13 18:40:39');
        Functions\when('rest_ensure_response')->alias(fn($data) => new \WP_REST_Response($data));
        Functions\when('get_option')->alias(
            fn($name, $default = null) => $name === 'dpxl_shield_last_scan_id' ? self::LAST_SCAN_ID : $default
        );

        $GLOBALS['wpdb'] = $this->wpdb = new FakeScanWpdb(self::stagingRows());
    }

    protected function tearDown(): void {
        unset($GLOBALS['wpdb']);
        Monkey\tearDown();
        parent::tearDown();
    }

    /**
     * The staging install's scan_results table, in shape.
     *
     * 19 open threats, none of them carrying the last scan's id: ten
     * vulnerable_version findings from one July scan, a malware_signature open
     * since July, and the rest trickled in over six later scans. Plus the
     * advisory rows and the resolved history that sit alongside them.
     *
     * @return list<array<string,mixed>>
     */
    private static function stagingRows(): array {
        $rows = [];
        $id   = 1;

        $add = function (string $scanId, string $type, string $severity, string $status) use (&$rows, &$id): void {
            $rows[] = [
                'id'           => $id,
                'scan_id'      => $scanId,
                'issue_type'   => $type,
                'severity'     => $severity,
                'status'       => $status,
                'file_path'    => 'file-' . $id . '.php',
                'signature_id' => null,
                'details'      => null,
            ];
            $id++;
        };

        // Open threats, by the scan that detected each one first.
        for ($i = 0; $i < 10; $i++) {
            $add('scan-03-july', 'vulnerable_version', 'medium', 'new');
        }

        $add('scan-01-july', 'malware_signature', 'high', 'new');
        $add('scan-04-august', 'vulnerable_version', 'medium', 'new');
        $add('scan-04-august', 'vulnerable_version', 'medium', 'new');
        $add('scan-05-august', 'vulnerable_version', 'medium', 'new');
        $add('scan-06-august', 'vulnerable_version', 'medium', 'new');
        $add('scan-06-august', 'vulnerable_version', 'medium', 'new');
        $add('scan-07-august', 'vulnerable_version', 'medium', 'new');
        $add('scan-08-october', 'vulnerable_version', 'medium', 'new');
        $add('scan-08-october', 'unknown', 'critical', 'new');

        // Open advisory rows: real findings, but not threats, so they belong to
        // the recommendations list and must stay out of both counts.
        for ($i = 0; $i < 8; $i++) {
            $add('scan-08-october', 'heuristic', 'medium', 'new');
        }

        $add('scan-09-october', 'unknown', 'low', 'new');

        // Closed history. The last scan resolved what it stopped seeing, which is
        // the reason status='new' can be trusted as "what the last scan found".
        for ($i = 0; $i < 40; $i++) {
            $add('scan-02-july', 'vulnerable_version', 'medium', 'resolved');
        }

        $add('scan-02-july', 'malware_signature', 'critical', 'false_positive');

        return $rows;
    }

    /** @param array<string,mixed> $params */
    private function scanResults(array $params = []): array {
        return (new RestApi())->getScanResults(new \WP_REST_Request($params))->get_data();
    }

    private function dashboard(): array {
        return (new RestApi())->getDashboard()->get_data();
    }

    public function testTheTwoScreensCountTheSameThreats(): void {
        $panel = $this->dashboard()['scan_issues']['total'];
        $scan  = $this->scanResults()['total'];

        $this->assertSame(19, $panel, 'The panel counts every open threat.');
        $this->assertSame(
            $panel,
            $scan,
            'The scan screen and the panel badge must be folded from the same open rows.'
        );
    }

    public function testTheCriticalCountAlsoAgrees(): void {
        $this->assertSame(
            $this->dashboard()['scan_issues']['critical'],
            $this->scanResults()['critical_total'],
            'Both screens read "critical" off the same rows.'
        );
    }

    /**
     * The defect itself: with the old default the scan screen saw none of the 19.
     * Driving the same filter through the explicit parameter reproduces it, so
     * this pins the cause and not just the symptom.
     */
    public function testFilteringByTheLastScanIdIsWhatUsedToShowZero(): void {
        $this->assertSame(
            0,
            $this->scanResults(['scan_id' => self::LAST_SCAN_ID])['total'],
            'The last scan inserted nothing, so its scan_id matches no row.'
        );
    }

    public function testNoQueryNarrowsToOneScanByDefault(): void {
        $this->scanResults();

        foreach ($this->wpdb->executed as $sql) {
            $this->assertStringNotContainsString(
                'scan_id',
                $sql,
                "The default listing must not narrow to a single scan: {$sql}"
            );
        }

        $this->assertNotEmpty($this->wpdb->executed);
    }

    public function testAnExplicitScanIdStillNarrowsToThatScan(): void {
        $data = $this->scanResults(['scan_id' => 'scan-04-august']);

        $this->assertSame(2, $data['total'], 'Asking for one scan still answers for that scan alone.');
        $this->assertSame('scan-04-august', $data['scan_id']);
    }

    public function testTheDefaultResponseReportsNoScanFilter(): void {
        $this->assertSame('', $this->scanResults()['scan_id'], 'Nothing was filtered, so nothing is reported.');
    }

    public function testAdvisoryRowsAreCountedAsRecommendationsNotThreats(): void {
        $data = $this->scanResults();

        $this->assertSame(9, $data['recommendation_total'], 'The eight heuristics plus the low "unknown" row.');
        $this->assertCount(19, $data['items']);
        $this->assertCount(9, $data['recommendations']);

        foreach ($data['items'] as $item) {
            $this->assertTrue(ScanClassifier::isThreat($item), 'The threats list holds threats only.');
        }

        foreach ($data['recommendations'] as $item) {
            $this->assertFalse(ScanClassifier::isThreat($item), 'The recommendations list holds no threats.');
        }
    }

    public function testTheThreatsAndRecommendationsSplitLosesNothing(): void {
        $data = $this->scanResults();
        $open = count(array_filter(self::stagingRows(), fn($r) => $r['status'] === 'new'));

        $this->assertSame(
            $open,
            $data['total'] + $data['recommendation_total'],
            'Every open row is either a threat or a recommendation — none falls between.'
        );
    }

    /** A clean install must not be told it has problems. */
    public function testAnInstallWithNothingOpenCountsZeroOnBothScreens(): void {
        $GLOBALS['wpdb'] = $this->wpdb = new FakeScanWpdb([]);

        $this->assertSame(0, $this->dashboard()['scan_issues']['total']);
        $this->assertSame(0, $this->scanResults()['total']);
        $this->assertTrue($this->dashboard()['scan_ok']);
    }
}

/**
 * Enough of wpdb to answer both endpoints from one set of scan_results rows.
 *
 * It evaluates the WHERE clauses the two code paths actually build — status,
 * scan_id, the threat expression and its complement, severity, and the
 * repairable issue_type list — against the rows in memory. Queries against the
 * other tables (traffic log, login events) come back empty, which is a quiet
 * install, not a special case.
 */
class FakeScanWpdb {

    /** @var string */
    public $prefix = 'wp_';

    /** @var string[] Every statement that reached the "database". */
    public $executed = [];

    /** @var list<array<string,mixed>> */
    private $rows;

    /** @param list<array<string,mixed>> $rows */
    public function __construct(array $rows) {
        $this->rows = $rows;
    }

    public function esc_like(string $text): string {
        return addcslashes($text, '_%\\');
    }

    /** @param mixed ...$args */
    public function prepare(string $sql, ...$args): string {
        foreach ($args as $arg) {
            $replacement = is_int($arg) || is_float($arg)
                ? (string) $arg
                : "'" . str_replace("'", "\\'", (string) $arg) . "'";

            $sql = preg_replace('/%[sdf]/', $replacement, $sql, 1) ?? $sql;
        }

        return str_replace('%%', '%', $sql);
    }

    /** @return list<array<string,mixed>> */
    public function get_results(string $sql, $output = null): array {
        $this->executed[] = $sql;

        if (!$this->isScanQuery($sql)) {
            return [];
        }

        return array_values($this->matching($sql));
    }

    /** @return string */
    public function get_var(string $sql) {
        $this->executed[] = $sql;

        if (!$this->isScanQuery($sql)) {
            return '0';
        }

        return (string) count($this->matching($sql));
    }

    private function isScanQuery(string $sql): bool {
        return str_contains($sql, 'dpxl_shield_scan_results');
    }

    /**
     * @return array<int,array<string,mixed>>
     */
    private function matching(string $sql): array {
        $threatSql = ScanClassifier::threatWhereSql();
        $wantsNonThreat = str_contains($sql, $threatSql . ' = 0');
        $wantsThreat    = !$wantsNonThreat && str_contains($sql, $threatSql);

        // Remove the threat expression before reading the other predicates: it
        // carries a severity comparison of its own that is none of their business.
        $rest = str_replace([$threatSql . ' = 0', $threatSql], '', $sql);

        $status   = self::literal($rest, 'status');
        $scanId   = self::literal($rest, 'scan_id');
        $severity = self::literal($rest, 'severity');
        $types    = preg_match("/issue_type IN \(([^)]*)\)/", $rest, $m) === 1
            ? array_map(fn($t) => trim($t, " '"), explode(',', $m[1]))
            : null;

        return array_filter($this->rows, function (array $row) use (
            $wantsThreat, $wantsNonThreat, $status, $scanId, $severity, $types
        ): bool {
            if ($status !== null && $row['status'] !== $status) {
                return false;
            }

            if ($scanId !== null && $row['scan_id'] !== $scanId) {
                return false;
            }

            if ($severity !== null && $row['severity'] !== $severity) {
                return false;
            }

            if ($types !== null && !in_array($row['issue_type'], $types, true)) {
                return false;
            }

            if ($wantsThreat && !ScanClassifier::isThreat($row)) {
                return false;
            }

            if ($wantsNonThreat && ScanClassifier::isThreat($row)) {
                return false;
            }

            return true;
        });
    }

    private static function literal(string $sql, string $column): ?string {
        return preg_match("/{$column}\s*=\s*'([^']*)'/", $sql, $m) === 1 ? $m[1] : null;
    }
}
