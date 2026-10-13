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
 *
 * 1.7.7 is the next chapter. Once the two screens agreed, what they agreed on
 * turned out to be wrong: of the 19, exactly one was critical/high and the
 * other 18 were components with an update available. The other staging install
 * read 40, of which 34 were PHP files WPML compiles into its own cache — the
 * scanner itself calls those "not evidence of a compromise on its own" and then
 * counted them. So php_in_uploads and vulnerable_version became gated on
 * severity, the way 'unknown' already was. The dataset below carries both
 * installs' rows, and /scan/status joins the two endpoints as a third reader of
 * the same rows, because admin.js writes its issue_count into the very element
 * the results query fills.
 */
class ScanThreatCountTest extends TestCase {

    private const LAST_SCAN_ID = 'scan-10-nothing-new';

    /** What dpxl_shield_last_scan_issue_count still claims after the upgrade. */
    private const STALE_SNAPSHOT = 19;

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
        // 1.8.3: the dashboard payload now reports how much of each module is
        // actually on, and the login module asks how many administrators have
        // finished setting 2FA up.
        Functions\when('get_users')->justReturn([]);
        Functions\when('get_option')->alias(fn($name, $default = null) => [
            'dpxl_shield_last_scan_id'         => self::LAST_SCAN_ID,
            // The snapshot finalize() left behind under the old classification.
            // /scan/status must not hand it back.
            'dpxl_shield_last_scan_issue_count' => self::STALE_SNAPSHOT,
        ][$name] ?? $default);

        $GLOBALS['wpdb'] = $this->wpdb = new FakeScanWpdb(self::stagingRows());
    }

    protected function tearDown(): void {
        unset($GLOBALS['wpdb']);
        Monkey\tearDown();
        parent::tearDown();
    }

    /**
     * The staging installs' scan_results table, in shape.
     *
     * The 1.7.6 half, from the first install: 19 rows that both screens used to
     * count, none of them carrying the last scan's id — ten
     * vulnerable_version findings from one July scan, a malware_signature open
     * since July, and the rest trickled in over six later scans. Plus the
     * advisory rows and the resolved history alongside them.
     *
     * The 1.7.7 half: the other install's 34 WPML cache files, and one row on
     * each side of both new gates — PHP where media actually lands, and a CVE
     * left unpatched — so the gate is pinned in both directions rather than
     * just downward.
     *
     * Four rows are therefore threats: the malware signature, the exposed
     * .env, the real PHP upload, and the unpatched CVE.
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
        // A CVE with no fix available: scored high, so it stays a threat while
        // the merely-outdated rows around it do not.
        $add('scan-04-august', 'vulnerable_version', 'high', 'new');
        $add('scan-05-august', 'vulnerable_version', 'medium', 'new');
        $add('scan-06-august', 'vulnerable_version', 'medium', 'new');
        $add('scan-06-august', 'vulnerable_version', 'medium', 'new');
        $add('scan-07-august', 'vulnerable_version', 'medium', 'new');
        $add('scan-08-october', 'vulnerable_version', 'medium', 'new');
        $add('scan-08-october', 'unknown', 'critical', 'new');

        // PHP where media actually lands — the finding php_in_uploads exists
        // for. Critical, so it survives the gate.
        $add('scan-08-october', 'php_in_uploads', 'critical', 'new');

        // Open advisory rows: real findings, but not threats, so they belong to
        // the recommendations list and must stay out of both counts.
        for ($i = 0; $i < 8; $i++) {
            $add('scan-08-october', 'heuristic', 'medium', 'new');
        }

        $add('scan-09-october', 'unknown', 'low', 'new');

        // The other install's WPML Twig cache: compiled templates under
        // uploads/cache/, rated medium by the directory guard, which is the
        // scanner saying this is a plugin doing its job.
        for ($i = 0; $i < 34; $i++) {
            $add('scan-09-october', 'php_in_uploads', 'medium', 'new');
        }

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

        $this->assertSame(4, $panel, 'The panel counts every open threat, and only those.');
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

        $this->assertSame(1, $data['total'], 'That scan found one threat: the unpatched CVE.');
        $this->assertSame(2, $data['recommendation_total'], 'Its two outdated components narrow too.');
        $this->assertSame('scan-04-august', $data['scan_id']);
    }

    public function testTheDefaultResponseReportsNoScanFilter(): void {
        $this->assertSame('', $this->scanResults()['scan_id'], 'Nothing was filtered, so nothing is reported.');
    }

    public function testAdvisoryRowsAreCountedAsRecommendationsNotThreats(): void {
        $data = $this->scanResults();

        $this->assertSame(
            60,
            $data['recommendation_total'],
            'Eight heuristics, the low "unknown" row, 17 outdated components and 34 WPML cache files.'
        );
        $this->assertCount(4, $data['items']);
        $this->assertCount(60, $data['recommendations']);

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

    /**
     * The 1.7.7 decision, read off the badge the owner actually looks at: the
     * two gated types count at critical/high and not below. Asserted through
     * the endpoints, so threatWhereSql() carries it and not just isThreat().
     */
    public function testTheGatedTypesCountOnlyAtCriticalOrHigh(): void {
        $threats = $this->scanResults()['items'];

        $byType = [];

        foreach ($threats as $row) {
            $byType[$row['issue_type']][] = $row['severity'];
        }

        $this->assertSame(['critical'], $byType['php_in_uploads'] ?? [], 'Only the real upload counts.');
        $this->assertSame(['high'], $byType['vulnerable_version'] ?? [], 'Only the unpatched CVE counts.');

        $gated = array_filter(
            $this->scanResults()['recommendations'],
            fn($r) => in_array($r['issue_type'], ['php_in_uploads', 'vulnerable_version'], true)
        );

        $this->assertCount(51, $gated, 'The 34 cache files and the 17 outdated components.');

        foreach ($gated as $row) {
            $this->assertSame('medium', $row['severity'], 'Everything demoted was rated medium.');
        }
    }

    /**
     * /scan/status is the third screen reading these rows, and the one that
     * used to answer from a cached option. admin.js writes its issue_count into
     * the same stat and badge that the results query fills, so a snapshot taken
     * under the old classification would have made the scan screen show 19 or 4
     * depending on which request answered last.
     */
    public function testTheStatusEndpointCountsLiveInsteadOfReplayingTheSnapshot(): void {
        $status = (new RestApi())->getScanStatus()->get_data();

        $this->assertSame(
            $this->scanResults()['total'],
            $status['issue_count'],
            'The status endpoint folds the same open rows as the results screen.'
        );
        $this->assertNotSame(
            self::STALE_SNAPSHOT,
            $status['issue_count'],
            'dpxl_shield_last_scan_issue_count still claims the old total and must not be echoed.'
        );
    }

    /**
     * 1.7.8's other half, and the mirror image of 1.7.7: the badge was
     * over-counting, while the health gauge never lit at all. scan_ok asked
     * whether anything was *critical*, and the one open threat on both staging
     * installs was a high-severity malware signature — so the gauge read 100%
     * green for months with that finding open underneath it.
     */
    public function testTheHealthGaugeCountsHighAlongsideCritical(): void {
        $data = $this->dashboard();

        $this->assertSame(4, $data['scan_issues']['severe'], 'Two critical and two high threats are open.');
        $this->assertSame(2, $data['scan_issues']['critical'], 'The critical figure stays critical-only.');
        $this->assertFalse($data['scan_ok']);
    }

    /**
     * The staging installs exactly: one open threat, high, nothing critical.
     * This is the case the old rule called healthy.
     */
    public function testAHighThreatAloneIsEnoughToSayTheSiteIsNotOk(): void {
        $GLOBALS['wpdb'] = $this->wpdb = new FakeScanWpdb([[
            'id'           => 1,
            'scan_id'      => 'scan-01-july',
            'issue_type'   => 'malware_signature',
            'severity'     => 'high',
            'status'       => 'new',
            'file_path'    => 'wp-content/plugins/support/class-login-page-customizer.php',
            'signature_id' => 'sig-wp-open-registration-admin-role',
            'details'      => null,
        ]]);

        $data = $this->dashboard();

        $this->assertSame(0, $data['scan_issues']['critical'], 'Nothing is critical, which is why this went unnoticed.');
        $this->assertSame(1, $data['scan_issues']['severe']);
        $this->assertFalse($data['scan_ok'], 'One open high-severity threat is not a healthy site.');
        $this->assertSame(1, $this->scanResults()['total'], 'And the scan screen was listing it all along.');
    }

    /**
     * The other direction, which is the reason medium is left out: an install
     * whose open rows are all advisory keeps its gauge green. Turning it red
     * for a recommendation would be the 1.7.7 defect again, one screen over.
     */
    public function testAdvisoryRowsAloneLeaveTheGaugeGreen(): void {
        $rows = [];

        foreach (['php_in_uploads', 'vulnerable_version', 'heuristic', 'unknown'] as $i => $type) {
            $rows[] = [
                'id'           => $i + 1,
                'scan_id'      => 'scan-09-october',
                'issue_type'   => $type,
                'severity'     => 'medium',
                'status'       => 'new',
                'file_path'    => 'file-' . $i . '.php',
                'signature_id' => null,
                'details'      => null,
            ];
        }

        $GLOBALS['wpdb'] = $this->wpdb = new FakeScanWpdb($rows);

        $data = $this->dashboard();

        $this->assertSame(0, $data['scan_issues']['total'], 'None of these is a threat.');
        $this->assertSame(0, $data['scan_issues']['severe']);
        $this->assertTrue($data['scan_ok']);
        $this->assertSame(4, $this->scanResults()['recommendation_total'], 'They are all still listed.');
    }

    /** A clean install must not be told it has problems. */
    public function testAnInstallWithNothingOpenCountsZeroOnBothScreens(): void {
        $GLOBALS['wpdb'] = $this->wpdb = new FakeScanWpdb([]);

        $this->assertSame(0, $this->dashboard()['scan_issues']['total']);
        $this->assertSame(0, $this->scanResults()['total']);
        $this->assertSame(0, (new RestApi())->getScanStatus()->get_data()['issue_count']);
        $this->assertSame(0, $this->dashboard()['scan_issues']['severe']);
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
        // The severe expression contains the threat expression, so it has to be
        // recognised first or every gauge query would read as a plain threat
        // count. Both are delegated to the PHP classifier rather than parsed;
        // ScanClassifierTest is what holds the SQL and the PHP to one rule.
        $severeSql = ScanClassifier::severeWhereSql();
        $threatSql = ScanClassifier::threatWhereSql();

        $wantsSevere    = str_contains($sql, $severeSql);
        $wantsNonThreat = !$wantsSevere && str_contains($sql, $threatSql . ' = 0');
        $wantsThreat    = !$wantsSevere && !$wantsNonThreat && str_contains($sql, $threatSql);

        // Remove the threat expression before reading the other predicates: it
        // carries a severity comparison of its own that is none of their business.
        $rest = str_replace([$severeSql, $threatSql . ' = 0', $threatSql], '', $sql);

        $status   = self::literal($rest, 'status');
        $scanId   = self::literal($rest, 'scan_id');
        $severity = self::literal($rest, 'severity');
        $types    = preg_match("/issue_type IN \(([^)]*)\)/", $rest, $m) === 1
            ? array_map(fn($t) => trim($t, " '"), explode(',', $m[1]))
            : null;

        return array_filter($this->rows, function (array $row) use (
            $wantsSevere, $wantsThreat, $wantsNonThreat, $status, $scanId, $severity, $types
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

            if ($wantsSevere && !ScanClassifier::isSevere($row)) {
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
