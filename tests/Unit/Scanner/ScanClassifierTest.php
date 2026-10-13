<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Scanner;

use DPXL\Shield\Scanner\ScanClassifier;
use PHPUnit\Framework\TestCase;

/**
 * Locks the threat/recommendation split — the rule that keeps the scanner from
 * crying wolf. If any of these flip, the "problems" count changes for users.
 */
class ScanClassifierTest extends TestCase {

    /**
     * @dataProvider threatCases
     * @param array<string,mixed> $row
     */
    public function testIsThreat(array $row, bool $expected, string $why): void {
        $this->assertSame($expected, ScanClassifier::isThreat($row), $why);
    }

    /** @return array<string,array{0:array<string,mixed>,1:bool,2:string}> */
    public static function threatCases(): array {
        return [
            'modified core is a threat' => [
                ['issue_type' => 'modified_core', 'severity' => 'critical'], true,
                'A genuinely modified core file must be reported',
            ],
            'modified plugin is a threat' => [
                ['issue_type' => 'modified_plugin', 'severity' => 'high'], true, '',
            ],
            'malware signature is a threat' => [
                ['issue_type' => 'malware_signature', 'severity' => 'high'], true,
                'Curated signatures are high confidence and stay threats',
            ],
            'php in the media tree is a threat' => [
                ['issue_type' => 'php_in_uploads', 'severity' => 'critical'], true,
                'Executable code where media lands is what this finding exists for',
            ],
            'an unpatched vulnerability is a threat' => [
                ['issue_type' => 'vulnerable_version', 'severity' => 'high'], true,
                'A CVE scored high, or left without a fix, warrants acting now',
            ],
            'a severe vulnerability is a threat' => [
                ['issue_type' => 'vulnerable_version', 'severity' => 'critical'], true, '',
            ],
            'exposed .env is a threat' => [
                ['issue_type' => 'unknown', 'severity' => 'critical'], true,
                '.env / .git / phpinfo exposure is critical unknown → threat',
            ],
            'phpinfo (high, unknown) is a threat' => [
                ['issue_type' => 'unknown', 'severity' => 'high'], true, '',
            ],
            'shell-exec-from-user-input heuristic stays a threat' => [
                ['issue_type' => 'heuristic', 'severity' => 'critical'], true,
                'The one high-confidence heuristic is kept',
            ],
            // ── Recommendations (advisory, not counted) ──────────────────────
            'weak heuristic in plugin is advisory' => [
                ['issue_type' => 'heuristic', 'severity' => 'medium'], false,
                'Broad heuristics on plugin code are noise, not threats',
            ],
            'high heuristic in plugin is advisory' => [
                ['issue_type' => 'heuristic', 'severity' => 'high'], false,
                'Only critical heuristics survive as threats',
            ],
            'server hardening notice is advisory' => [
                ['issue_type' => 'unknown', 'severity' => 'medium'], false,
                'WP_DEBUG-style hardening is a recommendation',
            ],
            'wp-config-sample (low) is advisory' => [
                ['issue_type' => 'unknown', 'severity' => 'low'], false, '',
            ],
            'suspicious post content is advisory' => [
                ['issue_type' => 'unknown', 'severity' => 'low'], false, '',
            ],
            // ── The 1.7.7 gates ─────────────────────────────────────────────
            'php a plugin compiled into its own cache is advisory' => [
                ['issue_type' => 'php_in_uploads', 'severity' => 'medium'], false,
                'MalwareScanner rates it medium and says so in the finding: WPML '
                . 'compiling Twig templates is not a compromise, and 34 of them '
                . 'must not fill the badge',
            ],
            'a component that merely has an update available is advisory' => [
                ['issue_type' => 'vulnerable_version', 'severity' => 'medium'], false,
                'Layer 1 is hardcoded medium and says only "installed X, latest '
                . 'Y" — no CVE. Worth doing, not an alarm, and the weekly '
                . 'report lists these from its own query either way',
            ],
            'a patched CVE scored medium is advisory' => [
                ['issue_type' => 'vulnerable_version', 'severity' => 'medium'], false,
                'A fix exists and the score is below 7: that is an update, not an incident',
            ],
        ];
    }

    public function testRecommendationIsComplementOfThreat(): void {
        $row = ['issue_type' => 'heuristic', 'severity' => 'medium'];

        $this->assertTrue(ScanClassifier::isRecommendation($row));
        $this->assertFalse(ScanClassifier::isThreat($row));
    }

    /**
     * isThreat() and threatWhereSql() are one rule written twice, and the
     * dashboard badge reads the SQL while the orchestrator reads the PHP. This
     * walks every type/severity pair through both and fails on the first that
     * disagrees — the cheapest guard against the two drifting apart.
     */
    public function testTheSqlTranslationAgreesWithIsThreatForEveryPair(): void {
        $types = ['modified_core', 'modified_plugin', 'malware_signature', 'heuristic', 'php_in_uploads', 'vulnerable_version', 'unknown'];
        $sql   = ScanClassifier::threatWhereSql();

        foreach ($types as $type) {
            foreach (['critical', 'high', 'medium', 'low'] as $severity) {
                $this->assertSame(
                    ScanClassifier::isThreat(['issue_type' => $type, 'severity' => $severity]),
                    self::evaluateThreatSql($sql, $type, $severity),
                    "isThreat() and threatWhereSql() disagree on {$type}/{$severity}"
                );
            }
        }
    }

    /**
     * Evaluates the WHERE fragment the way MySQL would for one row. The
     * fragment is literal-only, so substituting the row's values and reading
     * the IN / = / OR / AND tree is enough.
     */
    private static function evaluateThreatSql(string $sql, string $type, string $severity): bool {
        $expr = preg_replace_callback(
            "/(issue_type|severity)\s*(=|IN)\s*(\(([^)]*)\)|'([^']*)')/",
            static function (array $m) use ($type, $severity): string {
                $value  = $m[1] === 'issue_type' ? $type : $severity;
                $wanted = $m[2] === 'IN'
                    ? array_map(static fn($v) => trim($v, " '"), explode(',', $m[4]))
                    : [$m[5]];

                return in_array($value, $wanted, true) ? 'true' : 'false';
            },
            $sql
        );

        $expr = str_replace([' OR ', ' AND '], [' || ', ' && '], (string) $expr);

        return (bool) eval("return {$expr};");
    }

    public function testThreatSqlIsParenthesisedAndParamFree(): void {
        $sql = ScanClassifier::threatWhereSql();

        $this->assertStringStartsWith('(', $sql);
        $this->assertStringEndsWith(')', $sql);
        $this->assertStringNotContainsString('%s', $sql, 'Fragment must be literal-only (no bound params)');
    }
}
