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
            'php in uploads is a threat' => [
                ['issue_type' => 'php_in_uploads', 'severity' => 'critical'], true, '',
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
        ];
    }

    public function testRecommendationIsComplementOfThreat(): void {
        $row = ['issue_type' => 'heuristic', 'severity' => 'medium'];

        $this->assertTrue(ScanClassifier::isRecommendation($row));
        $this->assertFalse(ScanClassifier::isThreat($row));
    }

    public function testThreatSqlIsParenthesisedAndParamFree(): void {
        $sql = ScanClassifier::threatWhereSql();

        $this->assertStringStartsWith('(', $sql);
        $this->assertStringEndsWith(')', $sql);
        $this->assertStringNotContainsString('%s', $sql, 'Fragment must be literal-only (no bound params)');
    }
}
