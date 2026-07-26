<?php
declare(strict_types=1);

namespace DPXL\Shield\Scanner;

/**
 * Splits scan findings into two buckets, following the "only real problems"
 * philosophy: a security scanner must not cry wolf.
 *
 *   THREAT          High-confidence findings that warrant action and count as
 *                   "problems": modified core/plugin files, matched malware
 *                   signatures, PHP in uploads, exposed secrets (.env/.git),
 *                   reputation/blocklist hits, and the one heuristic that is
 *                   genuinely high-confidence (shell exec from user input).
 *
 *   RECOMMENDATION  Advisory items — worth surfacing, but NOT a compromise and
 *                   NOT counted as a threat: server hardening notices
 *                   (WP_DEBUG on, file editor enabled), low-confidence broad
 *                   heuristics in plugin/theme code, suspicious-looking post
 *                   content, and cosmetic public files (wp-config-sample.php,
 *                   debug.log).
 *
 * Both accessors below MUST stay in sync: isThreat() is the PHP source of
 * truth, threatWhereSql() is its SQL translation for COUNT queries. There are
 * no bound parameters — every term is a literal — so the fragment can be
 * concatenated into a WHERE clause directly.
 */
class ScanClassifier {

    /** Issue types that are always high-confidence threats. */
    private const THREAT_TYPES = ['modified_core', 'modified_plugin', 'malware_signature', 'php_in_uploads', 'vulnerable_version'];

    /**
     * @param array<string,mixed> $row  A scan_results row (issue_type, severity, ...)
     */
    public static function isThreat(array $row): bool {
        $type     = (string) ($row['issue_type'] ?? 'unknown');
        $severity = strtolower((string) ($row['severity'] ?? 'medium'));

        if (in_array($type, self::THREAT_TYPES, true)) {
            return true;
        }

        // Broad heuristics are low-confidence noise on heavy plugin stacks.
        // Only the critical "shell exec from user input" pattern is kept as a
        // threat; the rest become review recommendations.
        if ($type === 'heuristic') {
            return $severity === 'critical';
        }

        // 'unknown' covers both real exposures (.env, .git, phpinfo, config
        // backups, reputation hit — critical/high) and hardening advisories
        // (server/*, wp-config-sample.php, debug.log — medium/low).
        if ($type === 'unknown') {
            return in_array($severity, ['critical', 'high'], true);
        }

        return false;
    }

    public static function isRecommendation(array $row): bool {
        return !self::isThreat($row);
    }

    /**
     * SQL WHERE fragment (no bound params) selecting threat rows. Wrap-safe:
     * already parenthesised, so callers can `... AND " . threatWhereSql()`.
     */
    public static function threatWhereSql(): string {
        return "("
            . "issue_type IN ('modified_core','modified_plugin','malware_signature','php_in_uploads','vulnerable_version')"
            . " OR (issue_type = 'heuristic' AND severity = 'critical')"
            . " OR (issue_type = 'unknown' AND severity IN ('critical','high'))"
            . ")";
    }

    /** Complement of threatWhereSql(): advisory / recommendation rows. */
    public static function recommendationWhereSql(): string {
        return 'NOT ' . self::threatWhereSql();
    }
}
