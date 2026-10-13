<?php
declare(strict_types=1);

namespace DPXL\Shield\Scanner;

/**
 * Splits scan findings into two buckets, following the "only real problems"
 * philosophy: a security scanner must not cry wolf.
 *
 *   THREAT          High-confidence findings that warrant action and count as
 *                   "problems": modified core/plugin files, matched malware
 *                   signatures, PHP where media belongs, exposed secrets
 *                   (.env/.git), reputation/blocklist hits, serious or
 *                   unpatched component vulnerabilities, and the one heuristic
 *                   that is genuinely high-confidence (shell exec from user
 *                   input).
 *
 *   RECOMMENDATION  Advisory items — worth surfacing, but NOT a compromise and
 *                   NOT counted as a threat: server hardening notices
 *                   (WP_DEBUG on, file editor enabled), low-confidence broad
 *                   heuristics in plugin/theme code, suspicious-looking post
 *                   content, components that merely have an update available,
 *                   PHP a plugin generates in its own cache directory, and
 *                   cosmetic public files (wp-config-sample.php, debug.log).
 *
 * Three issue types are therefore gated on severity rather than being threats
 * outright. Severity is where the scanners already record how sure they are, so
 * the split reuses that judgement instead of inventing a second one.
 *
 * Both accessors below MUST stay in sync: isThreat() is the PHP source of
 * truth, threatWhereSql() is its SQL translation for COUNT queries. There are
 * no bound parameters — every term is a literal — so the fragment can be
 * concatenated into a WHERE clause directly.
 */
class ScanClassifier {

    /** Issue types that are threats whatever the severity. */
    private const THREAT_TYPES = ['modified_core', 'modified_plugin', 'malware_signature'];

    /**
     * Issue types that are threats only when the scanner rated them
     * critical/high. See isThreat() for why each one is on this list.
     */
    private const SEVERITY_GATED_TYPES = ['php_in_uploads', 'vulnerable_version', 'unknown'];

    /** The severities that make a gated type count as a threat. */
    private const THREAT_SEVERITIES = ['critical', 'high'];

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

        // The severity-gated types, and why each one is gated:
        //
        //   php_in_uploads      MalwareScanner rates it critical where media
        //                       actually lands, and medium inside a directory a
        //                       plugin compiles into — writing, in the finding
        //                       itself, that it is "not evidence of a compromise
        //                       on its own". Counting that as a threat
        //                       contradicted the plugin's own words: WPML's Twig
        //                       cache alone put 34 of them on the badge.
        //
        //   vulnerable_version  VulnerabilityScanner emits two different things
        //                       under one type. A component that merely has an
        //                       update available is hardcoded medium; a CVE
        //                       match is scored from CVSS, so critical/high
        //                       means severe or unpatched. Severity is already
        //                       the line between "update when you can" and
        //                       "this is being exploited". The weekly report
        //                       lists outdated components from its own query, so
        //                       nothing stops being visible.
        //
        //   unknown             Covers both real exposures (.env, .git, phpinfo,
        //                       config backups, reputation hit — critical/high)
        //                       and hardening advisories (server/*,
        //                       wp-config-sample.php, debug.log — medium/low).
        if (in_array($type, self::SEVERITY_GATED_TYPES, true)) {
            return in_array($severity, self::THREAT_SEVERITIES, true);
        }

        return false;
    }

    public static function isRecommendation(array $row): bool {
        return !self::isThreat($row);
    }

    /**
     * Whether a threat is severe enough to say the site is not healthy.
     *
     * The dashboard's health gauge and the post-scan alert email both ask this
     * question, and both used to ask it only of `critical`. The one open threat
     * on two staging installs was a high-severity malware signature, so the
     * gauge read 100% for months with that finding sitting underneath it and no
     * email ever went out about it. Both now read critical *and* high, which is
     * the same line THREAT_SEVERITIES already draws for the gated types.
     *
     * Medium is deliberately left out: a medium finding is one the scanner is
     * not sure about, and turning the gauge red for every one of those is the
     * crying-wolf failure in the other direction. Such a finding is still
     * listed and still counted as a threat — it just does not claim the site is
     * compromised.
     *
     * @param array<string,mixed> $row  A scan_results row (issue_type, severity, ...)
     */
    public static function isSevere(array $row): bool {
        if (!self::isThreat($row)) {
            return false;
        }

        return in_array(strtolower((string) ($row['severity'] ?? 'medium')), self::THREAT_SEVERITIES, true);
    }

    /**
     * SQL WHERE fragment (no bound params) selecting threat rows. Wrap-safe:
     * already parenthesised, so callers can `... AND " . threatWhereSql()`.
     */
    public static function threatWhereSql(): string {
        return "("
            . "issue_type IN ('modified_core','modified_plugin','malware_signature')"
            . " OR (issue_type = 'heuristic' AND severity = 'critical')"
            . " OR (issue_type IN ('php_in_uploads','vulnerable_version','unknown')"
            . " AND severity IN ('critical','high'))"
            . ")";
    }

    /**
     * SQL counterpart of isSevere(): threat rows the gauge and the alert treat
     * as "act now". Same contract as threatWhereSql() — literal-only and
     * already parenthesised — and the same obligation to stay in sync with its
     * PHP twin.
     */
    public static function severeWhereSql(): string {
        return '(' . self::threatWhereSql() . " AND severity IN ('critical','high'))";
    }

    /** Complement of threatWhereSql(): advisory / recommendation rows. */
    public static function recommendationWhereSql(): string {
        return 'NOT ' . self::threatWhereSql();
    }
}
