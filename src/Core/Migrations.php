<?php
declare(strict_types=1);

namespace DPXL\Shield\Core;

/**
 * One-time data fixes that run once per site, after an update.
 *
 * Correcting a detection stops new false findings; it does nothing about the
 * ones already recorded. Those keep the dashboard red and the critical count
 * meaningless, which is the same harm the correction was meant to undo — so
 * the fix is only finished when the old rows are dealt with too.
 */
class Migrations {

    private const DONE_OPTION = 'dpxl_shield_migrations_done';

    /**
     * Detections corrected in 1.7.1. Every open finding carrying these was
     * produced by a rule that could not have been right:
     *
     * - `sig-php-in-img` ran against .php files, where it matched any mention
     *   of an image format near an opening tag — WordPress core included.
     * - `sig-skimmer-js` needed a card field, a network call and a URL present
     *   anywhere in the same file, at any distance.
     * - `site/reputation` findings predate 1.6.3, when a refused Spamhaus query
     *   was read as a listing.
     */
    private const FALSE_POSITIVE_SIGNATURES = ['sig-php-in-img', 'sig-skimmer-js'];

    public static function run(): void {
        $done = get_option(self::DONE_OPTION, []);
        $done = is_array($done) ? $done : [];

        if (!in_array('clear_false_positives_171', $done, true)) {
            self::clearFalsePositives171();
            $done[] = 'clear_false_positives_171';
            update_option(self::DONE_OPTION, $done, false);
        }
    }

    /**
     * Marks the known-false findings as `false_positive` rather than deleting
     * them: the rows are a record of what the scanner did, and that record is
     * worth keeping precisely because it was wrong.
     */
    private static function clearFalsePositives171(): void {
        global $wpdb;

        if (!isset($wpdb)) {
            return;
        }

        $table        = $wpdb->prefix . 'dpxl_shield_scan_results';
        $placeholders = implode(',', array_fill(0, count(self::FALSE_POSITIVE_SIGNATURES), '%s'));

        $cleared = $wpdb->query(
            $wpdb->prepare(
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                "UPDATE {$table}
                    SET status = 'false_positive'
                  WHERE status = 'new'
                    AND (signature_id IN ({$placeholders}) OR file_path = %s)",
                array_merge(self::FALSE_POSITIVE_SIGNATURES, ['site/reputation'])
            )
        );

        if ($cleared) {
            Logger::debug("Migrations: cleared {$cleared} findings from corrected detections.");
        }
    }
}
