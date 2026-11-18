<?php
declare(strict_types=1);

namespace DPXL\Shield\Core;

/**
 * The few filesystem calls the plugin makes on its own data folder.
 *
 * With WordPress loaded they go through WordPress's helpers. Extended
 * Protection runs these same code paths before WordPress exists, so each
 * helper falls back to the plain PHP call — the only place in the plugin that
 * does so.
 */
final class Fs {

    private function __construct() {}

    public static function delete(string $path): void {
        if (function_exists('wp_delete_file')) {
            wp_delete_file($path);
            return;
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- runs before WordPress loads, wp_delete_file() does not exist yet.
        @unlink($path);
    }

    public static function isWritable(string $path): bool {
        if (function_exists('wp_is_writable')) {
            return wp_is_writable($path);
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- runs before WordPress loads.
        return is_writable($path);
    }

    public static function mkdirP(string $dir): bool {
        if (is_dir($dir)) {
            return true;
        }

        if (function_exists('wp_mkdir_p')) {
            return wp_mkdir_p($dir);
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- runs before WordPress loads.
        return @mkdir($dir, 0755, true) || is_dir($dir);
    }

    /**
     * Replaces $to with $from in one step. rename() is atomic on the same
     * filesystem, which is the point: the firewall reads these files on every
     * request and must never see half of one. WP_Filesystem::move() copies and
     * deletes when it cannot rename, so it offers no such guarantee.
     */
    public static function move(string $from, string $to): bool {
        // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- atomic replace, see above.
        return @rename($from, $to);
    }

    /** Writes $contents and asks the OS to flush it to disk before returning. */
    public static function putSynced(string $path, string $contents): bool {
        // phpcs:disable WordPress.WP.AlternativeFunctions.file_system_operations_fopen, WordPress.WP.AlternativeFunctions.file_system_operations_fwrite, WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- fsync() needs a handle; WP_Filesystem has no synced write.
        $handle = @fopen($path, 'wb');

        if ($handle === false) {
            return false;
        }

        $ok = @fwrite($handle, $contents) !== false;

        if ($ok) {
            @fflush($handle);

            // fsync (PHP 8.1+) forces the bytes to disk so a crash can't leave
            // a torn file behind the rename. Guarded in case it is disabled.
            if (function_exists('fsync')) {
                @fsync($handle);
            }
        }

        @fclose($handle);
        // phpcs:enable

        return $ok;
    }
}
