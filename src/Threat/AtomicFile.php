<?php
declare(strict_types=1);

namespace DPXL\Shield\Threat;

/**
 * Atomic file replacement with one-level rollback.
 *
 * The active feed file (data/waf-rules.active.json) is read by the firewall
 * *before WordPress loads* (Extended mode). A half-written file there could
 * break the firewall and, worst case, 500 the whole site. So writes go to a
 * sibling temp file, are flushed to disk, and are swapped in with rename() —
 * atomic on the same filesystem — never exposing a partial file. The previous
 * good copy is kept as `<name>.bak` so a bad update can be rolled back.
 *
 * Filesystem-only, no WordPress dependency: safe to call from any context.
 */
class AtomicFile {

    /**
     * Atomically writes $contents to $path, backing up the current file to
     * `<path>.bak` first. Returns false (leaving the existing file untouched)
     * on any failure.
     */
    public static function write(string $path, string $contents): bool {
        $dir = dirname($path);

        if (!is_dir($dir) || !is_writable($dir)) {
            return false;
        }

        // Back up the current good copy before swapping (best-effort rollback point).
        if (is_file($path)) {
            @copy($path, $path . '.bak');
        }

        $tmp = $path . '.' . getmypid() . '.tmp';

        if (!self::putContentsSynced($tmp, $contents)) {
            @unlink($tmp);
            return false;
        }

        // rename() is atomic within the same filesystem and overwrites the target.
        if (!@rename($tmp, $path)) {
            @unlink($tmp);
            return false;
        }

        return true;
    }

    /** Restores $path from `<path>.bak`, if the backup exists. */
    public static function rollback(string $path): bool {
        $bak = $path . '.bak';

        if (!is_file($bak)) {
            return false;
        }

        return @copy($bak, $path);
    }

    // ── Internals ──────────────────────────────────────────────────────────

    /** Writes $contents to $path and fsyncs before returning. */
    private static function putContentsSynced(string $path, string $contents): bool {
        $handle = @fopen($path, 'wb');

        if ($handle === false) {
            return false;
        }

        $ok = true;

        if (@fwrite($handle, $contents) === false) {
            $ok = false;
        }

        if ($ok && function_exists('fflush')) {
            @fflush($handle);
        }

        // fsync (PHP 8.1+) forces the bytes to disk so a crash can't leave a
        // torn file behind the rename. Guarded in case it is disabled.
        if ($ok && function_exists('fsync')) {
            @fsync($handle);
        }

        @fclose($handle);

        return $ok;
    }
}
