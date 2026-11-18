<?php
declare(strict_types=1);

namespace DPXL\Shield\Threat;

use DPXL\Shield\Core\Fs;

/**
 * Atomic file replacement with one-level rollback.
 *
 * The active feed file (waf-rules.active.json in the data folder) is read by the firewall
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
    public static function write(string $path, string $contents, bool $keepBackup = true): bool {
        $dir = dirname($path);

        // The data folder does not exist on a fresh install, so the first
        // write creates it. Without this the threat feed and the country
        // database never landed.
        Fs::mkdirP($dir);

        if (!is_dir($dir) || !Fs::isWritable($dir)) {
            return false;
        }

        // Back up the current good copy before swapping (best-effort rollback point).
        if ($keepBackup && is_file($path)) {
            @copy($path, $path . '.bak');
        }

        $tmp = $path . '.' . getmypid() . '.tmp';

        if (!Fs::putSynced($tmp, $contents)) {
            Fs::delete($tmp);
            return false;
        }

        // rename() is atomic within the same filesystem and overwrites the target.
        if (!Fs::move($tmp, $path)) {
            Fs::delete($tmp);
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
}
