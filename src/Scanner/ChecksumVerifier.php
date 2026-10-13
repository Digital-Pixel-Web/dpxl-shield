<?php
declare(strict_types=1);

namespace DPXL\Shield\Scanner;

use DPXL\Shield\Core\Logger;

/**
 * Records SHA-256 checksums of files and verifies them against the baseline.
 * Uses WP.org MD5 checksums for core file change detection.
 */
class ChecksumVerifier {

    /**
     * Core files that legitimately differ from the WP.org manifest on normal,
     * uncompromised installs — they must not be reported as modified core:
     *
     * - wp-includes/version.php: localized installs add `$wp_local_package`,
     *   and many hosts stamp a build string here.
     * - wp-config-sample.php / readme.html / licence files: routinely edited or
     *   removed by hosts and site owners.
     *
     * These files are still scanned for actual malware by MalwareScanner
     * (they are .php/.html under the scanned trees), so genuine injections are
     * caught by content — just not by a benign checksum diff.
     */
    private const IGNORED_CORE_FILES = [
        'wp-includes/version.php',
        'wp-config-sample.php',
        'readme.html',
        'license.txt',
        'wp-content/index.php',
    ];

    /**
     * Fetches official checksums from WP.org and compares them against the
     * current files on disk. Returns scan result rows for changed files.
     *
     * @return list<array{file_path:string,issue_type:string,severity:string,details:string}>
     */
    public function detectChangedCoreFiles(): array {
        $api      = new WpOrgChecksumApi();
        $official = $api->getCoreChecksums();

        if (empty($official)) {
            Logger::error('ChecksumVerifier: could not fetch WP.org checksums.');
            return [];
        }

        $issues = [];

        foreach ($official as $relativePath => $expectedMd5) {
            if (in_array($relativePath, self::IGNORED_CORE_FILES, true)) {
                continue;
            }

            // The manifest also lists what WordPress *ships* under wp-content:
            // Akismet and the default themes, 444 files in 7.1.3. Those update
            // independently of core — updating Akismet is correct maintenance —
            // so comparing them against the core release reports a well-run site
            // as having 21 modified core files. Core integrity means wp-admin,
            // wp-includes and the root; wp-content is not core.
            if (strpos($relativePath, 'wp-content/') === 0) {
                continue;
            }

            $absolutePath = ABSPATH . $relativePath;

            if (!file_exists($absolutePath)) {
                continue;
            }

            $actualMd5 = md5_file($absolutePath);

            if ($actualMd5 !== $expectedMd5) {
                $issues[] = [
                    'file_path'  => $absolutePath,
                    'issue_type' => 'modified_core',
                    'severity'   => 'critical',
                    'details'    => "O arquivo difere da versão oficial do WordPress. Esperado: {$expectedMd5}, encontrado: {$actualMd5}",
                ];
            }
        }

        return $issues;
    }

    /**
     * Checks one core file against the official WP.org manifest for the
     * running WordPress version.
     *
     * This is the authority a baseline cannot be: a stored baseline only says
     * "this file is not what it was", never "this file is not WordPress".
     * Core updates rewrite core files legitimately, so the manifest is what
     * separates a routine update from tampering.
     *
     * @return bool|null true  = byte-for-byte the official file,
     *                   false = differs from the official file,
     *                   null  = no verdict available (file is not shipped by
     *                           core, e.g. wp-config.php, or WP.org is
     *                           unreachable). Callers must treat null as
     *                           "unknown", never as "fine".
     */
    public function matchesOfficialCore(string $relativePath): ?bool {
        $official = (new WpOrgChecksumApi())->getCoreChecksums();

        if (empty($official) || !isset($official[$relativePath])) {
            return null;
        }

        $absolutePath = ABSPATH . $relativePath;

        if (!is_readable($absolutePath)) {
            return null;
        }

        // WP.org publishes MD5. Fine here: this compares against a value fetched
        // over TLS for the exact version, it is not a password or a signature.
        return md5_file($absolutePath) === $official[$relativePath];
    }

    /**
     * Records a SHA-256 checksum for a file into the database.
     * Used for the integrity baseline (plugin own files + critical WP files).
     */
    public function record(string $absolutePath, string $fileType = 'core'): void {
        global $wpdb;

        if (!is_readable($absolutePath)) {
            return;
        }

        $relativePath = $this->toRelative($absolutePath);
        $checksum     = hash_file('sha256', $absolutePath);

        $wpdb->replace(
            $wpdb->prefix . 'dpxl_shield_file_checksums',
            [
                'file_path'   => $relativePath,
                'checksum'    => $checksum,
                'file_type'   => $fileType,
                'recorded_at' => current_time('mysql', true),
            ],
            ['%s', '%s', '%s', '%s']
        );
    }

    /**
     * Verifies a file against its stored SHA-256 baseline.
     *
     * @return bool|null  true=unchanged, false=modified, null=no baseline
     */
    public function verify(string $absolutePath): ?bool {
        global $wpdb;

        if (!is_readable($absolutePath)) {
            return null;
        }

        $relativePath = $this->toRelative($absolutePath);

        $stored = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT checksum
                 FROM {$wpdb->prefix}dpxl_shield_file_checksums
                 WHERE file_path = %s",
                $relativePath
            )
        );

        if ($stored === null) {
            return null;
        }

        return hash_file('sha256', $absolutePath) === $stored;
    }

    /**
     * Records checksums for every PHP file in a directory tree.
     *
     * @param string $directory  Absolute path
     * @param string $fileType   'core' | 'plugin' | 'theme' | 'shieldwp'
     */
    public function recordDirectory(string $directory, string $fileType): void {
        if (!is_dir($directory)) {
            return;
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($directory, \FilesystemIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                $this->record($file->getRealPath(), $fileType);
            }
        }
    }

    private function toRelative(string $absolutePath): string {
        return ltrim(str_replace(ABSPATH, '', $absolutePath), '/\\');
    }
}
