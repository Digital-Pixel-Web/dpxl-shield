<?php
declare(strict_types=1);

namespace DPXL\Shield\Scanner;

use DPXL\Shield\Core\Logger;

/**
 * Restores modified or deleted WordPress core and plugin files
 * from the official WP.org repository.
 *
 * Before overwriting, the current file is backed up to:
 *   wp-content/shieldwp-backups/{timestamp}/{relative_path}
 *
 * Only files for which WP.org provides a canonical copy are repairable:
 *   - WordPress core files (via api.wordpress.org/core/checksums)
 *   - Plugin files installed from WP.org (via downloads.wordpress.org/plugin)
 *
 * Theme files and custom files cannot be repaired automatically.
 */
class FileRepair {

    private const BACKUP_DIR = 'shieldwp-backups';

    private WpOrgChecksumApi $checksumApi;

    public function __construct() {
        $this->checksumApi = new WpOrgChecksumApi();
    }

    // ── Public API ─────────────────────────────────────────────────────────

    /**
     * Repair a single file.
     *
     * @return array{success: bool, message: string}
     */
    public function repairFile(string $absolutePath): array {
        $type = $this->classifyFile($absolutePath);

        if ($type === 'core') {
            return $this->repairCoreFile($absolutePath);
        }

        if ($type === 'plugin') {
            return $this->repairPluginFile($absolutePath);
        }

        return ['success' => false, 'message' => 'This file cannot be repaired automatically (theme or custom file).'];
    }

    /**
     * Repair all new/high-severity scan results that have a repairable file type.
     *
     * @return array{repaired: int, failed: int, skipped: int}
     */
    public function repairAll(): array {
        global $wpdb;

        $lastScanId = (string) get_option('dpxl_shield_last_scan_id', '');

        if ($lastScanId !== '') {
            $results = $wpdb->get_results(
                $wpdb->prepare(
                    "SELECT id, file_path, issue_type FROM {$wpdb->prefix}dpxl_shield_scan_results
                     WHERE status = 'new'
                     AND scan_id = %s
                     AND issue_type IN ('modified_core', 'modified_plugin')
                     ORDER BY id ASC",
                    $lastScanId
                ),
                ARRAY_A
            ) ?? [];
        } else {
            $results = $wpdb->get_results(
                "SELECT id, file_path, issue_type FROM {$wpdb->prefix}dpxl_shield_scan_results
                 WHERE status = 'new'
                 AND issue_type IN ('modified_core', 'modified_plugin')
                 ORDER BY id ASC",
                ARRAY_A
            ) ?? [];
        }

        $repaired = $failed = $skipped = 0;

        foreach ($results as $row) {
            $path   = (string) $row['file_path'];
            $result = $this->repairFile($path);

            if ($result['success']) {
                $wpdb->update(
                    $wpdb->prefix . 'dpxl_shield_scan_results',
                    ['status' => 'resolved'],
                    ['id'     => (int) $row['id']],
                    ['%s'],
                    ['%d']
                );
                $repaired++;
            } else {
                $failed++;
            }
        }

        return compact('repaired', 'failed', 'skipped');
    }

    // ── Core file repair ───────────────────────────────────────────────────

    /** @return array{success: bool, message: string} */
    private function repairCoreFile(string $absolutePath): array {
        global $wp_version;

        $relative = str_replace(ABSPATH, '', $absolutePath);
        $relative = ltrim(str_replace(DIRECTORY_SEPARATOR, '/', $relative), '/');

        $checksums = $this->checksumApi->getCoreChecksums($wp_version ?? '');

        if (!isset($checksums[$relative])) {
            return ['success' => false, 'message' => "No WP.org checksum found for: {$relative}"];
        }

        $version = $wp_version ?? '';
        $url     = "https://raw.githubusercontent.com/WordPress/WordPress/{$version}/{$relative}";

        return $this->downloadAndReplace($url, $absolutePath, $relative);
    }

    // ── Plugin file repair ─────────────────────────────────────────────────

    /** @return array{success: bool, message: string} */
    private function repairPluginFile(string $absolutePath): array {
        $pluginsDir = WP_PLUGIN_DIR;
        $relative   = ltrim(str_replace([$pluginsDir, DIRECTORY_SEPARATOR], ['', '/'], $absolutePath), '/');
        $parts      = explode('/', $relative, 2);
        $pluginSlug = $parts[0] ?? '';
        $fileInPlugin = $parts[1] ?? '';

        if (!$pluginSlug || !$fileInPlugin) {
            return ['success' => false, 'message' => 'Could not determine plugin slug.'];
        }

        // Get plugin version from headers.
        $pluginFile = "{$pluginsDir}/{$pluginSlug}/{$pluginSlug}.php";

        if (!file_exists($pluginFile)) {
            return ['success' => false, 'message' => "Plugin main file not found: {$pluginFile}"];
        }

        $pluginData = get_plugin_data($pluginFile, false, false);
        $version    = $pluginData['Version'] ?? '';

        if (!$version) {
            return ['success' => false, 'message' => "Could not determine version for plugin: {$pluginSlug}"];
        }

        // Download the entire plugin zip and extract just the file.
        $zipUrl = "https://downloads.wordpress.org/plugin/{$pluginSlug}.{$version}.zip";

        return $this->repairFromZip($zipUrl, $pluginSlug, $fileInPlugin, $absolutePath);
    }

    /** @return array{success: bool, message: string} */
    private function repairFromZip(string $zipUrl, string $pluginSlug, string $fileInPlugin, string $dest): array {
        require_once ABSPATH . 'wp-admin/includes/file.php';

        $tmpFile = download_url($zipUrl, 30);

        if (is_wp_error($tmpFile)) {
            return ['success' => false, 'message' => 'Failed to download plugin zip: ' . $tmpFile->get_error_message()];
        }

        $zip = new \ZipArchive();

        if ($zip->open($tmpFile) !== true) {
            @unlink($tmpFile);
            return ['success' => false, 'message' => 'Failed to open plugin zip.'];
        }

        $entryName = "{$pluginSlug}/{$fileInPlugin}";
        $contents  = $zip->getFromName($entryName);
        $zip->close();
        @unlink($tmpFile);

        if ($contents === false) {
            return ['success' => false, 'message' => "File not found in zip: {$entryName}"];
        }

        $this->backup($dest);

        if (file_put_contents($dest, $contents) === false) {
            return ['success' => false, 'message' => "Failed to write repaired file: {$dest}"];
        }

        Logger::error("FileRepair: repaired plugin file {$dest}");

        return ['success' => true, 'message' => "File repaired: {$dest}"];
    }

    // ── Generic download + replace ─────────────────────────────────────────

    /** @return array{success: bool, message: string} */
    private function downloadAndReplace(string $url, string $dest, string $label): array {
        $response = wp_remote_get($url, ['timeout' => 20]);

        if (is_wp_error($response)) {
            return ['success' => false, 'message' => 'Download failed: ' . $response->get_error_message()];
        }

        if (wp_remote_retrieve_response_code($response) !== 200) {
            return ['success' => false, 'message' => "File not found on WP.org: {$label}"];
        }

        $contents = wp_remote_retrieve_body($response);

        $this->backup($dest);

        if (!wp_mkdir_p(dirname($dest))) {
            return ['success' => false, 'message' => "Cannot create directory for: {$dest}"];
        }

        if (file_put_contents($dest, $contents) === false) {
            return ['success' => false, 'message' => "Failed to write file: {$dest}"];
        }

        Logger::error("FileRepair: repaired core file {$dest}");

        return ['success' => true, 'message' => "File repaired: {$label}"];
    }

    // ── Backup ─────────────────────────────────────────────────────────────

    private function backup(string $absolutePath): void {
        if (!file_exists($absolutePath)) {
            return;
        }

        $backupRoot = WP_CONTENT_DIR . '/' . self::BACKUP_DIR . '/' . gmdate('Ymd-His');
        $relative   = str_replace(ABSPATH, '', $absolutePath);
        $backupPath = $backupRoot . '/' . ltrim(str_replace(DIRECTORY_SEPARATOR, '/', $relative), '/');

        wp_mkdir_p(dirname($backupPath));
        @copy($absolutePath, $backupPath);
    }

    // ── Classification ─────────────────────────────────────────────────────

    private function classifyFile(string $absolutePath): string {
        if (str_starts_with($absolutePath, WP_PLUGIN_DIR)) {
            return 'plugin';
        }

        if (str_starts_with($absolutePath, ABSPATH . 'wp-includes') || str_starts_with($absolutePath, ABSPATH . 'wp-admin')) {
            return 'core';
        }

        return 'other';
    }
}
